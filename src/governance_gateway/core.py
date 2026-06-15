"""
GovernanceGateway — the single non-bypassable chokepoint for the governed swarm.

This is the "more powerful deploy": instead of governance being drop-in libraries the swarm
is trusted to call, the swarm's MCP client points at ONE gateway, and the gateway is the
reference monitor. Every tool call is enforced through BOTH layers, in order, and recorded:

    1. AGENT integrity (ShadowAuditor): does the calling agent hold the capability this
       tool requires? (recon tools need RECON_TOOLS; exploit tools need EXPLOIT_TOOLS.)
       A capability the agent's role lacks is privilege escalation -> the agent is STRIPPED.
    2. TOOL governance (KKI GovernedExecutor via GovernedKaliBridge): validation -> policy
       -> network scope -> binary attestation -> human consent -> HMAC audit -> execute.

Because the swarm can only reach a tool through this object, the terminal/free-form surface
is covered too: the gateway's ``command`` entry parses the leading binary and routes known
binaries through full governance, refusing unknown ones by allowlist (and recording the
attempt on the agent chain). Bypass-resistance is topological, not a matter of discipline.

The gateway shares the SAME ShadowAuditor singleton as the live handoff gate
(``swarm_integrity.handoff_gate.get_auditor``), so an agent's tool-capability assertions and
its control-transfers land on one unified, seed-deterministic agent chain — which cross-links
to KKI's separate HMAC tool chain. Two verifiable records, one chokepoint.

This module is import-safe without ``mcp``/``langgraph``: the dispatch core only needs the
KKI bridge (stdlib + governance) and the pure-Python ShadowAuditor.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make ``src`` importable whether run as a module or a script.
_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from kki_gov.kki_bridge import GovernedKaliBridge, TOOL_ALIASES  # tool-level governance
from swarm_integrity.handoff_gate import get_auditor             # shared agent auditor
from swarm_integrity.constants import (
    CAP_RECON_TOOLS, CAP_EXPLOIT_TOOLS,
)

# Which agent capability each governed tool requires. The gateway asserts this against the
# calling agent's role before the tool is even evaluated for tool-level governance.
TOOL_REQUIRED_CAPABILITY: Dict[str, str] = {
    "nmap_scan": CAP_RECON_TOOLS,
    "gobuster_scan": CAP_RECON_TOOLS,
    "nikto_scan": CAP_RECON_TOOLS,
    "masscan_quick": CAP_RECON_TOOLS,
    "quick_recon": CAP_RECON_TOOLS,
    "sqlmap_scan": CAP_EXPLOIT_TOOLS,
}

# Free-form command binaries the gateway will route to a governed tool. Anything else is
# refused by allowlist (the terminal surface is gated, not open).
_BINARY_TO_TOOL: Dict[str, str] = {
    "nmap": "nmap_scan", "gobuster": "gobuster_scan", "nikto": "nikto_scan",
    "masscan": "masscan_quick", "sqlmap": "sqlmap_scan",
}


class GovernanceGateway:
    def __init__(
        self,
        network_scope: Optional[List[str]] = None,
        consent_mode: str = "deny",
        enforce_agent_integrity: bool = True,
        preauth: Any = None,
    ):
        self.bridge = GovernedKaliBridge(
            network_scope=network_scope
            or _split_env("KKI_NETWORK_SCOPE"),
            consent_mode=consent_mode or os.environ.get("KKI_CONSENT_MODE", "deny"),
            audit_path=os.environ.get("KKI_AUDIT_PATH"),
        )
        self.enforce_agent_integrity = enforce_agent_integrity
        # Optional preventive layer: a PreAuthBroker. When set, execution is gated on a
        # write-ahead-committed, action-bound capability token and a just-in-time egress grant.
        self.preauth = preauth

    def _action(self, tool: str, params: Dict[str, Any], agent: Optional[str]) -> Dict[str, Any]:
        """Build the action descriptor a capability token binds to."""
        from preauth.tokens import args_digest  # local import; preauth is optional
        target = str(params.get("target") or params.get("url") or params.get("host") or "")
        return {
            "tool": tool, "agent": agent, "args_digest": args_digest(params),
            "binary_sha256": "", "dst": target, "dst_ip": target,
            "dport": params.get("dport"),
        }


    # -- the unified chokepoint -------------------------------------------------------

    def dispatch(self, tool: str, params: Dict[str, Any],
                 agent: Optional[str] = None,
                 identity_source: str = "arg") -> Dict[str, Any]:
        """Enforce both layers for one proposed tool call and return a unified envelope.

        ``agent`` is the caller's authenticated role (resolved from the connection token by
        the server; see identity.py). ``identity_source`` records HOW it was established
        ("token" = session-bound, "arg" = self-asserted, "none" = unidentified) so a reviewer
        can tell strongly-authenticated calls from weakly-authenticated ones.

        Fail-closed identity: when a tool requires a capability, an unidentified caller
        (``agent is None``) is refused at the agent layer — an unauthenticated call can never
        reach tool governance. submit_capability also fails closed (and audits) for an unknown
        role, so a forged identity is rejected the same way.
        """
        envelope: Dict[str, Any] = {
            "tool": tool, "agent": agent, "identity_source": identity_source, "allowed": False,
            "agent_integrity": None, "tool_governance": None,
            "denied_stage": None, "denial_reason": None, "result": None,
        }

        # Stage 1: agent-level integrity (capability ownership). Runs whenever the tool needs
        # a capability — including when agent is None, which submit_capability denies + audits.
        cap = TOOL_REQUIRED_CAPABILITY.get(tool)
        if self.enforce_agent_integrity and cap:
            v = get_auditor().submit_capability(agent, cap)
            envelope["agent_integrity"] = v.to_dict()
            if not v.allowed:
                envelope["denied_stage"] = "agent_integrity"
                envelope["denial_reason"] = (
                    "unidentified caller (no authenticated agent token); fail closed"
                    if agent is None else v.reason
                )
                return envelope

        # Stage 3 (optional, preventive): pre-authorization. Write-ahead-commit the intent,
        # open a just-in-time per-action egress grant, mint an action-bound TTL token, and
        # gate execution on it — so the record precedes the act and nothing runs without the
        # broker's signed yes. The JIT grant is revoked in finally, regardless of outcome.
        grant = None
        if self.preauth is not None:
            from preauth.executor import enforce, ExecutionDenied
            action = self._action(tool, params, agent)
            grant = self.preauth.authorize(action)            # 1. write-ahead + JIT + token
            # Bind the per-action nonce the broker chose so the executor enforces against the
            # exact action the token was minted for.
            action["nonce"] = grant.action_id
            envelope["preauth"] = grant.to_envelope()
            try:
                enforce(self.preauth.secret, grant.token, action)   # 2. token-gated exec check
            except ExecutionDenied as e:
                self.preauth.complete(grant)                  # revoke JIT; nothing executed
                envelope["denied_stage"] = "preauth"
                envelope["denial_reason"] = str(e)
                return envelope

        # Stage 2: tool-level governance (KKI) + execution (runs under the open JIT grant).
        try:
            out = self.bridge.scan(tool, params)
        finally:
            if grant is not None:
                self.preauth.complete(grant)                  # 3. revoke JIT capability
        envelope["tool_governance"] = out
        if not out.get("allowed"):
            envelope["denied_stage"] = "tool_governance"
            envelope["denial_reason"] = out.get("denial_reason")
            return envelope

        envelope["allowed"] = True
        envelope["result"] = out.get("result")
        return envelope

    def dispatch_command(self, command: str, agent: Optional[str] = None,
                         identity_source: str = "arg") -> Dict[str, Any]:
        """Govern a free-form command (the terminal surface). The leading binary must be in
        the gateway allowlist; it is then routed through full governance. Unknown binaries
        are refused (and the attempt is recorded on the agent chain via a capability assert)."""
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return {"tool": "command", "agent": agent, "allowed": False,
                    "denied_stage": "parse", "denial_reason": f"unparseable command: {e}",
                    "result": None}
        if not argv:
            return {"tool": "command", "agent": agent, "allowed": False,
                    "denied_stage": "parse", "denial_reason": "empty command", "result": None}

        binary = argv[0]
        tool = _BINARY_TO_TOOL.get(binary)
        if tool is None:
            # Unknown binary: refuse by allowlist. Record the attempt on the agent chain so a
            # repeated reach for ungoverned shell is auditable (and strippable as priv-esc).
            # submit_capability handles an unidentified caller (agent None) by failing closed.
            if self.enforce_agent_integrity:
                get_auditor().submit_capability(agent, CAP_EXPLOIT_TOOLS)
            return {"tool": "command", "agent": agent, "identity_source": identity_source,
                    "allowed": False, "denied_stage": "allowlist",
                    "denial_reason": (f"binary {binary!r} is not in the gateway allowlist "
                                      f"({sorted(_BINARY_TO_TOOL)}); use a governed tool or "
                                      f"extend the policy"),
                    "result": None}

        # Map the rest of argv into the governed tool's params (target = last non-flag token,
        # flags = the remainder). Best-effort; KKI's validation is authoritative.
        rest = argv[1:]
        target = next((t for t in reversed(rest) if not t.startswith("-")), "")
        flags = " ".join(t for t in rest if t != target)
        params: Dict[str, Any] = {"target": target}
        if flags:
            params["flags"] = flags
        return self.dispatch(tool, params, agent=agent, identity_source=identity_source)

    # -- introspection ----------------------------------------------------------------

    @staticmethod
    def governed_tools() -> List[str]:
        return sorted(set(TOOL_ALIASES.values()))

    def report(self) -> Dict[str, Any]:
        return {
            "tool_governance": self.bridge.session_report(),
            "agent_integrity": get_auditor().session_report(),
        }


def _split_env(name: str) -> Optional[List[str]]:
    raw = os.environ.get(name, "").strip()
    return [c.strip() for c in raw.split(",") if c.strip()] or None
