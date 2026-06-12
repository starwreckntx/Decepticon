#!/usr/bin/env python3
"""
GovernedKaliBridge — routes Decepticon's autonomous red-team tool calls through the
Kali Kimi Interface (KKI) IRP governance layer before anything executes.

Why this exists
---------------
Decepticon's stock recon/terminal MCP servers shell straight into the attacker
container:

    subprocess.run(["docker", "exec", "attacker", "sh", "-c", command])

That is fully autonomous and ungoverned — an agent can run any string, against any
target, with no human in the loop and no tamper-evident record. "In the wild" that is
exactly what you do NOT want a self-driving offensive swarm to have.

This bridge inserts KKI's ``GovernedExecutor`` in front of every proposed call so each
one must pass, in order:

    positive allowlist validation  (no injection, flags from a per-tool allowlist)
      -> permission-as-code policy (DANGER ⇒ REQUIRES_CONSENT)
      -> network-scope allowlist   (target must be inside the engagement CIDRs)
      -> per-invocation binary attestation (PATH / symlink-hijack defense)
      -> Mirror_RTC human consent  (per-action APPROVE <nonce>, default-deny)
      -> execution (only if cleared)
      -> append-only HMAC hash-chained audit entry

KKI itself is imported unmodified — this module is a *consumer* of its public
governance API, so none of KKI's security guarantees are altered here.

Execution model
---------------
KKI executes wrapped tools (nmap/gobuster/nikto/sqlmap/...) as local subprocesses, so
run this bridge (and the governed MCP server that wraps it) on the host where the Kali
binaries live — e.g. inside the same attacker container Decepticon already provisions.
Co-locating governance with execution is what makes the binary attestation real: the
bytes that are hashed and consented to are the bytes that run.

Usage:
    from kki_gov.kki_bridge import GovernedKaliBridge
    bridge = GovernedKaliBridge(network_scope=["192.168.56.0/24"], consent_mode="broker")
    out = bridge.scan("nmap_scan", {"target": "192.168.56.101", "flags": "-sS -p 1-1000"})
    if out["allowed"]:
        ...  # out["result"] holds the structured tool output
    else:
        ...  # out["denial_reason"] explains which gate refused it
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# --- KKI location / import -----------------------------------------------------------

def _locate_kki() -> Path:
    """Find the kali-kimi-interface checkout and return its ``src`` directory.

    Resolution order: ``KKI_PATH`` env var → a ``kali-kimi-interface`` sibling of the
    Decepticon repo → a sibling of this file's repo root. Fails loudly: a silent fallback
    would let calls run ungoverned, which is the whole thing we are preventing.
    """
    candidates: List[Path] = []
    env = os.environ.get("KKI_PATH")
    if env:
        candidates.append(Path(env))
    repo_root = Path(__file__).resolve().parents[2]   # .../Decepticon
    candidates.append(repo_root.parent / "kali-kimi-interface")
    candidates.append(repo_root.parent.parent / "kali-kimi-interface")

    for base in candidates:
        src = base / "src"
        if (src / "governance" / "engine.py").exists():
            return src
    raise RuntimeError(
        "Could not locate the kali-kimi-interface checkout. Set KKI_PATH to its repo "
        "root (the directory containing src/governance/engine.py). Refusing to run "
        "ungoverned."
    )


def _import_governance():
    src = _locate_kki()
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from governance.engine import GovernedExecutor  # type: ignore
    from governance.consent import ConsentRequest    # type: ignore
    return GovernedExecutor, ConsentRequest


# --- consent strategies --------------------------------------------------------------
#
# A consent strategy is a prompt_fn: (ConsentRequest) -> Optional[str]. It must return
# "APPROVE <nonce>" to authorize a DANGER action, or anything else / None to deny. The
# gate is default-deny, so the safe failure mode is "return None".

def _deny_prompt(_req) -> None:
    """Default-deny: no operator is reachable, so every DANGER action is refused. The
    swarm can still run read-only work, but nothing dangerous executes unattended."""
    return None


def _preauth_prompt_factory():
    """Scoped pre-authorization for *authorized* unattended runs.

    Only active when ``KKI_SESSION_AUTHORIZED=1`` is explicitly set by an operator who has
    accepted responsibility for the engagement. Even then, every other gate still
    applies — allowlist validation, the network-scope CIDR check, binary attestation, and
    the audit trail — so "pre-authorized" never means "ungoverned". Absent the env var
    this behaves exactly like default-deny.
    """
    authorized = os.environ.get("KKI_SESSION_AUTHORIZED") == "1"

    def _prompt(req) -> Optional[str]:
        if authorized:
            return f"APPROVE {req.nonce}"
        return None

    return _prompt


def _resolve_consent(consent_mode: str, consent_prompt: Optional[Callable]) -> Callable:
    if consent_prompt is not None:
        return consent_prompt
    if consent_mode == "deny":
        return _deny_prompt
    if consent_mode == "preauth":
        return _preauth_prompt_factory()
    if consent_mode == "broker":
        # Imported lazily so the bridge has no hard dependency on the broker module.
        from kki_gov.consent_broker import FileConsentBroker  # type: ignore
        return FileConsentBroker().prompt
    raise ValueError(f"unknown consent_mode: {consent_mode!r} "
                     "(expected 'deny', 'broker', or 'preauth')")


# --- the bridge ----------------------------------------------------------------------

# Decepticon-facing tool aliases -> KKI harness tool names. The aliases match the names
# Decepticon's recon prompts already use, so the governed server is close to a drop-in.
TOOL_ALIASES: Dict[str, str] = {
    "nmap": "nmap_scan",
    "nmap_scan": "nmap_scan",
    "gobuster": "gobuster_scan",
    "gobuster_scan": "gobuster_scan",
    "nikto": "nikto_scan",
    "nikto_scan": "nikto_scan",
    "sqlmap": "sqlmap_scan",
    "sqlmap_scan": "sqlmap_scan",
    "masscan": "masscan_quick",
    "quick_recon": "quick_recon",
}


class GovernedKaliBridge:
    """Front door an MCP server (or any caller) uses to run governed Kali tools."""

    def __init__(
        self,
        network_scope: Optional[List[str]] = None,
        consent_mode: str = "deny",
        consent_prompt: Optional[Callable] = None,
        consent_timeout: float = 120.0,
        executor: Any = None,
        registry: Any = None,
        audit_path: Optional[str] = None,
    ):
        GovernedExecutor, _ = _import_governance()
        prompt = _resolve_consent(consent_mode, consent_prompt)
        self.consent_mode = consent_mode
        self.network_scope = network_scope
        self._audit_path = audit_path
        # executor/registry are injectable so tests can drive the gate without Kali present.
        kwargs: Dict[str, Any] = dict(
            network_scope=network_scope,
            consent_prompt=prompt,
            consent_timeout=consent_timeout,
        )
        if executor is not None:
            kwargs["executor"] = executor
        if registry is not None:
            kwargs["registry"] = registry
        self.gov = GovernedExecutor(**kwargs)

    # -- name/param mapping -----------------------------------------------------------

    @staticmethod
    def resolve_tool(name: str) -> str:
        tool = TOOL_ALIASES.get(name)
        if tool is None:
            raise KeyError(
                f"tool {name!r} is not governed by this bridge. Governed tools: "
                f"{sorted(set(TOOL_ALIASES.values()))}"
            )
        return tool

    # -- the governed call ------------------------------------------------------------

    def scan(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run one governed tool call. Returns a JSON-serializable dict the agent can
        reason over: always includes ``allowed`` and, when refused, ``denial_reason`` plus
        the governance trace. Never raises for a *policy* refusal — refusal is data."""
        try:
            tool = self.resolve_tool(name)
        except KeyError as e:
            return {"tool": name, "allowed": False, "denial_reason": str(e),
                    "governed": True, "result": None}

        result = self.gov.execute(tool, params)
        return self._shape(name, tool, result)

    def nmap(self, target: str, options: Optional[str] = None,
             ports: Optional[str] = None) -> Dict[str, Any]:
        """Convenience wrapper matching Decepticon's recon ``nmap(target, options)``."""
        params: Dict[str, Any] = {"target": target}
        if options:
            params["flags"] = options
        if ports:
            params["ports"] = ports
        return self.scan("nmap_scan", params)

    @staticmethod
    def _shape(alias: str, tool: str, gr) -> Dict[str, Any]:
        """Flatten a KKI GovernedResult into an agent-friendly envelope."""
        d = gr.to_dict() if hasattr(gr, "to_dict") else dict(gr)
        return {
            "tool": alias,
            "kki_tool": tool,
            "governed": True,
            "allowed": d.get("allowed", False),
            "authorization": d.get("authorization"),
            "blast_radius": d.get("blast_radius"),
            "denial_reason": d.get("denial_reason"),
            "audit_seq": d.get("audit_seq", []),
            "result": d.get("result"),
        }

    # -- session lifecycle ------------------------------------------------------------

    def session_report(self) -> Dict[str, Any]:
        return self.gov.session_report()

    def save_audit(self, path: Optional[str] = None) -> Optional[str]:
        path = path or self._audit_path
        if not path:
            return None
        return self.gov.save_audit(path)
