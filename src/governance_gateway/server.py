#!/usr/bin/env python3
"""
MCP Governance Gateway server — the ONE endpoint every Decepticon agent connects to.

Identity is **session-bound**: each agent connects carrying only its own per-agent token
(an ``X-Agent-Token`` header set in that agent's MCP client config), and the gateway derives
the caller's role from that token via the AgentIdentityRegistry — NOT from any tool argument.
A call with a missing/unknown token resolves to an unidentified caller, which the integrity
gate fails closed on. This removes the self-asserted-identity spoof (a Recon agent can no
longer claim to be Initial_Access by passing a string).

Modes (GATEWAY_IDENTITY_MODE): "token" (default, secure) | "trust-arg" (dev only — honors the
self-asserted ``agent`` argument; the old, spoofable behavior).

Provision tokens with:  python -m governance_gateway.identity --mint

Config (environment): KKI_PATH, KKI_NETWORK_SCOPE, KKI_CONSENT_MODE, KKI_AUDIT_PATH,
SWARM_INTEGRITY_AUDIT_PATH, GATEWAY_PORT (3000), GATEWAY_ENFORCE_AGENT (1),
GATEWAY_IDENTITY_MODE (token), GATEWAY_TOKENS_FILE / GATEWAY_AGENT_TOKENS.

Run:  python src/governance_gateway/server.py
"""
from __future__ import annotations

import atexit
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from governance_gateway.core import GovernanceGateway          # noqa: E402
from governance_gateway.identity import (                       # noqa: E402
    AgentIdentityRegistry, resolve_identity, AGENT_TOKEN_HEADER, MODE_TOKEN, MODE_TRUST_ARG,
)

_PORT = int(os.environ.get("GATEWAY_PORT", "3000"))
mcp = FastMCP("governance_gateway", port=_PORT)

def _build_preauth():
    """Construct the preventive pre-authorization broker when PREAUTH_ENABLE=1."""
    if os.environ.get("PREAUTH_ENABLE", "0") != "1":
        return None
    import secrets as _secrets
    from preauth import PreAuthBroker, WriteAheadLedger, JitEgress
    from preauth.jit_egress import nft_set_hooks
    secret = (os.environ.get("PREAUTH_SECRET") or "").encode() or _secrets.token_bytes(32)
    if not os.environ.get("PREAUTH_SECRET"):
        sys.stderr.write("[gateway] PREAUTH_SECRET unset — using an ephemeral key (tokens "
                         "won't verify across restarts)\n")
    ttl = float(os.environ.get("PREAUTH_TTL", "10"))
    if os.environ.get("PREAUTH_JIT_NFT", "0") == "1":
        apply_fn, revoke_fn = nft_set_hooks(ttl=int(ttl))
        jit = JitEgress(apply_fn=apply_fn, revoke_fn=revoke_fn)
    else:
        jit = JitEgress()   # tracking-only (no kernel grants); software token gate still holds
    return PreAuthBroker(secret, ledger=WriteAheadLedger(), jit=jit, default_ttl=ttl)


_preauth = _build_preauth()
_gateway = GovernanceGateway(
    consent_mode=os.environ.get("KKI_CONSENT_MODE", "deny"),
    enforce_agent_integrity=os.environ.get("GATEWAY_ENFORCE_AGENT", "1") == "1",
    preauth=_preauth,
)
_registry = AgentIdentityRegistry.from_env()
_mode = os.environ.get("GATEWAY_IDENTITY_MODE", MODE_TOKEN)


@atexit.register
def _persist() -> None:
    try:
        p = _gateway.bridge.save_audit()
        if p:
            sys.stderr.write(f"[gateway] tool audit saved to {p}\n")
    except Exception:
        pass
    try:
        agent_path = os.environ.get("SWARM_INTEGRITY_AUDIT_PATH")
        if agent_path:
            from swarm_integrity.handoff_gate import export_audit
            export_audit(agent_path)
            sys.stderr.write(f"[gateway] agent audit saved to {agent_path}\n")
    except Exception:
        pass
    try:
        ledger_path = os.environ.get("PREAUTH_LEDGER_PATH")
        if _preauth is not None and ledger_path:
            import json
            with open(ledger_path, "w") as f:
                json.dump({"head": _preauth.ledger.head, "entries": _preauth.ledger.entries},
                          f, indent=2, default=str)
            sys.stderr.write(f"[gateway] pre-auth ledger saved to {ledger_path}\n")
    except Exception:
        pass


def _graceful(signum, _frame):
    sys.stderr.write(f"[gateway] signal {signum}; flushing audits and exiting\n")
    sys.exit(0)


signal.signal(signal.SIGTERM, _graceful)


def _caller_token() -> Optional[str]:
    """Best-effort extraction of the per-agent token from the live request headers.

    The attribute path into the ASGI request is mcp-version dependent, so this is wrapped
    defensively: any failure yields None, which in token mode fails closed (safe). If your
    mcp version exposes the request differently, this is the single spot to adjust.
    """
    try:
        ctx = mcp.get_context()
        req_ctx = getattr(ctx, "request_context", None)
        request = getattr(req_ctx, "request", None)        # Starlette Request (http transport)
        if request is not None:
            headers = getattr(request, "headers", None)
            if headers is not None:
                return headers.get(AGENT_TOKEN_HEADER)
    except Exception:
        pass
    return None


def _identity(asserted_agent: str):
    """Resolve (role, source) for the current call from the connection token."""
    token = _caller_token()
    return resolve_identity(_registry, token=token,
                            asserted_agent=asserted_agent or None, mode=_mode)


def _render(env: dict) -> str:
    src = env.get("identity_source")
    if env.get("allowed"):
        result = env.get("result") or {}
        body = (result.get("output") or result.get("stdout") or result.get("result") or result
                if isinstance(result, dict) else result)
        return f"[GATEWAY ✓ {env['tool']} | agent={env.get('agent')} via {src}]\n{body}"
    return (f"[GATEWAY ✗ {env['tool']} | agent={env.get('agent')} via {src} | "
            f"stage={env.get('denied_stage')}]\nreason: {env.get('denial_reason')}\n"
            f"(no execution; the agent and/or tool call did not clear governance)")


def _run(tool: str, params: dict, asserted_agent: str) -> str:
    role, source = _identity(asserted_agent)
    return _render(_gateway.dispatch(tool, params, agent=role, identity_source=source))


@mcp.tool(description="Network discovery and port scanning (governed nmap)")
def nmap(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"target": target}
    if options:
        params["flags"] = options
    return _run("nmap_scan", params, agent)


@mcp.tool(description="Directory/content brute forcing (governed gobuster)")
def gobuster(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _run("gobuster_scan", params, agent)


@mcp.tool(description="Web server vulnerability scanning (governed nikto)")
def nikto(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"target": target}
    if options:
        params["flags"] = options
    return _run("nikto_scan", params, agent)


@mcp.tool(description="SQL injection testing (governed sqlmap) — requires EXPLOIT_TOOLS")
def sqlmap(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _run("sqlmap_scan", params, agent)


@mcp.tool(description="Run a Kali command through governance (terminal surface, allowlisted)")
def command(command: str, agent: str = "") -> Annotated[str, "governed result"]:
    role, source = _identity(agent)
    return _render(_gateway.dispatch_command(command, agent=role, identity_source=source))


@mcp.tool(description="Gateway governance report (both audit chains + roster)")
def gateway_report() -> Annotated[str, "report"]:
    import json
    return json.dumps(_gateway.report(), indent=2, default=str)


if __name__ == "__main__":
    sys.stderr.write(
        f"[gateway] starting on :{_PORT} | tools={_gateway.governed_tools()} "
        f"| consent={os.environ.get('KKI_CONSENT_MODE', 'deny')} "
        f"| enforce_agent={_gateway.enforce_agent_integrity} "
        f"| identity_mode={_mode} | known_roles={_registry.roles()}\n"
    )
    if _mode == MODE_TRUST_ARG:
        sys.stderr.write("[gateway] WARNING: identity_mode=trust-arg — identities are "
                         "self-asserted and SPOOFABLE; use only for dev.\n")
    mcp.run(transport="streamable-http")
