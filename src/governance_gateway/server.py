#!/usr/bin/env python3
"""
MCP Governance Gateway server — the ONE endpoint every Decepticon agent connects to.

Point all four agents' MCP config at this single URL (see mcp_config.gateway.json). Every
tool call then traverses the gateway, which enforces agent-integrity + KKI tool-governance
and records both chains. There is no other route to a tool, so the governance is
non-bypassable by topology — including the otherwise free-form terminal surface, exposed
here as the governed ``command`` tool.

The agent identity is taken from the MCP call's ``agent`` argument; in the langgraph swarm
that is the active agent. (A future hardening is to bind identity to the transport/session
rather than trust an argument — see docs.)

Config (environment): KKI_PATH, KKI_NETWORK_SCOPE, KKI_CONSENT_MODE, KKI_AUDIT_PATH,
SWARM_INTEGRITY_AUDIT_PATH, GATEWAY_PORT (default 3000), GATEWAY_ENFORCE_AGENT (default 1).

Run:  python src/governance_gateway/server.py
"""
from __future__ import annotations

import atexit
import os
import signal
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from governance_gateway.core import GovernanceGateway  # noqa: E402

_PORT = int(os.environ.get("GATEWAY_PORT", "3000"))
mcp = FastMCP("governance_gateway", port=_PORT)

_gateway = GovernanceGateway(
    consent_mode=os.environ.get("KKI_CONSENT_MODE", "deny"),
    enforce_agent_integrity=os.environ.get("GATEWAY_ENFORCE_AGENT", "1") == "1",
)


@atexit.register
def _persist() -> None:
    # Flush BOTH chains on exit: KKI tool chain + the agent integrity chain.
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


def _graceful(signum, _frame):
    sys.stderr.write(f"[gateway] signal {signum}; flushing audits and exiting\n")
    sys.exit(0)


signal.signal(signal.SIGTERM, _graceful)


def _render(env: dict) -> str:
    if env.get("allowed"):
        result = env.get("result") or {}
        body = (result.get("output") or result.get("stdout") or result.get("result") or result
                if isinstance(result, dict) else result)
        return f"[GATEWAY ✓ {env['tool']} | agent={env.get('agent')}]\n{body}"
    return (f"[GATEWAY ✗ {env['tool']} | agent={env.get('agent')} | "
            f"stage={env.get('denied_stage')}]\nreason: {env.get('denial_reason')}\n"
            f"(no execution; the agent and/or tool call did not clear governance)")


@mcp.tool(description="Network discovery and port scanning (governed nmap)")
def nmap(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"target": target}
    if options:
        params["flags"] = options
    return _render(_gateway.dispatch("nmap_scan", params, agent=agent or None))


@mcp.tool(description="Directory/content brute forcing (governed gobuster)")
def gobuster(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _render(_gateway.dispatch("gobuster_scan", params, agent=agent or None))


@mcp.tool(description="Web server vulnerability scanning (governed nikto)")
def nikto(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"target": target}
    if options:
        params["flags"] = options
    return _render(_gateway.dispatch("nikto_scan", params, agent=agent or None))


@mcp.tool(description="SQL injection testing (governed sqlmap) — requires EXPLOIT_TOOLS")
def sqlmap(target: str, options: str = "", agent: str = "") -> Annotated[str, "governed result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _render(_gateway.dispatch("sqlmap_scan", params, agent=agent or None))


@mcp.tool(description="Run a Kali command through governance (terminal surface, allowlisted)")
def command(command: str, agent: str = "") -> Annotated[str, "governed result"]:
    return _render(_gateway.dispatch_command(command, agent=agent or None))


@mcp.tool(description="Gateway governance report (both audit chains + roster)")
def gateway_report() -> Annotated[str, "report"]:
    import json
    return json.dumps(_gateway.report(), indent=2, default=str)


if __name__ == "__main__":
    sys.stderr.write(
        f"[gateway] starting on :{_PORT} | tools={_gateway.governed_tools()} "
        f"| consent={os.environ.get('KKI_CONSENT_MODE', 'deny')} "
        f"| enforce_agent={_gateway.enforce_agent_integrity}\n"
    )
    mcp.run(transport="streamable-http")
