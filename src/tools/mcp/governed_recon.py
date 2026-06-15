#!/usr/bin/env python3
"""
governed_recon — a governed drop-in replacement for Decepticon's Reconnaissance MCP server.

Decepticon's stock ``Reconnaissance.py`` exposes nmap/curl/dig/whois by building a shell
string and running it inside the attacker container with ``sh -c`` — no validation, no
target scoping, no consent, no audit. This server exposes the same agent-facing tool
surface but routes every call through the KKI IRP governance layer via
``GovernedKaliBridge``:

    validation -> policy -> network scope -> attestation -> consent -> audit -> execute

Refusals are returned to the agent as structured text (not exceptions) so the planner can
reason about *why* an action was blocked and adapt, exactly as it would with a tool error.

Configuration (environment):
    KKI_PATH               path to the kali-kimi-interface checkout (required if not a sibling)
    KKI_NETWORK_SCOPE      comma-separated engagement CIDRs, e.g. "192.168.56.0/24"
                           (STRONGLY recommended — without it the scope gate is advisory)
    KKI_CONSENT_MODE       "broker" (out-of-band human approval, default),
                           "deny" (refuse all DANGER unattended),
                           "preauth" (honor KKI_SESSION_AUTHORIZED=1 for authorized runs)
    KKI_CONSENT_DIR        broker spool dir (default <tmp>/kki-consent-<user>)
    KKI_AUDIT_PATH         where to persist the session audit trail on shutdown
    GOVERNED_RECON_PORT    MCP port (default 3001, matching the stock recon server)

Run:
    python src/tools/mcp/governed_recon.py
"""

from __future__ import annotations

import atexit
import os
import signal
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated

# Make ``src`` importable whether launched as a module or a script.
_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from kki_gov.kki_bridge import GovernedKaliBridge  # noqa: E402


def _scope_from_env():
    raw = os.environ.get("KKI_NETWORK_SCOPE", "").strip()
    return [c.strip() for c in raw.split(",") if c.strip()] or None


_PORT = int(os.environ.get("GOVERNED_RECON_PORT", "3001"))
mcp = FastMCP("governed_reconnaissance", port=_PORT)

_bridge = GovernedKaliBridge(
    network_scope=_scope_from_env(),
    consent_mode=os.environ.get("KKI_CONSENT_MODE", "broker"),
    audit_path=os.environ.get("KKI_AUDIT_PATH"),
)


@atexit.register
def _persist_audit() -> None:
    try:
        path = _bridge.save_audit()
        if path:
            sys.stderr.write(f"[governed_recon] audit trail saved to {path}\n")
    except Exception:
        pass


def _graceful_exit(signum, _frame):
    # `atexit` handlers do NOT run on a bare SIGTERM (what `docker stop` / Kubernetes send),
    # so translate it into a normal exit — that flushes the audit trail via _persist_audit.
    sys.stderr.write(f"[governed_recon] received signal {signum}; flushing audit and exiting\n")
    sys.exit(0)


signal.signal(signal.SIGTERM, _graceful_exit)


def _render(out: dict) -> str:
    """Turn a governance envelope into compact text for the agent to read."""
    if out.get("allowed"):
        result = out.get("result") or {}
        body = result.get("output") or result.get("stdout") or result.get("result") or ""
        if not body and isinstance(result, dict):
            # Structured parser output (e.g. nmap ports) — hand it over verbatim.
            body = result
        return (f"[GOVERNED ✓ allowed | {out['tool']} | radius={out.get('blast_radius')} "
                f"| audit_seq={out.get('audit_seq')}]\n{body}")
    return (f"[GOVERNED ✗ blocked | {out['tool']} | radius={out.get('blast_radius')}]\n"
            f"reason: {out.get('denial_reason')}\n"
            f"(the action did not run; adjust target/flags or request operator consent)")


@mcp.tool(description="Network discovery and port scanning (governed nmap)")
def nmap(target: str, options: str = "") -> Annotated[str, "governed command result"]:
    return _render(_bridge.nmap(target, options=options or None))


@mcp.tool(description="Directory/content brute forcing (governed gobuster)")
def gobuster(target: str, options: str = "") -> Annotated[str, "governed command result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _render(_bridge.scan("gobuster_scan", params))


@mcp.tool(description="Web server vulnerability scanning (governed nikto)")
def nikto(target: str, options: str = "") -> Annotated[str, "governed command result"]:
    params = {"target": target}
    if options:
        params["flags"] = options
    return _render(_bridge.scan("nikto_scan", params))


@mcp.tool(description="SQL injection testing (governed sqlmap)")
def sqlmap(target: str, options: str = "") -> Annotated[str, "governed command result"]:
    params = {"url": target, "target": target}
    if options:
        params["flags"] = options
    return _render(_bridge.scan("sqlmap_scan", params))


@mcp.tool(description="Governance session report (consent + audit summary)")
def governance_report() -> Annotated[str, "session governance report"]:
    import json
    return json.dumps(_bridge.session_report(), indent=2, default=str)


if __name__ == "__main__":
    scope = _scope_from_env()
    sys.stderr.write(
        f"[governed_recon] starting on :{_PORT} | scope={scope or 'UNRESTRICTED (advisory)'} "
        f"| consent={os.environ.get('KKI_CONSENT_MODE', 'broker')}\n"
    )
    mcp.run(transport="streamable-http")
