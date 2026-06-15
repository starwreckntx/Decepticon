#!/usr/bin/env python3
"""
Session-bound identity demo/test for the governance gateway.

Proves the spoof we set out to close: identity comes from a per-agent connection token via
the AgentIdentityRegistry, never from a self-asserted argument, and an unidentified caller
fails closed. Runs against the real engines (no mcp/langgraph needed); asserts, exits nonzero
on any failure.

Run:  KKI_PATH=../kali-kimi-interface python examples/gateway_identity_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from governance_gateway.core import GovernanceGateway
from governance_gateway.identity import (
    AgentIdentityRegistry, resolve_identity, MODE_TOKEN, MODE_TRUST_ARG,
)
from swarm_integrity.handoff_gate import get_auditor, reset_auditor


def main() -> int:
    # Mint per-role tokens (what the orchestrator does at setup).
    registry, role_to_token = AgentIdentityRegistry.mint(
        ["Planner", "Reconnaissance", "Initial_Access", "Summary"])
    ia_token = role_to_token["Initial_Access"]
    recon_token = role_to_token["Reconnaissance"]

    # 1. token -> role; unknown/missing -> None (unidentified).
    assert registry.resolve(ia_token) == "Initial_Access"
    assert registry.resolve("forged-token") is None
    assert registry.resolve(None) is None
    print("PASS registry: valid token resolves; forged/missing -> None")

    # 2. token mode IGNORES the self-asserted argument — the spoof is inert.
    #    Recon's token + a claim of "Initial_Access" still resolves to Reconnaissance.
    role, src = resolve_identity(registry, token=recon_token,
                                 asserted_agent="Initial_Access", mode=MODE_TOKEN)
    assert role == "Reconnaissance" and src == "token", (role, src)
    print("PASS token mode: asserted 'Initial_Access' ignored; identity = Reconnaissance (from token)")

    # 3. no token in token mode -> unidentified, regardless of asserted arg.
    role, src = resolve_identity(registry, token=None,
                                 asserted_agent="Initial_Access", mode=MODE_TOKEN)
    assert role is None and src == "none"
    print("PASS token mode: no token -> unidentified even when an identity is asserted")

    # 4. trust-arg mode (dev) honors the argument — documented spoofable fallback.
    role, src = resolve_identity(registry, token=None,
                                 asserted_agent="Initial_Access", mode=MODE_TRUST_ARG)
    assert role == "Initial_Access" and src == "arg"
    print("PASS trust-arg mode: argument honored (dev-only, spoofable)")

    # --- end-to-end through the gateway core (fail-closed on identity) ---
    reset_auditor()
    get_auditor().elect_coordinator()
    gw = GovernanceGateway(network_scope=["192.168.56.0/24"], consent_mode="deny")

    # 5. Unidentified caller (token mode, no token) reaching a capability tool -> DENY at the
    #    agent layer, BEFORE tool governance.
    role, src = resolve_identity(registry, token=None, asserted_agent="Initial_Access", mode=MODE_TOKEN)
    env = gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                      agent=role, identity_source=src)
    assert not env["allowed"] and env["denied_stage"] == "agent_integrity", env
    print(f"PASS unidentified sqlmap -> blocked@{env['denied_stage']} ({env['denial_reason']})")

    # 6. The spoof, end to end: Recon token, asserts Initial_Access, calls sqlmap. Identity
    #    resolves to Reconnaissance (no EXPLOIT_TOOLS) -> STRIPPED, not allowed.
    role, src = resolve_identity(registry, token=recon_token,
                                 asserted_agent="Initial_Access", mode=MODE_TOKEN)
    env = gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                      agent=role, identity_source=src)
    assert not env["allowed"] and env["denied_stage"] == "agent_integrity", env
    assert env["agent_integrity"]["stripped"] == "Reconnaissance", env
    print("PASS spoof defeated: Recon-token call claiming Initial_Access -> STRIP (no priv laundering)")

    # 7. Legitimate Initial_Access token -> passes the agent layer (then tool governance runs).
    role, src = resolve_identity(registry, token=ia_token, asserted_agent="", mode=MODE_TOKEN)
    env = gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                      agent=role, identity_source=src)
    assert env["agent_integrity"]["verdict"] == "ALLOW", env
    print(f"PASS authenticated Initial_Access passes agent layer; tool stage -> "
          f"{env['denied_stage'] or 'allowed'}")

    print("\nAll session-bound identity checks passed — identity is token-derived and "
          "fail-closed; the self-asserted spoof is inert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
