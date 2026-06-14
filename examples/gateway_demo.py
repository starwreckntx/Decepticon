#!/usr/bin/env python3
"""
Demo: the single governance gateway enforcing BOTH layers on every tool call.

Drives GovernanceGateway.dispatch against the real engines (KKI tool governance + the
ShadowAuditor) — no mcp/langgraph needed. Shows the two-stage envelope: a call can be
refused at the AGENT layer (capability the role lacks → strip) before it ever reaches TOOL
governance, and the free-form `command` surface is gated by allowlist.

Run:  KKI_PATH=../kali-kimi-interface python examples/gateway_demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from governance_gateway.core import GovernanceGateway
from swarm_integrity.handoff_gate import get_auditor, reset_auditor


def show(title, env):
    verdict = "ALLOWED" if env.get("allowed") else f"BLOCKED@{env.get('denied_stage')}"
    print(f"\n[{verdict}] {title}")
    print(f"    tool={env['tool']} agent={env.get('agent')}")
    if not env.get("allowed"):
        print(f"    reason: {env.get('denial_reason')}")
    ai = env.get("agent_integrity")
    if ai:
        print(f"    agent_integrity: verdict={ai['verdict']} stripped={ai.get('stripped')}")


def main():
    reset_auditor()
    get_auditor().elect_coordinator()
    gw = GovernanceGateway(network_scope=["192.168.56.0/24"], consent_mode="deny")

    print("=" * 78)
    print("Governance Gateway — one chokepoint, two layers (agent integrity + KKI tools)")
    print("scope=192.168.56.0/24  consent=deny")
    print("=" * 78)

    # Recon agent runs an in-scope nmap: agent layer passes (Recon holds RECON_TOOLS);
    # tool layer evaluates (blocks at attestation here — no nmap binary — a correct outcome).
    show("Reconnaissance -> nmap 192.168.56.10 (in role, in scope)",
         gw.dispatch("nmap_scan", {"target": "192.168.56.10", "flags": "-sS"}, agent="Reconnaissance"))

    # Recon agent reaches for sqlmap (EXPLOIT): refused at the AGENT layer and STRIPPED,
    # before tool governance is even consulted.
    show("Reconnaissance -> sqlmap (capability it does NOT hold)",
         gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                     agent="Reconnaissance"))

    # Initial_Access agent runs sqlmap: agent layer passes (holds EXPLOIT_TOOLS).
    show("Initial_Access -> sqlmap (in role)",
         gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                     agent="Initial_Access"))

    # Free-form command, known binary: routed through full governance.
    show("command 'nmap -sS 192.168.56.10' (terminal surface, allowlisted binary)",
         gw.dispatch_command("nmap -sS 192.168.56.10", agent="Reconnaissance"))

    # Free-form command, unknown binary: refused by allowlist (no ungoverned shell).
    show("command 'rm -rf /' (terminal surface, binary NOT allowlisted)",
         gw.dispatch_command("rm -rf /", agent="Summary"))

    # Out-of-scope: blocked at tool governance scope gate even for a capable agent.
    show("Initial_Access -> sqlmap against 8.8.8.8 (out of scope)",
         gw.dispatch("sqlmap_scan", {"url": "http://8.8.8.8/", "target": "8.8.8.8"},
                     agent="Initial_Access"))

    rep = gw.report()
    print("\n" + "=" * 78)
    print("unified report (both chains):")
    print(json.dumps({
        "agent_chain_valid": rep["agent_integrity"]["chain_valid"],
        "agent_chain_entries": rep["agent_integrity"]["entry_count"],
        "stripped_agents": rep["agent_integrity"]["stripped_agents"],
        "tool_chain_valid": rep["tool_governance"]["auditor_state"]["chain_valid"],
    }, indent=2, default=str))
    print("=" * 78)
    print("\nOne endpoint enforced agent-integrity AND tool-governance on every call, and the "
          "free-form\ncommand surface was gated by allowlist — nothing reached a tool except "
          "through the chokepoint.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
