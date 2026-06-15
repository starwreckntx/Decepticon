#!/usr/bin/env python3
"""
Demo: governing Decepticon's red-team tool calls through the KKI IRP layer.

Runs a handful of agent-style proposals through ``GovernedKaliBridge`` against the REAL
KKI governance engine (no test doubles) and prints the decision for each, then the session
audit/consent report. It is environment-aware: where a Kali binary is absent the danger
gate fails closed at attestation (a correct governance outcome), while the injection and
network-scope refusals hold everywhere.

Run:
    KKI_PATH=/path/to/kali-kimi-interface python examples/governed_kki_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from kki_gov.kki_bridge import GovernedKaliBridge


SCOPE = ["192.168.56.0/24"]


def _show(title: str, out: dict) -> None:
    verdict = "ALLOWED" if out["allowed"] else "BLOCKED"
    print(f"\n[{verdict}] {title}")
    print(f"    tool          : {out['tool']} -> {out.get('kki_tool')}")
    print(f"    blast_radius  : {out.get('blast_radius')}")
    if not out["allowed"]:
        print(f"    denial_reason : {out.get('denial_reason')}")
    print(f"    audit_seq     : {out.get('audit_seq')}")


def main() -> int:
    print("=" * 78)
    print("Decepticon × KKI — governed red-team tool calls")
    print(f"engagement network scope: {SCOPE}")
    print("consent mode: deny (no operator attached for this non-interactive demo)")
    print("=" * 78)

    # consent_mode='deny' => DANGER actions cannot self-authorize. In a real run you'd use
    # 'broker' and approve out-of-band; here we show the gate holding by default.
    bridge = GovernedKaliBridge(network_scope=SCOPE, consent_mode="deny")

    # 1) Well-formed, in-scope scan. Refused only at the consent gate (or attestation if the
    #    nmap binary is absent) — never silently run.
    _show("in-scope nmap SYN scan, no operator consent",
          bridge.nmap("192.168.56.101", options="-sS -p 1-1000"))

    # 2) Command injection in the target — refused at the policy/validation layer.
    _show("command injection in target",
          bridge.nmap("192.168.56.101; rm -rf /", options="-sS"))

    # 3) Target outside the engagement scope — refused at the network-scope gate.
    _show("out-of-scope target (8.8.8.8)",
          bridge.nmap("8.8.8.8", options="-sS"))

    # 4) Disallowed flag — only allowlisted nmap flags survive validation.
    _show("disallowed nmap flag (--script-args evil)",
          bridge.nmap("192.168.56.101", options="--script-args attacker=1"))

    # 5) A tool this bridge does not govern — refused before any executor is reached.
    _show("ungoverned tool (metasploit)",
          bridge.scan("metasploit", {"target": "192.168.56.101"}))

    print("\n" + "=" * 78)
    print("session governance report (boundary consent + tamper-evident audit state):")
    print(json.dumps(bridge.session_report(), indent=2, default=str))
    print("=" * 78)
    print("\nEvery proposal above was evaluated BEFORE execution. Nothing dangerous ran "
          "without\npassing validation, scope, attestation, and human consent — and every "
          "step is\nrecorded in the append-only HMAC-chained audit trail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
