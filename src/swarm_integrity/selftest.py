#!/usr/bin/env python3
"""
Quick deterministic self-test for the swarm agent-integrity layer.

Runs the AV matrix and asserts 12/12 plus replay-determinism and the live-auditor
singleton. No LLMs, no langgraph required.

Run:  python -m swarm_integrity.selftest   (or  python src/swarm_integrity/selftest.py)
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from swarm_integrity import ShadowAuditor
from swarm_integrity.constants import SWARM_SEED
from swarm_integrity.validation.test_av_001_through_012 import run_matrix


def _script(seed):
    a = ShadowAuditor(seed=seed)
    a.open_session("selftest")
    a.elect_coordinator()
    a.submit_handoff("Planner", "Reconnaissance")
    a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")   # strip
    a.submit_handoff("Planner", "Initial_Access")
    a.close_session()
    return a.trail.head_hash


def main() -> int:
    results = run_matrix()
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    assert passed == len(results), f"AV matrix: {passed}/{len(results)} passed"

    assert _script(SWARM_SEED) == _script(SWARM_SEED), "replay determinism broken"
    assert _script(1) != _script(2), "different seeds must diverge"

    # Live-auditor singleton stays consistent across imports.
    from swarm_integrity.handoff_gate import get_auditor, reset_auditor
    reset_auditor()
    a1 = get_auditor()
    a2 = get_auditor()
    assert a1 is a2, "auditor singleton not stable"
    reset_auditor()

    print(f"PASS — AV matrix {passed}/{len(results)}, determinism OK, singleton OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
