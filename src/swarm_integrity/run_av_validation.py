#!/usr/bin/env python3
"""
run_av_validation.py — execute the AV matrix and emit the agent-integrity evidence bundle.

Mirror of the mesh-gateway run_validation.py. Produces a set of artifacts linked by a
single swarm_seed and an explicit "Integrity Continuity Statement" (the agent-level
analogue of the mesh Mission Continuity Statement, with explicit non-claims). The artifacts
are designed to be reviewed together and independently re-verified by validate_swarm_bundle.py.

Artifacts written to --output-dir:
    av_matrix_results.json     per-test verdicts + evidence
    agent_decision_log.json    seed-deterministic hash-chained decision trail (canonical run)
    capability_state_log.json  strip / quarantine history
    roster_state.json          final roster + coordinator
    integrity_report.json      executive summary + integrity continuity statement
    integrity_report.md        human-readable summary

Run:
    python -m swarm_integrity.run_av_validation --output-dir integrity_output
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from swarm_integrity import ShadowAuditor
from swarm_integrity.constants import SWARM_SEED
from swarm_integrity.validation.test_av_001_through_012 import run_matrix, AV_MATRIX


INTEGRITY_CONTINUITY_STATEMENT = (
    "This bundle validates the Decepticon swarm's AGENT-LEVEL control integrity in "
    "deterministic simulation only. It proves that the ShadowAuditor enforces role-graph "
    "handoff legality, capability ownership, quarantine (strip) on violation, deterministic "
    "coordinator nomination and re-election, and an unbroken, replay-deterministic, "
    "hash-chained audit of every agent decision.\n\n"
    "Explicit non-claims — this bundle does NOT claim:\n"
    "  - correctness or safety of the agents' LLM outputs or security judgement;\n"
    "  - tool-level authorization (that is the separate KKI/Mnemosyne layer in kki_gov);\n"
    "  - resistance to a compromised host or a tampered ShadowAuditor process itself;\n"
    "  - production or live-engagement authorization.\n\n"
    "Closure means: the agent-integrity rules behave correctly under controlled, scripted "
    "conditions. Live-swarm validation against real LLM agents is pending."
)


def _canonical_run() -> ShadowAuditor:
    """A single scripted session that exercises legal flow + every strip path, used as the
    canonical decision_log artifact. Deterministic under SWARM_SEED."""
    a = ShadowAuditor(seed=SWARM_SEED)
    a.open_session("av-canonical")
    a.elect_coordinator()
    a.submit_handoff("Planner", "Reconnaissance")
    a.submit_capability("Reconnaissance", "RECON_TOOLS")
    a.submit_handoff("Reconnaissance", "Initial_Access")
    a.submit_capability("Initial_Access", "EXPLOIT_TOOLS")
    a.assert_coordinator("Initial_Access")              # impersonation -> strip
    a.submit_handoff("Planner", "Initial_Access")       # into quarantine -> deny
    a.submit_capability("Summary", "EXPLOIT_TOOLS")     # priv-esc -> strip
    a.operator_reinstate("Initial_Access")
    a.close_session()
    return a


def main() -> int:
    parser = argparse.ArgumentParser(description="Decepticon agent-integrity validation runner")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=SWARM_SEED)
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    results = run_matrix()
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    auditor = _canonical_run()
    report_state = auditor.session_report()
    now = datetime.now(timezone.utc).isoformat()

    def _write(name: str, payload: Dict[str, Any]) -> None:
        payload.setdefault("swarm_seed", args.seed)
        (out / name).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))

    _write("av_matrix_results.json", {"generated": now, "total": len(results),
                                      "passed": passed, "tests": results})
    _write("agent_decision_log.json", auditor.trail.export())
    _write("capability_state_log.json", {"events": report_state["capability_strips"]})
    _write("roster_state.json", {"roster": report_state["roster"],
                                 "coordinator": report_state["coordinator"],
                                 "stripped_agents": report_state["stripped_agents"]})
    _write("integrity_report.json", {
        "directive": "DECEPTICON-AGENT-INTEGRITY-PHASE1",
        "generated": now,
        "total_tests": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "chain_head": report_state["chain_head"],
        "chain_valid": report_state["chain_valid"],
        "integrity_continuity_statement": INTEGRITY_CONTINUITY_STATEMENT,
        "results": results,
    })

    md = [
        "# Decepticon Agent-Integrity Validation Report",
        "",
        f"**Directive:** DECEPTICON-AGENT-INTEGRITY-PHASE1  ",
        f"**Swarm Seed:** {args.seed}  ",
        f"**Generated:** {now}  ",
        f"**Total Tests:** {len(results)}  **Passed:** {passed}  **Failed:** {len(results) - passed}",
        "",
        "## Integrity Continuity Statement",
        "",
        INTEGRITY_CONTINUITY_STATEMENT,
        "",
        "## AV Matrix",
        "",
        "| Test | Scenario | Verdict |",
        "|------|----------|---------|",
    ]
    for r in results:
        md.append(f"| {r['id']} | {r['scenario']} | {r['verdict']} |")
    md += ["", "## Canonical Decision Chain", "",
           f"- chain_head: `{report_state['chain_head']}`",
           f"- entry_count: {report_state['entry_count']}",
           f"- chain_valid: {report_state['chain_valid']}",
           f"- stripped_agents: {report_state['stripped_agents']}",
           f"- coordinator: {report_state['coordinator']}", "",
           "*Reviewed together with the JSON artifacts; not in isolation.*", ""]
    (out / "integrity_report.md").write_text("\n".join(md))

    print(f"Wrote agent-integrity bundle to {out}/ ({passed}/{len(results)} AV passed)")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
