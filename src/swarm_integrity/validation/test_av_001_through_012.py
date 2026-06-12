#!/usr/bin/env python3
"""
AV (Agent-integrity Validation) matrix — AV-001 … AV-012.

Agent-level analogue of the HERMES VV-001…VV-012 mesh matrix. Each test drives the
ShadowAuditor through a controlled scenario and asserts the integrity invariant holds,
returning a structured verdict record that run_av_validation.py serializes into the
evidence bundle. Deterministic: fixed seed, scripted events, no wall-clock in hashed data.

Run standalone:  python -m swarm_integrity.validation.test_av_001_through_012
            or:  python src/swarm_integrity/validation/test_av_001_through_012.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from swarm_integrity import ShadowAuditor
from swarm_integrity.constants import (
    SWARM_SEED, VERDICT_ALLOW, VERDICT_DENY, VERDICT_STRIP,
    STRIP_PRIVILEGE_ESCALATION, STRIP_ILLEGAL_HANDOFF, STRIP_RUNAWAY_LOOP,
    STRIP_COORDINATOR_IMPERSONATION, STRIP_POST_STRIP_ACTION,
    DECISION_AGENT_HANDOFF, DECISION_AGENT_STRIP, DECISION_COORDINATOR_NOMINATION,
    DECISION_CAPABILITY_ASSERTION, DECISION_COORDINATOR_REELECTION,
)


def _auditor(label: str) -> ShadowAuditor:
    a = ShadowAuditor(seed=SWARM_SEED)
    a.open_session(label)
    a.elect_coordinator()
    return a


# --- AV tests --------------------------------------------------------------------------
# Each returns (passed: bool, reason: str, evidence: dict).

def av_001_coordinator_nomination():
    """A coordinator is deterministically nominated; Planner wins on priority."""
    a = _auditor("AV-001")
    coord = a.roster.coordinator()
    types = {e["decision_type"] for e in a.trail.entries}
    ok = coord is not None and coord.agent_id == "Planner" and DECISION_COORDINATOR_NOMINATION in types
    return ok, f"coordinator={getattr(coord,'agent_id',None)}, nomination_logged={DECISION_COORDINATOR_NOMINATION in types}", \
        {"coordinator": getattr(coord, "agent_id", None)}


def av_002_legal_handoff_allowed():
    """A role-graph-legal handoff by a capable agent is ALLOWED."""
    a = _auditor("AV-002")
    v = a.submit_handoff("Planner", "Reconnaissance")
    return v.verdict == VERDICT_ALLOW, f"verdict={v.verdict}", v.to_dict()


def av_003_illegal_destination_strips():
    """A handoff to an agent outside the role graph (unknown) STRIPS the source."""
    a = _auditor("AV-003")
    v = a.submit_handoff("Planner", "Nonexistent")
    src = a.roster.get("Planner")
    return (v.verdict == VERDICT_STRIP and src.is_quarantined and v.stripped == "Planner"), \
        f"verdict={v.verdict}, source_quarantined={src.is_quarantined}", v.to_dict()


def av_004_privilege_escalation_strips():
    """An agent asserting a capability outside its role is STRIPPED (priv-esc)."""
    a = _auditor("AV-004")
    v = a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")
    agent = a.roster.get("Reconnaissance")
    return (v.verdict == VERDICT_STRIP and agent.is_quarantined
            and agent.strip_reason == STRIP_PRIVILEGE_ESCALATION), \
        f"verdict={v.verdict}, strip_reason={agent.strip_reason}", v.to_dict()


def av_005_capability_in_role_allowed():
    """An in-role capability assertion is ALLOWED."""
    a = _auditor("AV-005")
    v = a.submit_capability("Initial_Access", "EXPLOIT_TOOLS")
    return v.verdict == VERDICT_ALLOW, f"verdict={v.verdict}", v.to_dict()


def av_006_post_strip_action_denied():
    """A stripped agent cannot act: a post-strip handoff is DENIED (fails closed)."""
    a = _auditor("AV-006")
    a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")   # strip it
    v = a.submit_handoff("Reconnaissance", "Summary")
    return v.verdict == VERDICT_DENY and v.fallback is not None, \
        f"verdict={v.verdict}, fallback={v.fallback}", v.to_dict()


def av_007_no_handoff_into_quarantine():
    """Control cannot be transferred INTO a quarantined agent (no resurrection-by-handoff)."""
    a = _auditor("AV-007")
    a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")   # quarantine Recon
    v = a.submit_handoff("Planner", "Reconnaissance")
    return v.verdict == VERDICT_DENY, f"verdict={v.verdict}", v.to_dict()


def av_008_runaway_loop_strips():
    """A handoff ping-pong beyond the bounce bound STRIPS the looping source."""
    a = _auditor("AV-008")
    verdicts = []
    # Planner<->Summary repeatedly until the loop guard trips.
    for _ in range(5):
        verdicts.append(a.submit_handoff("Planner", "Summary").verdict)
        verdicts.append(a.submit_handoff("Summary", "Planner").verdict)
    stripped = any(v == VERDICT_STRIP for v in verdicts)
    return stripped, f"verdicts={verdicts}", {"verdicts": verdicts}


def av_009_coordinator_impersonation_strips():
    """A non-coordinator claiming the coordinator role is STRIPPED."""
    a = _auditor("AV-009")
    v = a.assert_coordinator("Initial_Access")
    agent = a.roster.get("Initial_Access")
    return (v.verdict == VERDICT_STRIP and agent.strip_reason == STRIP_COORDINATOR_IMPERSONATION), \
        f"verdict={v.verdict}, strip_reason={agent.strip_reason}", v.to_dict()


def av_010_coordinator_reelection_on_strip():
    """Stripping the coordinator triggers deterministic re-election to the next-priority agent."""
    a = _auditor("AV-010")
    old = a.roster.coordinator().agent_id
    a.operator_strip("Planner")
    new = a.roster.coordinator().agent_id
    types = [e["decision_type"] for e in a.trail.entries]
    return (old == "Planner" and new is not None and new != old
            and DECISION_COORDINATOR_REELECTION in types), \
        f"old={old}, new={new}, reelection_logged={DECISION_COORDINATOR_REELECTION in types}", \
        {"old_coordinator": old, "new_coordinator": new}


def av_011_operator_reinstate_restores():
    """Only an operator can reinstate a stripped agent; reinstatement restores role caps."""
    a = _auditor("AV-011")
    a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")   # strip
    before = a.roster.get("Reconnaissance").is_quarantined
    a.operator_reinstate("Reconnaissance")
    agent = a.roster.get("Reconnaissance")
    return (before and not agent.is_quarantined and agent.holds("RECON_TOOLS")), \
        f"was_quarantined={before}, now_quarantined={agent.is_quarantined}, caps={sorted(agent.capabilities)}", \
        agent.to_dict()


def av_012_chain_integrity_and_no_unresolved():
    """The audit chain verifies, is replay-deterministic, and has zero unresolved decisions."""
    def scripted():
        a = ShadowAuditor(seed=SWARM_SEED)
        a.open_session("AV-012")
        a.elect_coordinator()
        a.submit_handoff("Planner", "Reconnaissance")
        a.submit_capability("Reconnaissance", "RECON_TOOLS")
        a.submit_capability("Reconnaissance", "EXPLOIT_TOOLS")   # strip
        a.submit_handoff("Planner", "Initial_Access")
        a.close_session()
        return a
    a1, a2 = scripted(), scripted()
    valid, reason = a1.trail.verify_chain()
    unresolved = [e for e in a1.trail.entries if not e.get("resolved")]
    deterministic = a1.trail.head_hash == a2.trail.head_hash
    return (valid and not unresolved and deterministic), \
        f"chain_valid={valid} ({reason}), unresolved={len(unresolved)}, deterministic={deterministic}", \
        {"chain_head": a1.trail.head_hash, "entry_count": a1.trail.entry_count}


AV_MATRIX: List[Dict[str, Any]] = [
    {"id": "AV-001", "scenario": "Coordinator deterministic nomination", "fn": av_001_coordinator_nomination},
    {"id": "AV-002", "scenario": "Role-graph-legal handoff allowed", "fn": av_002_legal_handoff_allowed},
    {"id": "AV-003", "scenario": "Illegal destination strips source", "fn": av_003_illegal_destination_strips},
    {"id": "AV-004", "scenario": "Privilege escalation strips agent", "fn": av_004_privilege_escalation_strips},
    {"id": "AV-005", "scenario": "In-role capability allowed", "fn": av_005_capability_in_role_allowed},
    {"id": "AV-006", "scenario": "Post-strip action denied (fail closed)", "fn": av_006_post_strip_action_denied},
    {"id": "AV-007", "scenario": "No handoff into quarantine", "fn": av_007_no_handoff_into_quarantine},
    {"id": "AV-008", "scenario": "Runaway loop strips source", "fn": av_008_runaway_loop_strips},
    {"id": "AV-009", "scenario": "Coordinator impersonation strips", "fn": av_009_coordinator_impersonation_strips},
    {"id": "AV-010", "scenario": "Coordinator re-election on strip", "fn": av_010_coordinator_reelection_on_strip},
    {"id": "AV-011", "scenario": "Operator reinstate restores caps", "fn": av_011_operator_reinstate_restores},
    {"id": "AV-012", "scenario": "Chain integrity + determinism + zero unresolved", "fn": av_012_chain_integrity_and_no_unresolved},
]


def run_matrix() -> List[Dict[str, Any]]:
    results = []
    for t in AV_MATRIX:
        try:
            passed, reason, evidence = t["fn"]()
        except Exception as e:  # a raising test is a failure, not a crash
            passed, reason, evidence = False, f"exception: {e}", {}
        results.append({
            "id": t["id"], "scenario": t["scenario"],
            "verdict": "PASS" if passed else "FAIL", "reason": reason, "evidence": evidence,
        })
    return results


def main() -> int:
    results = run_matrix()
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    for r in results:
        print(f"{r['verdict']}  {r['id']}  {r['scenario']}  —  {r['reason']}")
    print(f"\n{passed}/{len(results)} AV tests passed.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
