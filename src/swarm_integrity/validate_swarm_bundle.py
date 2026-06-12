#!/usr/bin/env python3
"""
validate_swarm_bundle.py — independent post-hoc validator for the agent-integrity bundle.

Mirror of the mesh-gateway validate_bundle.py. Runs AFTER run_av_validation.py; does not
re-run the simulation. It re-verifies the evidence and, only if every check passes, writes
AGENT-INTEGRITY-CLOSED.txt with SHA-256 hashes of every artifact and explicit non-claims.

Checks:
  1. all required artifacts present
  2. swarm_seed consistent across artifacts
  3. decision chain re-verifies (re-hash the chain independently)
  4. zero unresolved decisions
  5. every resolved entry has a non-empty rationale and a valid ALGO_* identifier
  6. required decision types present
  7. AV matrix has the full set of tests and all PASS
  8. integrity continuity statement present in both reports
  9. AGENT-INTEGRITY-CLOSED.txt does not already exist (no overwrite)

Exit codes: 0 = closed, 2 = validation failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from swarm_integrity.trail import AgentAuditTrail
from swarm_integrity.constants import (
    SWARM_SEED, VALID_ALGORITHMS,
    DECISION_COORDINATOR_NOMINATION, DECISION_AGENT_HANDOFF, DECISION_AGENT_STRIP,
    DECISION_CAPABILITY_ASSERTION,
)

REQUIRED_ARTIFACTS = [
    "av_matrix_results.json",
    "agent_decision_log.json",
    "capability_state_log.json",
    "roster_state.json",
    "integrity_report.json",
    "integrity_report.md",
]
REQUIRED_DECISION_TYPES = {
    DECISION_COORDINATOR_NOMINATION, DECISION_AGENT_HANDOFF,
    DECISION_AGENT_STRIP, DECISION_CAPABILITY_ASSERTION,
}
EXPECTED_AV_COUNT = 12


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_present(d: Path) -> List[str]:
    return [f"missing artifact: {a}" for a in REQUIRED_ARTIFACTS if not (d / a).exists()]


def _check_seed(d: Path, seed: int) -> List[str]:
    errs = []
    for a in REQUIRED_ARTIFACTS:
        if a.endswith(".json") and (d / a).exists():
            data = json.loads((d / a).read_text())
            if data.get("swarm_seed") not in (seed, None):
                errs.append(f"{a}: seed mismatch ({data.get('swarm_seed')} != {seed})")
    return errs


def _check_chain(d: Path, seed: int) -> List[str]:
    errs: List[str] = []
    path = d / "agent_decision_log.json"
    if not path.exists():
        return ["agent_decision_log.json missing"]
    log = json.loads(path.read_text())
    entries = log.get("entries", [])

    trail = AgentAuditTrail(seed)
    trail._entries = entries
    trail._head_hash = log.get("chain_head", "")
    valid, reason = trail.verify_chain()
    if not valid:
        errs.append(f"chain integrity failure: {reason}")

    unresolved = [e for e in entries if not e.get("resolved")]
    if unresolved:
        errs.append(f"{len(unresolved)} unresolved decision(s)")

    empty_rationale = [e for e in entries
                       if e.get("resolved") and not (e.get("rationale") or "")]
    if empty_rationale:
        errs.append(f"{len(empty_rationale)} resolved entries with empty rationale")

    bad_algo = [e for e in entries
                if e.get("resolved") and e.get("algorithm") not in VALID_ALGORITHMS]
    if bad_algo:
        errs.append(f"{len(bad_algo)} entries with invalid algorithm identifier")

    found = {e.get("decision_type") for e in entries}
    missing = REQUIRED_DECISION_TYPES - found
    if missing:
        errs.append(f"missing required decision types: {sorted(missing)}")
    return errs


def _check_matrix(d: Path) -> List[str]:
    errs: List[str] = []
    path = d / "av_matrix_results.json"
    if not path.exists():
        return ["av_matrix_results.json missing"]
    data = json.loads(path.read_text())
    tests = data.get("tests", [])
    if len(tests) != EXPECTED_AV_COUNT:
        errs.append(f"av_matrix has {len(tests)} tests, expected {EXPECTED_AV_COUNT}")
    failed = [t["id"] for t in tests if t.get("verdict") != "PASS"]
    if failed:
        errs.append(f"AV tests not passing: {failed}")
    return errs


def _check_continuity(d: Path) -> List[str]:
    errs: List[str] = []
    md = d / "integrity_report.md"
    if not md.exists() or "Integrity Continuity Statement" not in md.read_text():
        errs.append("integrity_report.md missing Integrity Continuity Statement")
    js = d / "integrity_report.json"
    if js.exists():
        if "integrity_continuity_statement" not in json.loads(js.read_text()):
            errs.append("integrity_report.json missing integrity_continuity_statement")
    else:
        errs.append("integrity_report.json missing")
    return errs


def _write_closed(d: Path, seed: int) -> None:
    lines = [
        "# Decepticon Agent-Integrity Phase 1 Closure",
        f"swarm_seed: {seed}",
        f"timestamp: {datetime.now(timezone.utc).isoformat()}",
        "agent_chain_integrity: verified",
        "live_swarm_validation_pending: true",
        "integrity_continuity_statement_ref: integrity_report.json#integrity_continuity_statement",
        "",
        "## Artifact Hashes (SHA-256)",
    ]
    for a in REQUIRED_ARTIFACTS:
        p = d / a
        if p.exists():
            lines.append(f"SHA-256: {_hash_file(p)}  {a}")
    lines += [
        "",
        "## Closure Meaning",
        "The agent-integrity rules behave correctly in deterministic simulation.",
        "This closure does NOT claim LLM-output correctness, tool-level authorization",
        "(see the KKI/Mnemosyne layer), host integrity, or production authorization.",
        "",
    ]
    (d / "AGENT-INTEGRITY-CLOSED.txt").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decepticon agent-integrity bundle validator")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=SWARM_SEED)
    args = parser.parse_args()
    d = Path(args.output_dir)

    errors: List[str] = []
    errors += _check_present(d)
    errors += _check_seed(d, args.seed)
    errors += _check_chain(d, args.seed)
    errors += _check_matrix(d)
    errors += _check_continuity(d)
    if (d / "AGENT-INTEGRITY-CLOSED.txt").exists():
        errors.append("AGENT-INTEGRITY-CLOSED.txt already exists — prevent overwrite")

    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        return 2

    _write_closed(d, args.seed)
    print("AGENT-INTEGRITY-CLOSED.txt written. Agent-integrity Phase 1 closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
