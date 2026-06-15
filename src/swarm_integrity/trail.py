"""
AgentAuditTrail — seed-deterministic, hash-chained, append-only log of agent decisions.

Chain properties (mirrored from the HERMES mesh decision_log):
- Every entry hashes its predecessor (prev_hash) and itself (entry_hash).
- The genesis hash is seeded with SWARM_SEED, so the same seed + same decision sequence
  reproduce the identical chain head — the replay-determinism property the bundle is
  validated on.
- Unresolved decisions are *recorded*, never suppressed.

This chain is deliberately separate from KKI's HMAC Mnemosyne tool-level audit: that one
is keyed/non-reproducible by design, this one is reproducible by design. They cross-link
by reference (entries may carry kki_audit_ref) rather than merging.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Tuple


class AgentAuditTrail:
    def __init__(self, seed: int):
        self._entries: List[Dict[str, Any]] = []
        self._seed = seed
        self._head_hash = self._genesis_hash(seed)

    @staticmethod
    def _genesis_hash(seed: int) -> str:
        return hashlib.sha256(f"GENESIS:{seed}".encode()).hexdigest()

    def record(self, decision) -> str:
        """Append a resolved decision; return its entry hash. Called by Decision.resolve()."""
        entry = {
            "entry_index": len(self._entries),
            "prev_hash": self._head_hash,
            "step": decision.step,
            "actor": decision.actor,
            "decision_type": decision.decision_type,
            "context": decision.context,
            "outcome": self._serialize(decision._outcome),
            "rationale": decision._rationale,
            "algorithm": decision._algorithm,
            "alternatives": decision._alternatives or [],
            "kki_audit_ref": decision._kki_audit_ref,
            "resolved": True,
        }
        return self._append(entry)

    def record_unresolved(self, decision, reason: str) -> str:
        """Forced failure record for a decision that was never resolved. Cannot be suppressed."""
        entry = {
            "entry_index": len(self._entries),
            "prev_hash": self._head_hash,
            "step": getattr(decision, "step", -1),
            "actor": getattr(decision, "actor", None),
            "decision_type": getattr(decision, "decision_type", "UNKNOWN"),
            "context": getattr(decision, "context", {}),
            "outcome": None,
            "rationale": None,
            "algorithm": None,
            "alternatives": [],
            "kki_audit_ref": None,
            "resolved": False,
            "unresolved_reason": reason,
        }
        return self._append(entry)

    def _append(self, entry: Dict[str, Any]) -> str:
        entry_hash = self._hash_entry(entry)
        entry["entry_hash"] = entry_hash
        self._entries.append(entry)
        self._head_hash = entry_hash
        return entry_hash

    def verify_chain(self) -> Tuple[bool, str]:
        """Walk the chain; any break returns (False, reason). Used by the bundle validator."""
        if not self._entries:
            return True, "OK (empty chain)"
        prev = self._genesis_hash(self._seed)
        for i, entry in enumerate(self._entries):
            if entry.get("prev_hash") != prev:
                return False, f"chain break at entry {i}: prev_hash mismatch"
            recomputed = self._hash_entry({k: v for k, v in entry.items() if k != "entry_hash"})
            if recomputed != entry.get("entry_hash"):
                return False, f"chain break at entry {i}: entry_hash mismatch"
            prev = entry["entry_hash"]
        return True, "OK"

    def export(self) -> Dict[str, Any]:
        return {
            "swarm_seed": self._seed,
            "chain_head": self._head_hash,
            "entry_count": len(self._entries),
            "entries": self._entries,
        }

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        canonical = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _serialize(outcome: Any) -> Any:
        if outcome is None or isinstance(outcome, (str, int, float, bool, list, dict)):
            return outcome
        if hasattr(outcome, "to_dict"):
            return outcome.to_dict()
        if hasattr(outcome, "__dict__"):
            return {k: v for k, v in outcome.__dict__.items() if not k.startswith("_")}
        return str(outcome)

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return self._entries
