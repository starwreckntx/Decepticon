"""
Decision — structural audit wrapper for every agent-integrity branch point.

Adapted from the HERMES mesh-gateway audit pattern. The invariant is the whole point:

    No agent-integrity decision may occur without producing its own audit evidence as a
    structural side-effect of being made.

You cannot read a Decision's outcome before it is resolved, resolution atomically writes
to the AgentAuditTrail, and a Decision that is garbage-collected unresolved is *force
recorded* as a failure — it cannot silently escape the chain. That property is what makes
the ShadowAuditor trustworthy: an agent (or a bug) cannot make an integrity decision off
the books.
"""
from __future__ import annotations

import weakref
from typing import Any, Dict, List, Optional


class DecisionNotResolvedError(RuntimeError):
    """Raised when a Decision's outcome is read before it is resolved."""


_live_decisions: "weakref.WeakSet" = weakref.WeakSet()


def get_live_decisions() -> list:
    """Snapshot of currently live (unresolved) Decision objects — used in tick/step audits."""
    return list(_live_decisions)


def clear_live_decisions() -> None:
    _live_decisions.clear()


class Decision:
    """Every agent-integrity branch point is expressed as one of these.

    1. Cannot be constructed without decision_type, step, context, trail.
    2. Cannot be resolved without outcome, rationale, algorithm.
    3. Outcome cannot be read before resolution.
    4. Writes to the AgentAuditTrail atomically on resolution.
    5. Records the alternatives considered and an optional cross-link to the KKI
       tool-level audit (``kki_audit_ref``), so the agent chain and the Mnemosyne tool
       chain can be reconciled without being merged.
    """

    def __init__(
        self,
        decision_type: str,
        step: int,
        context: Dict[str, Any],
        trail: "AgentAuditTrail",
        actor: Optional[str] = None,
    ):
        self.decision_type = decision_type
        self.step = step
        self.context = context
        self.trail = trail
        self.actor = actor
        self._resolved = False
        self._outcome: Any = None
        self._rationale: Optional[str] = None
        self._algorithm: Optional[str] = None
        self._alternatives: Optional[List[Any]] = None
        self._kki_audit_ref: Optional[Any] = None
        self._entry_hash: Optional[str] = None
        _live_decisions.add(self)

    def resolve(
        self,
        outcome: Any,
        rationale: str,
        algorithm: str,
        alternatives: Optional[List[Any]] = None,
        kki_audit_ref: Optional[Any] = None,
    ) -> Any:
        """Resolve, write to the trail, and return the outcome. The ONLY path to the
        outcome; there is no other way to read it."""
        if self._resolved:
            return self._outcome
        if not rationale or not isinstance(rationale, str):
            raise ValueError("rationale must be a non-empty string")

        self._resolved = True
        self._outcome = outcome
        self._rationale = rationale
        self._algorithm = algorithm
        self._alternatives = alternatives or []
        self._kki_audit_ref = kki_audit_ref

        try:
            self._entry_hash = self.trail.record(self)
        except Exception:
            self._resolved = False   # roll back so the failure is visible, then re-raise
            raise

        _live_decisions.discard(self)
        return self._outcome

    @property
    def outcome(self) -> Any:
        if not self._resolved:
            raise DecisionNotResolvedError(
                f"{self.decision_type} at step {self.step} was read before resolution. "
                f"context={self.context}"
            )
        return self._outcome

    @property
    def resolved(self) -> bool:
        return self._resolved

    @property
    def entry_hash(self) -> Optional[str]:
        return self._entry_hash

    def __del__(self):
        """Force-record an unresolved decision at GC. Best-effort; the trail may be gone."""
        if not getattr(self, "_resolved", False):
            try:
                trail = getattr(self, "trail", None)
                if trail is not None:
                    trail.record_unresolved(
                        self, reason="Decision garbage-collected before resolution"
                    )
            except Exception:
                pass
