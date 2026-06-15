"""
swarm_integrity — agent-level integrity for the Decepticon swarm.

A ShadowAuditor runs alongside the agents with authority to *strip* (quarantine) any agent
that violates role integrity, and records every agent-level decision (handoff, capability
assertion, coordinator nomination, strip) on a seed-deterministic, hash-chained audit
trail. The structure mirrors the HERMES mesh-gateway V&V bundle: a Decision wrapper that
cannot escape the chain, a deterministic election, an AV-NNN validation matrix, and an
independent bundle validator that emits a hash-stamped closure.

This is the agent-level complement to the tool-level KKI governance in ``kki_gov``: the two
chains cross-link (agent decisions may carry a ``kki_audit_ref``) for end-to-end integrity.
"""
from __future__ import annotations

from .shadow_auditor import ShadowAuditor, IntegrityVerdict
from .roster import AgentRoster, AgentIdentity
from .trail import AgentAuditTrail
from .decision import Decision, DecisionNotResolvedError

__all__ = [
    "ShadowAuditor", "IntegrityVerdict",
    "AgentRoster", "AgentIdentity",
    "AgentAuditTrail",
    "Decision", "DecisionNotResolvedError",
]
