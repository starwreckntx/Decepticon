"""
Coordinator nomination — the agent-level analogue of the mesh hub election.

The mesh chose a hub by geospatial centroid with telemetry disqualification; a swarm has
no geometry, so the deterministic rule is: among non-quarantined agents that hold the
COORDINATE capability, pick the lowest coordinator-priority rank, breaking ties
lexicographically on agent_id. Every nomination is wrapped in a Decision, so the choice
and its alternatives land on the hash chain (mirrors HUB_NOMINATION).

Re-election (mirror of VV-009 hub-failure re-election) is the same rule run again after
the incumbent coordinator is stripped or removed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    CAP_COORDINATE, STATE_COORDINATOR, STATE_ACTIVE,
    DECISION_COORDINATOR_NOMINATION, DECISION_COORDINATOR_REELECTION,
    ALGO_COORDINATOR_PRIORITY, ALGO_LEXICOGRAPHIC_TIEBREAK,
)
from .decision import Decision
from .roster import AgentRoster, AgentIdentity
from .trail import AgentAuditTrail


def _rank(agent: AgentIdentity) -> Tuple[int, str]:
    """Sort key: (priority rank, agent_id) — deterministic and total."""
    return (agent.coordinator_priority, agent.agent_id)


def nominate_coordinator(
    roster: AgentRoster,
    trail: AgentAuditTrail,
    step: int,
    reelection: bool = False,
) -> Optional[AgentIdentity]:
    """Deterministically nominate (or re-elect) the swarm coordinator and record it.

    Returns the elected agent, or None when no eligible agent exists (the swarm has no
    coordinator — analogue of a sub-threshold no-hub cluster)."""
    eligible: List[AgentIdentity] = sorted(
        (a for a in roster.active_agents() if a.holds(CAP_COORDINATE)),
        key=_rank,
    )

    decision = Decision(
        decision_type=DECISION_COORDINATOR_REELECTION if reelection else DECISION_COORDINATOR_NOMINATION,
        step=step,
        context={
            "eligible": [a.agent_id for a in eligible],
            "priorities": {a.agent_id: a.coordinator_priority for a in eligible},
            "reelection": reelection,
        },
        trail=trail,
        actor="ShadowAuditor",
    )

    if not eligible:
        decision.resolve(
            outcome=None,
            rationale="no non-quarantined COORDINATE-capable agent available; swarm has no coordinator",
            algorithm=ALGO_COORDINATOR_PRIORITY,
            alternatives=[],
        )
        return None

    winner = eligible[0]
    runners_up = [a.agent_id for a in eligible[1:]]
    tie = len(eligible) > 1 and eligible[1].coordinator_priority == winner.coordinator_priority
    decision.resolve(
        outcome={"agent_id": winner.agent_id, "role": winner.role},
        rationale=(
            f"{winner.agent_id} has lowest coordinator priority "
            f"{winner.coordinator_priority}"
            + (" (lexicographic tiebreak applied)" if tie else "")
        ),
        algorithm=ALGO_LEXICOGRAPHIC_TIEBREAK if tie else ALGO_COORDINATOR_PRIORITY,
        alternatives=runners_up,
    )

    # Demote any prior coordinator, promote the winner.
    prior = roster.coordinator()
    if prior is not None and prior.agent_id != winner.agent_id and not prior.is_quarantined:
        prior.state = STATE_ACTIVE
    winner.state = STATE_COORDINATOR
    return winner
