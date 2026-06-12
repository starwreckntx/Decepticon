"""
AgentIdentity + AgentRoster — the swarm membership model.

Agent-level analogue of the mesh Node + cluster. Each agent has a fixed role, a capability
set derived from that role, and a mutable integrity state. The roster is the set of agents
the ShadowAuditor governs; it is the authority on "who is in play and what may they do".

A *strip* clears an agent's live capability set and moves it to QUARANTINED — the agent
analogue of greying-out a mesh capability. Strips are not reversible by the agent; only an
operator reinstate restores capabilities (default-deny resurrection).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from .constants import (
    ALL_ROLES, ROLE_CAPABILITIES, ROLE_HANDOFF_GRAPH, ROLE_COORDINATOR_PRIORITY,
    STATE_ISOLATED, STATE_ACTIVE, STATE_COORDINATOR, STATE_SUSPENDED, STATE_QUARANTINED,
    CAP_COORDINATE,
)


@dataclass
class AgentIdentity:
    """A single agent's identity, role, live capabilities, and integrity state."""
    agent_id: str
    role: str
    state: str = STATE_ISOLATED
    # Live capabilities start as the role's full set; a strip empties this.
    capabilities: set = field(default_factory=set)
    strip_reason: Optional[str] = None
    stripped_at_step: Optional[int] = None

    def __post_init__(self):
        if self.role not in ROLE_CAPABILITIES:
            raise ValueError(f"unknown role {self.role!r}; valid: {ALL_ROLES}")
        if not self.capabilities:
            self.capabilities = set(ROLE_CAPABILITIES[self.role])

    @property
    def role_capabilities(self) -> FrozenSet[str]:
        """The capabilities this role is *entitled* to (independent of strip state)."""
        return ROLE_CAPABILITIES[self.role]

    @property
    def legal_destinations(self) -> FrozenSet[str]:
        return ROLE_HANDOFF_GRAPH[self.role]

    @property
    def is_quarantined(self) -> bool:
        return self.state == STATE_QUARANTINED

    @property
    def is_coordinator(self) -> bool:
        return self.state == STATE_COORDINATOR

    @property
    def coordinator_priority(self) -> int:
        return ROLE_COORDINATOR_PRIORITY.get(self.role, 99)

    def holds(self, capability: str) -> bool:
        """True only if the capability is both role-entitled AND currently live (not stripped)."""
        return capability in self.capabilities

    def entitled_to(self, capability: str) -> bool:
        """True if the role is entitled to the capability, regardless of strip state."""
        return capability in self.role_capabilities

    def strip(self, reason: str, step: int) -> None:
        self.capabilities = set()
        self.state = STATE_QUARANTINED
        self.strip_reason = reason
        self.stripped_at_step = step

    def reinstate(self) -> None:
        self.capabilities = set(self.role_capabilities)
        self.state = STATE_ACTIVE
        self.strip_reason = None
        self.stripped_at_step = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "state": self.state,
            "capabilities": sorted(self.capabilities),
            "strip_reason": self.strip_reason,
            "stripped_at_step": self.stripped_at_step,
        }


class AgentRoster:
    """The set of agents under integrity governance, keyed by agent_id."""

    def __init__(self):
        self._agents: Dict[str, AgentIdentity] = {}

    def register(self, agent_id: str, role: str) -> AgentIdentity:
        if agent_id in self._agents:
            return self._agents[agent_id]
        agent = AgentIdentity(agent_id=agent_id, role=role, state=STATE_ACTIVE)
        self._agents[agent_id] = agent
        return agent

    def get(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._agents.get(agent_id)

    def by_role(self, role: str) -> List[AgentIdentity]:
        return [a for a in self._agents.values() if a.role == role]

    def active_agents(self) -> List[AgentIdentity]:
        return [a for a in self._agents.values() if not a.is_quarantined]

    def coordinator(self) -> Optional[AgentIdentity]:
        for a in self._agents.values():
            if a.is_coordinator:
                return a
        return None

    def all(self) -> List[AgentIdentity]:
        return list(self._agents.values())

    def snapshot(self) -> Dict[str, Any]:
        return {aid: a.to_dict() for aid, a in self._agents.items()}

    @classmethod
    def default_decepticon(cls) -> "AgentRoster":
        """The stock four-agent Decepticon swarm, each agent_id == role for clarity."""
        roster = cls()
        for role in ALL_ROLES:
            roster.register(role, role)
        return roster
