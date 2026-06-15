"""
ShadowAuditor — a parallel integrity authority for the swarm, with strip capability.

It runs *alongside* the agents (a "shadow"): the agents cannot see, address, or modify it,
and every agent-level decision — a handoff, a capability assertion, a coordinator claim —
is submitted to it synchronously *before* it is allowed to take effect. The auditor:

    1. wraps the event in a Decision (structural force-audit -> seed-deterministic chain),
    2. evaluates it against role-integrity policy (role graph, capability ownership,
       quarantine state, loop bounds, coordinator authenticity),
    3. and, on a violation, STRIPS the offending agent — revoking its live capabilities
       and quarantining it — recording the strip on the same chain.

"At swarm latency cost": evaluation is synchronous and on the critical path of every
handoff. That is the deliberate trade — integrity over speed. A stripped agent fails
closed: it can no longer hand off or be handed to, and control falls back to the safe
coordinator role.

This is the agent-level complement to KKI's tool-level governance. Tool governance asks
"is this tool call allowed?"; the ShadowAuditor asks "is this *agent* acting within its
role, and is every control transfer on an unbroken chain?" — which captures the decision
to act even when a tool path (e.g. the raw terminal) is itself ungoverned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    SWARM_SEED, SAFE_FALLBACK_ROLE,
    CAP_HANDOFF, CAP_COORDINATE,
    MAX_HANDOFF_DEPTH, MAX_PAIR_BOUNCES,
    STATE_ACTIVE, STATE_COORDINATOR, STATE_QUARANTINED,
    STRIP_PRIVILEGE_ESCALATION, STRIP_ILLEGAL_HANDOFF, STRIP_RUNAWAY_LOOP,
    STRIP_COORDINATOR_IMPERSONATION, STRIP_POST_STRIP_ACTION, STRIP_OPERATOR,
    DECISION_AGENT_REGISTER, DECISION_AGENT_HANDOFF, DECISION_CAPABILITY_ASSERTION,
    DECISION_AGENT_STRIP, DECISION_AGENT_REINSTATE, DECISION_INVARIANT_VIOLATION,
    DECISION_SESSION_BOUNDARY,
    ALGO_ROLE_GRAPH_GATE, ALGO_CAPABILITY_OWNERSHIP, ALGO_LOOP_DETECTION,
    ALGO_STRIP_ON_VIOLATION, ALGO_QUARANTINE_GATE, ALGO_REINSTATE_OPERATOR, ALGO_SESSION,
    VERDICT_ALLOW, VERDICT_DENY, VERDICT_STRIP,
)
from .decision import Decision
from .roster import AgentRoster, AgentIdentity
from .trail import AgentAuditTrail
from . import coordinator as _coordinator


@dataclass
class IntegrityVerdict:
    """Result of submitting an agent event to the ShadowAuditor."""
    verdict: str                       # ALLOW | DENY | STRIP
    actor: str
    action: str                        # e.g. "handoff", "capability:EXPLOIT_TOOLS"
    target: Optional[str] = None
    reason: str = ""
    stripped: Optional[str] = None     # agent_id that was stripped, if any
    fallback: Optional[str] = None     # where control should go on DENY/STRIP
    entry_hash: Optional[str] = None
    audit_index: Optional[int] = None

    @property
    def allowed(self) -> bool:
        return self.verdict == VERDICT_ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict, "actor": self.actor, "action": self.action,
            "target": self.target, "reason": self.reason, "stripped": self.stripped,
            "fallback": self.fallback, "entry_hash": self.entry_hash,
            "audit_index": self.audit_index,
        }


class ShadowAuditor:
    def __init__(self, roster: Optional[AgentRoster] = None, seed: int = SWARM_SEED):
        self.roster = roster or AgentRoster.default_decepticon()
        self.trail = AgentAuditTrail(seed)
        self._step = 0
        # Per-pair bounce counters for runaway-loop detection: (src,dst) -> count.
        self._bounces: Dict[Tuple[str, str], int] = {}
        self._handoff_run = 0          # consecutive handoffs without other activity
        self._capability_strips: List[Dict[str, Any]] = []  # capability-state log

    # -- lifecycle --------------------------------------------------------------------

    def open_session(self, label: str = "swarm-session") -> None:
        d = Decision(DECISION_SESSION_BOUNDARY, self._tick(), {"event": "open", "label": label},
                     self.trail, actor="ShadowAuditor")
        d.resolve(outcome="opened", rationale=f"session {label} opened", algorithm=ALGO_SESSION)
        # Register every roster member on the chain so the membership baseline is auditable.
        for agent in self.roster.all():
            rd = Decision(DECISION_AGENT_REGISTER, self._tick(),
                          {"agent_id": agent.agent_id, "role": agent.role}, self.trail,
                          actor="ShadowAuditor")
            rd.resolve(outcome=agent.to_dict(),
                       rationale=f"registered {agent.agent_id} as {agent.role}",
                       algorithm=ALGO_SESSION)

    def close_session(self) -> Dict[str, Any]:
        d = Decision(DECISION_SESSION_BOUNDARY, self._tick(), {"event": "close"}, self.trail,
                     actor="ShadowAuditor")
        d.resolve(outcome="closed", rationale="session closed", algorithm=ALGO_SESSION)
        return self.session_report()

    # -- the gate: every agent decision passes through here ---------------------------

    def submit_handoff(self, source_id: str, dest_id: str) -> IntegrityVerdict:
        """Evaluate a proposed control transfer. Returns a verdict and records the decision.

        Order of checks (fail closed at the first that refuses):
          1. acting agent must exist and not be quarantined (POST_STRIP_ACTION -> already stripped)
          2. acting agent must currently hold HANDOFF
          3. destination must exist
          4. destination must be a legal role-graph target (else STRIP source)
          5. destination must not be quarantined (no resurrection-by-handoff)
          6. runaway-loop bound (else STRIP source)
        """
        step = self._tick()
        src = self.roster.get(source_id)
        dst = self.roster.get(dest_id)

        decision = Decision(
            DECISION_AGENT_HANDOFF, step,
            {"source": source_id, "dest": dest_id,
             "src_state": getattr(src, "state", None), "dst_state": getattr(dst, "state", None)},
            self.trail, actor=source_id,
        )

        # 1. acting agent must be known and live.
        if src is None:
            return self._deny(decision, source_id, "handoff", dest_id,
                              f"unknown source agent {source_id!r}", ALGO_QUARANTINE_GATE)
        if src.is_quarantined:
            return self._deny(decision, source_id, "handoff", dest_id,
                              f"{source_id} is quarantined and may not initiate handoffs",
                              ALGO_QUARANTINE_GATE, fallback=self._fallback())

        # 2. capability ownership: must currently hold HANDOFF.
        if not src.holds(CAP_HANDOFF):
            return self._deny(decision, source_id, "handoff", dest_id,
                              f"{source_id} does not hold {CAP_HANDOFF}",
                              ALGO_CAPABILITY_OWNERSHIP, fallback=self._fallback())

        # 3. destination existence.
        if dst is None:
            return self._strip(decision, src, "handoff", dest_id,
                               f"handoff to unknown agent {dest_id!r}",
                               STRIP_ILLEGAL_HANDOFF)

        # 4. role-graph legality.
        if dst.role not in src.legal_destinations:
            return self._strip(decision, src, "handoff", dest_id,
                               f"{src.role} -> {dst.role} is not a legal handoff "
                               f"({sorted(src.legal_destinations)})",
                               STRIP_ILLEGAL_HANDOFF)

        # 5. no handoff INTO a quarantined agent.
        if dst.is_quarantined:
            return self._deny(decision, source_id, "handoff", dest_id,
                              f"{dest_id} is quarantined; cannot receive control",
                              ALGO_QUARANTINE_GATE, fallback=self._fallback())

        # 6. runaway-loop detection.
        key = (source_id, dest_id)
        self._bounces[key] = self._bounces.get(key, 0) + 1
        self._handoff_run += 1
        if self._bounces[key] > MAX_PAIR_BOUNCES or self._handoff_run > MAX_HANDOFF_DEPTH:
            return self._strip(decision, src, "handoff", dest_id,
                               f"runaway loop: pair_bounces={self._bounces[key]} "
                               f"run={self._handoff_run} exceeds bounds",
                               STRIP_RUNAWAY_LOOP, algorithm=ALGO_LOOP_DETECTION)

        # ALLOW.
        decision.resolve(
            outcome={"verdict": VERDICT_ALLOW, "dest": dest_id},
            rationale=f"{src.role} -> {dst.role} legal; {source_id} holds {CAP_HANDOFF}; not looping",
            algorithm=ALGO_ROLE_GRAPH_GATE,
            alternatives=sorted(src.legal_destinations),
        )
        return IntegrityVerdict(
            VERDICT_ALLOW, source_id, "handoff", dest_id,
            reason="legal handoff", entry_hash=decision.entry_hash,
            audit_index=self.trail.entry_count - 1,
        )

    def submit_capability(self, agent_id: str, capability: str) -> IntegrityVerdict:
        """Evaluate an agent exercising a capability (e.g. running an EXPLOIT tool). An agent
        asserting a capability its role is not entitled to is privilege escalation -> STRIP."""
        step = self._tick()
        agent = self.roster.get(agent_id)
        decision = Decision(
            DECISION_CAPABILITY_ASSERTION, step,
            {"agent_id": agent_id, "capability": capability,
             "state": getattr(agent, "state", None)},
            self.trail, actor=agent_id,
        )
        if agent is None:
            return self._deny(decision, agent_id, f"capability:{capability}", None,
                              f"unknown agent {agent_id!r}", ALGO_QUARANTINE_GATE)
        if agent.is_quarantined:
            return self._strip(decision, agent, f"capability:{capability}", None,
                               f"{agent_id} exercised {capability} while quarantined",
                               STRIP_POST_STRIP_ACTION)
        # Entitlement: is the ROLE allowed this capability at all?
        if not agent.entitled_to(capability):
            return self._strip(decision, agent, f"capability:{capability}", None,
                               f"{agent.role} is not entitled to {capability} "
                               f"(role caps: {sorted(agent.role_capabilities)})",
                               STRIP_PRIVILEGE_ESCALATION)
        # Live possession (could have been individually revoked).
        if not agent.holds(capability):
            return self._deny(decision, agent_id, f"capability:{capability}", None,
                              f"{agent_id} does not currently hold {capability}",
                              ALGO_CAPABILITY_OWNERSHIP, fallback=self._fallback())
        decision.resolve(
            outcome={"verdict": VERDICT_ALLOW, "capability": capability},
            rationale=f"{agent.role} is entitled to and currently holds {capability}",
            algorithm=ALGO_CAPABILITY_OWNERSHIP,
        )
        return IntegrityVerdict(VERDICT_ALLOW, agent_id, f"capability:{capability}", None,
                                reason="capability held", entry_hash=decision.entry_hash,
                                audit_index=self.trail.entry_count - 1)

    def assert_coordinator(self, agent_id: str) -> IntegrityVerdict:
        """An agent claiming to act AS the coordinator. If it is not the elected coordinator,
        that is impersonation -> STRIP (mirror of the mesh self-promotion gate)."""
        step = self._tick()
        agent = self.roster.get(agent_id)
        decision = Decision(
            DECISION_INVARIANT_VIOLATION, step,
            {"agent_id": agent_id, "claim": "coordinator",
             "actual_coordinator": getattr(self.roster.coordinator(), "agent_id", None)},
            self.trail, actor=agent_id,
        )
        if agent is None:
            return self._deny(decision, agent_id, "assert:coordinator", None,
                              f"unknown agent {agent_id!r}", ALGO_QUARANTINE_GATE)
        if not agent.is_coordinator:
            return self._strip(decision, agent, "assert:coordinator", None,
                               f"{agent_id} claimed coordinator but the elected coordinator is "
                               f"{getattr(self.roster.coordinator(), 'agent_id', None)}",
                               STRIP_COORDINATOR_IMPERSONATION)
        decision.resolve(
            outcome={"verdict": VERDICT_ALLOW},
            rationale=f"{agent_id} is the elected coordinator",
            algorithm=ALGO_QUARANTINE_GATE,
        )
        return IntegrityVerdict(VERDICT_ALLOW, agent_id, "assert:coordinator", None,
                                reason="is coordinator", entry_hash=decision.entry_hash,
                                audit_index=self.trail.entry_count - 1)

    # -- coordinator election / re-election ------------------------------------------

    def elect_coordinator(self, reelection: bool = False) -> Optional[AgentIdentity]:
        return _coordinator.nominate_coordinator(self.roster, self.trail, self._tick(),
                                                  reelection=reelection)

    # -- operator-directed actions ----------------------------------------------------

    def operator_strip(self, agent_id: str, reason: str = STRIP_OPERATOR) -> IntegrityVerdict:
        step = self._tick()
        agent = self.roster.get(agent_id)
        decision = Decision(DECISION_AGENT_STRIP, step,
                            {"agent_id": agent_id, "initiator": "operator"}, self.trail,
                            actor="operator")
        if agent is None:
            return self._deny(decision, agent_id, "operator_strip", None,
                              f"unknown agent {agent_id!r}", ALGO_STRIP_ON_VIOLATION)
        was_coord = agent.is_coordinator
        agent.strip(reason, step)
        self._capability_strips.append({"step": step, "agent_id": agent_id, "reason": reason})
        decision.resolve(outcome=agent.to_dict(),
                         rationale=f"operator stripped {agent_id}: {reason}",
                         algorithm=ALGO_STRIP_ON_VIOLATION)
        v = IntegrityVerdict(VERDICT_STRIP, "operator", "operator_strip", agent_id,
                             reason=reason, stripped=agent_id, fallback=self._fallback(),
                             entry_hash=decision.entry_hash,
                             audit_index=self.trail.entry_count - 1)
        if was_coord:
            self.elect_coordinator(reelection=True)
        return v

    def operator_reinstate(self, agent_id: str) -> IntegrityVerdict:
        """Restore a stripped agent. Only an operator can do this — agents cannot
        self-resurrect (default-deny resurrection)."""
        step = self._tick()
        agent = self.roster.get(agent_id)
        decision = Decision(DECISION_AGENT_REINSTATE, step,
                            {"agent_id": agent_id, "initiator": "operator"}, self.trail,
                            actor="operator")
        if agent is None or not agent.is_quarantined:
            return self._deny(decision, agent_id, "operator_reinstate", None,
                              f"{agent_id} is not quarantined / unknown", ALGO_REINSTATE_OPERATOR)
        agent.reinstate()
        decision.resolve(outcome=agent.to_dict(),
                         rationale=f"operator reinstated {agent_id}",
                         algorithm=ALGO_REINSTATE_OPERATOR)
        return IntegrityVerdict(VERDICT_ALLOW, "operator", "operator_reinstate", agent_id,
                                reason="reinstated", entry_hash=decision.entry_hash,
                                audit_index=self.trail.entry_count - 1)

    # -- internal helpers -------------------------------------------------------------

    def _tick(self) -> int:
        self._step += 1
        return self._step

    def _fallback(self) -> str:
        coord = self.roster.coordinator()
        if coord is not None and not coord.is_quarantined:
            return coord.agent_id
        return SAFE_FALLBACK_ROLE

    def _deny(self, decision: Decision, actor: str, action: str, target: Optional[str],
              reason: str, algorithm: str, fallback: Optional[str] = None) -> IntegrityVerdict:
        decision.resolve(outcome={"verdict": VERDICT_DENY, "reason": reason},
                         rationale=reason, algorithm=algorithm)
        return IntegrityVerdict(VERDICT_DENY, actor, action, target, reason=reason,
                                fallback=fallback, entry_hash=decision.entry_hash,
                                audit_index=self.trail.entry_count - 1)

    def _strip(self, decision: Decision, agent: AgentIdentity, action: str,
               target: Optional[str], reason: str, strip_reason: str,
               algorithm: str = ALGO_STRIP_ON_VIOLATION) -> IntegrityVerdict:
        """Record the triggering decision AND a STRIP decision, then quarantine the agent.
        Re-elects the coordinator if the stripped agent was it."""
        step = decision.step
        was_coord = agent.is_coordinator
        decision.resolve(outcome={"verdict": VERDICT_STRIP, "reason": reason, "strip": strip_reason},
                         rationale=reason, algorithm=algorithm)
        agent.strip(strip_reason, step)
        self._capability_strips.append({"step": step, "agent_id": agent.agent_id,
                                        "reason": strip_reason})
        strip_decision = Decision(DECISION_AGENT_STRIP, self._tick(),
                                  {"agent_id": agent.agent_id, "trigger": strip_reason},
                                  self.trail, actor="ShadowAuditor")
        strip_decision.resolve(outcome=agent.to_dict(),
                               rationale=f"stripped {agent.agent_id}: {strip_reason}",
                               algorithm=ALGO_STRIP_ON_VIOLATION)
        v = IntegrityVerdict(VERDICT_STRIP, agent.agent_id, action, target, reason=reason,
                             stripped=agent.agent_id, fallback=self._fallback(),
                             entry_hash=strip_decision.entry_hash,
                             audit_index=self.trail.entry_count - 1)
        if was_coord:
            self.elect_coordinator(reelection=True)
        return v

    # -- reporting --------------------------------------------------------------------

    def session_report(self) -> Dict[str, Any]:
        valid, reason = self.trail.verify_chain()
        return {
            "swarm_seed": self.trail._seed,
            "chain_head": self.trail.head_hash,
            "entry_count": self.trail.entry_count,
            "chain_valid": valid,
            "chain_reason": reason,
            "roster": self.roster.snapshot(),
            "coordinator": getattr(self.roster.coordinator(), "agent_id", None),
            "stripped_agents": [a.agent_id for a in self.roster.all() if a.is_quarantined],
            "capability_strips": self._capability_strips,
        }
