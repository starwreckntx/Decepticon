"""
Symbolic constants for the swarm agent-integrity layer.

Agent-level analogue of the HERMES mesh-gateway constants: zero raw string literals in
the integrity/strip logic. Every role, capability, state, decision type and algorithm
identifier is named here so the hash-chained audit is self-describing and the bundle
validator can assert against a fixed vocabulary.

The mesh thread elected a *hub* among *nodes*; here we nominate a *coordinator* among
*agents*, gate *handoffs* the way the mesh gated *routes*, and *strip* (quarantine) a
misbehaving agent the way the mesh *greyed-out* a degraded capability.
"""
from __future__ import annotations

# --- Determinism -------------------------------------------------------------------
# Same seed + same event script -> identical chain head. This is the property the whole
# bundle is verifiable on; do not introduce wall-clock or nonce entropy into hashed data.
SWARM_SEED = 424242

# --- Agent roles (Decepticon swarm) ------------------------------------------------
ROLE_PLANNER = "Planner"
ROLE_RECON = "Reconnaissance"
ROLE_INITIAL_ACCESS = "Initial_Access"
ROLE_SUMMARY = "Summary"

ALL_ROLES = (ROLE_PLANNER, ROLE_RECON, ROLE_INITIAL_ACCESS, ROLE_SUMMARY)

# Coordinator nomination priority (lower rank = stronger claim). The Planner is the
# strategic brain, so it is coordinator-eligible first; ties break lexicographically on
# agent_id (mirrors the mesh LEXICOGRAPHIC_NODE_ID_TIEBREAKER).
ROLE_COORDINATOR_PRIORITY = {
    ROLE_PLANNER: 0,
    ROLE_SUMMARY: 1,
    ROLE_RECON: 2,
    ROLE_INITIAL_ACCESS: 3,
}

# --- Capabilities (the things a strip revokes) -------------------------------------
CAP_HANDOFF = "HANDOFF"            # may transfer control to another agent
CAP_COORDINATE = "COORDINATE"      # may hold the coordinator role
CAP_PLAN = "PLAN"
CAP_RECON_TOOLS = "RECON_TOOLS"
CAP_EXPLOIT_TOOLS = "EXPLOIT_TOOLS"
CAP_REPORT = "REPORT"

# Capabilities each role legitimately holds. An agent asserting a capability outside its
# role set is attempting privilege escalation -> strip (see ALGO_STRIP_ON_VIOLATION).
ROLE_CAPABILITIES = {
    ROLE_PLANNER: frozenset({CAP_HANDOFF, CAP_COORDINATE, CAP_PLAN}),
    ROLE_RECON: frozenset({CAP_HANDOFF, CAP_RECON_TOOLS}),
    ROLE_INITIAL_ACCESS: frozenset({CAP_HANDOFF, CAP_EXPLOIT_TOOLS}),
    ROLE_SUMMARY: frozenset({CAP_HANDOFF, CAP_COORDINATE, CAP_REPORT}),
}

# Legal handoff destinations per role (the role graph). Mirrors src/tools/handoff.py: the
# four agents are fully connected, minus self. The gate still matters because it rejects
# handoffs to unknown agents and to quarantined agents, and detects runaway loops.
ROLE_HANDOFF_GRAPH = {
    ROLE_PLANNER: frozenset({ROLE_RECON, ROLE_INITIAL_ACCESS, ROLE_SUMMARY}),
    ROLE_RECON: frozenset({ROLE_PLANNER, ROLE_INITIAL_ACCESS, ROLE_SUMMARY}),
    ROLE_INITIAL_ACCESS: frozenset({ROLE_PLANNER, ROLE_RECON, ROLE_SUMMARY}),
    ROLE_SUMMARY: frozenset({ROLE_PLANNER, ROLE_RECON, ROLE_INITIAL_ACCESS}),
}

# Where control falls back when a handoff is denied or the acting agent is stripped. The
# coordinator is the safe sink (analogue of the mesh EXTERNAL_SINK / hub fallback).
SAFE_FALLBACK_ROLE = ROLE_PLANNER

# --- Agent integrity states (mirror mesh node states) ------------------------------
STATE_ISOLATED = "ISOLATED"          # registered, not yet active
STATE_ACTIVE = "ACTIVE"              # full capabilities, not coordinator
STATE_COORDINATOR = "COORDINATOR"    # the elected hub
STATE_SUSPENDED = "SUSPENDED"        # flagged, capabilities intact, pending review
STATE_QUARANTINED = "QUARANTINED"    # STRIPPED: capabilities revoked, cannot act/hand off

# --- Strip / quarantine reasons ----------------------------------------------------
STRIP_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"   # asserted a capability it lacks
STRIP_ILLEGAL_HANDOFF = "ILLEGAL_HANDOFF"             # destination not in role graph
STRIP_RUNAWAY_LOOP = "RUNAWAY_LOOP"                   # ping-pong beyond depth bound
STRIP_COORDINATOR_IMPERSONATION = "COORDINATOR_IMPERSONATION"
STRIP_POST_STRIP_ACTION = "POST_STRIP_ACTION"        # acted while quarantined
STRIP_OPERATOR = "OPERATOR_DIRECTED"                 # human-initiated strip

# --- Bounds ------------------------------------------------------------------------
MAX_HANDOFF_DEPTH = 6        # max consecutive transfers before loop suspicion
MAX_PAIR_BOUNCES = 2         # A<->B ping-pong tolerance before strip

# --- Decision types (what lands on the hash chain) ---------------------------------
DECISION_SESSION_BOUNDARY = "SESSION_BOUNDARY"
DECISION_AGENT_REGISTER = "AGENT_REGISTER"
DECISION_COORDINATOR_NOMINATION = "COORDINATOR_NOMINATION"
DECISION_AGENT_HANDOFF = "AGENT_HANDOFF"
DECISION_CAPABILITY_ASSERTION = "CAPABILITY_ASSERTION"
DECISION_ROLE_INTEGRITY_CHECK = "ROLE_INTEGRITY_CHECK"
DECISION_AGENT_STRIP = "AGENT_STRIP"
DECISION_AGENT_REINSTATE = "AGENT_REINSTATE"
DECISION_INVARIANT_VIOLATION = "INVARIANT_VIOLATION"
DECISION_COORDINATOR_REELECTION = "COORDINATOR_REELECTION"

# --- Algorithm identifiers (every resolved decision names one) ---------------------
ALGO_COORDINATOR_PRIORITY = "COORDINATOR_PRIORITY_RULE"
ALGO_ROLE_GRAPH_GATE = "ROLE_HANDOFF_GRAPH_GATE"
ALGO_CAPABILITY_OWNERSHIP = "CAPABILITY_OWNERSHIP_RULE"
ALGO_LOOP_DETECTION = "HANDOFF_LOOP_DETECTION"
ALGO_STRIP_ON_VIOLATION = "STRIP_ON_VIOLATION_RULE"
ALGO_QUARANTINE_GATE = "QUARANTINE_GATE"
ALGO_LEXICOGRAPHIC_TIEBREAK = "LEXICOGRAPHIC_AGENT_ID_TIEBREAKER"
ALGO_REINSTATE_OPERATOR = "OPERATOR_REINSTATE_RULE"
ALGO_SESSION = "SESSION_LIFECYCLE"

VALID_ALGORITHMS = frozenset({
    ALGO_COORDINATOR_PRIORITY, ALGO_ROLE_GRAPH_GATE, ALGO_CAPABILITY_OWNERSHIP,
    ALGO_LOOP_DETECTION, ALGO_STRIP_ON_VIOLATION, ALGO_QUARANTINE_GATE,
    ALGO_LEXICOGRAPHIC_TIEBREAK, ALGO_REINSTATE_OPERATOR, ALGO_SESSION,
})

# --- Verdicts ----------------------------------------------------------------------
VERDICT_ALLOW = "ALLOW"
VERDICT_DENY = "DENY"
VERDICT_STRIP = "STRIP"
