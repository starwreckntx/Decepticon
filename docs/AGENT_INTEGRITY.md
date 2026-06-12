# Agent-Level Integrity for the Decepticon Swarm

**A ShadowAuditor with strip authority + a seed-deterministic, hash-chained record of every
agent decision — modeled on the HERMES mesh-gateway V&V bundle.**

The tool-level KKI governance (`kki_gov/`, see `GOVERNED_KKI_INTEGRATION.md`) answers *"is
this tool call allowed?"*. This layer answers the complementary question: *"is this **agent**
acting within its role, and is every control transfer on an unbroken, tamper-evident
chain?"* — which captures the **decision to act** even when a tool path (e.g. the raw
terminal) is itself ungoverned.

## Why "shadow" and why "strip"

Decepticon's stock handoff transfers control with a bare `Command(goto=agent_name)` — no
role check, no audit, no brake. A prompt-injected or runaway agent can seize control, bounce
it in a loop, or assert capabilities it shouldn't have, and nothing records or stops it.

The **ShadowAuditor** runs *alongside* the agents — they cannot see, address, or modify it.
Every agent-level decision (a handoff, a capability assertion, a coordinator claim) is
submitted to it **synchronously, before it takes effect**. This is the deliberate "at swarm
latency cost" trade: integrity is on the critical path, not best-effort. On a violation the
auditor **strips** the offending agent — revokes its live capabilities and quarantines it
out of the swarm — the agent-level analogue of the mesh "grey-out" of a degraded capability.

## The mesh parallel, mapped

| HERMES mesh-gateway | Decepticon agent integrity |
|---|---|
| Nodes with eligibility | Agents with a role + capability set (`roster.py`) |
| Hub election (centroid rule) | Coordinator nomination (priority + lexicographic tiebreak, `coordinator.py`) |
| Hub-failure re-election (VV-009) | Coordinator re-election when the coordinator is stripped |
| Route-violation prevention (VV-006/007) | Role-graph handoff legality + no-handoff-into-quarantine |
| Capability grey-out (VV-012) | Agent **strip** / quarantine on violation |
| Self-promotion gate (VV-011) | Coordinator-impersonation strip |
| Hash-chained `decision_log.json` | `agent_decision_log.json` (seed-deterministic) |
| `Decision` structural force-audit | Same pattern (`decision.py`) — a decision cannot escape the chain |
| VV-001…VV-012 matrix | AV-001…AV-012 matrix (`validation/test_av_001_through_012.py`) |
| `validate_bundle.py` → PHASE-1-CLOSED | `validate_swarm_bundle.py` → AGENT-INTEGRITY-CLOSED |

## The integrity gates (fail closed, in order)

A handoff `source → dest` is **ALLOWED** only if all hold; otherwise it is **DENIED**
(control falls back to the coordinator) or the source is **STRIPPED**:

1. source exists and is **not quarantined** (a stripped agent can't act → DENY)
2. source currently **holds `HANDOFF`** (capability ownership → DENY)
3. dest exists — else **STRIP** source (`ILLEGAL_HANDOFF`)
4. dest is a **legal role-graph target** — else **STRIP** source (`ILLEGAL_HANDOFF`)
5. dest is **not quarantined** — no resurrection-by-handoff → DENY
6. not a **runaway loop** (pair-bounce / depth bound) — else **STRIP** (`RUNAWAY_LOOP`)

Capability assertions strip on `PRIVILEGE_ESCALATION` (asserting a capability outside the
role) and `POST_STRIP_ACTION`. Claiming the coordinator role when you are not the elected
coordinator strips on `COORDINATOR_IMPERSONATION`. A stripped agent is **only** restored by
an operator (`operator_reinstate`) — agents cannot self-resurrect (default-deny).

## Audit chain — standalone + composable

The agent chain is **separate** from KKI's HMAC Mnemosyne tool-level audit, deliberately:
the mesh thread's load-bearing property is **replay-determinism** (same seed + same event
script → identical `chain_head`), and KKI's chain is keyed/nonce-based and not reproducible.
Merging would destroy that property. Instead each agent decision can carry a `kki_audit_ref`
cross-linking to the corresponding tool-level entry, so the two chains reconcile without
merging — giving end-to-end integrity (agent decision → tool call) across two verifiable
records.

## Run it (no LLMs, no langgraph required)

```bash
# AV matrix
PYTHONPATH=src python src/swarm_integrity/validation/test_av_001_through_012.py   # 12/12

# Quick self-test (matrix + determinism + singleton)
PYTHONPATH=src python src/swarm_integrity/selftest.py

# Generate the evidence bundle, then independently validate + close it
PYTHONPATH=src python src/swarm_integrity/run_av_validation.py --output-dir integrity_output
PYTHONPATH=src python src/swarm_integrity/validate_swarm_bundle.py --output-dir integrity_output
#   -> writes AGENT-INTEGRITY-CLOSED.txt with SHA-256 of every artifact, or exits 2 on any break
```

Tampering with any chain entry makes `validate_swarm_bundle.py` fail with
`chain break at entry N: entry_hash mismatch` (exit 2) — the closure cannot be forged.

## Wire it into the live swarm

`handoff_gate.py` is a near drop-in for `src/utils/swarm/handoff.py`. Per agent, e.g. in
`src/agents/swarm/Recon.py`:

```python
from swarm_integrity.handoff_gate import governed_handoff_tools_for
swarm_tools = governed_handoff_tools_for("Reconnaissance")   # governed handoff tools
```

Every transfer now passes the ShadowAuditor first; refused transfers route control to the
safe coordinator instead of the requested agent, and a violating agent is quarantined out of
the run. `langgraph` is imported lazily, so the audit core and AV bundle run without it.

## Files

| Path | Role |
|------|------|
| `src/swarm_integrity/constants.py` | Roles, capabilities, role graph, states, decision/algorithm vocab, `SWARM_SEED` |
| `src/swarm_integrity/decision.py` | `Decision` — structural force-audit wrapper (can't escape the chain) |
| `src/swarm_integrity/trail.py` | `AgentAuditTrail` — seed-deterministic hash chain + `verify_chain` |
| `src/swarm_integrity/roster.py` | `AgentIdentity` / `AgentRoster` — membership, capabilities, strip/reinstate |
| `src/swarm_integrity/coordinator.py` | Deterministic coordinator nomination + re-election |
| `src/swarm_integrity/shadow_auditor.py` | `ShadowAuditor` — the gate with strip authority |
| `src/swarm_integrity/handoff_gate.py` | Governed `create_handoff_tool` for the live langgraph swarm |
| `src/swarm_integrity/validation/test_av_001_through_012.py` | AV-001…AV-012 matrix |
| `src/swarm_integrity/run_av_validation.py` | Emits the evidence bundle |
| `src/swarm_integrity/validate_swarm_bundle.py` | Independent validator → `AGENT-INTEGRITY-CLOSED.txt` |
| `src/swarm_integrity/selftest.py` | Quick deterministic check |

## Scope & non-claims (Phase 1)

Closure means the **agent-integrity rules behave correctly in deterministic simulation**. It
does **not** claim: correctness/safety of the agents' LLM outputs or security judgement;
tool-level authorization (that is the KKI/Mnemosyne layer); resistance to a compromised host
or a tampered ShadowAuditor process itself; or production authorization. Live-swarm
validation against real LLM agents is the next phase.
