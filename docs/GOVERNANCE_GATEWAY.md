# The Governance Gateway — a non-bypassable deployment

The first two layers (KKI tool governance in `kki_gov/`, agent integrity in
`swarm_integrity/`) are **cooperative**: drop-in libraries and servers the swarm is *trusted
to call*. The gateway makes governance **mandatory** — the swarm executes inside it. It is a
*reference monitor*: a single chokepoint that is non-bypassable (by topology), enforces both
layers on every call, and records two tamper-evident chains.

## The shift

```
 BEFORE (cooperative)                         AFTER (mandatory)
 agent ─► governed_recon (3001)               agent ┐
 agent ─► stock Initial_Access (3002)  ✗      agent ├─► Governance Gateway (3000) ─► tools
 agent ─► stock terminal (3003)        ✗      agent ┘        │
   (multiple routes; some ungoverned)         agent          └─ enforces BOTH layers + audit
                                              (one route; nothing else reachable)
```

Every agent's MCP client points at one URL (`mcp_config.gateway.json`). There is no other
route to a tool, so the otherwise-ungoverned `Initial_Access` and `terminal` surfaces are
covered for free — not by bridging each, but because the only door is the monitor.

## What the gateway enforces, per call

```
agent tool call ─►  Stage 1: AGENT INTEGRITY (ShadowAuditor)
                      does the calling agent's role hold the required capability?
                      recon tools→RECON_TOOLS, sqlmap→EXPLOIT_TOOLS
                      NO → refuse (and STRIP the agent for privilege escalation)
                    Stage 2: TOOL GOVERNANCE (KKI GovernedExecutor)
                      validation → policy → network scope → attestation → consent → execute
                    ──► allowed only if BOTH stages clear; both chains recorded
```

A call can die at the **agent** layer before tool governance is ever consulted — e.g. a Recon
agent reaching for `sqlmap` is stripped on the spot. The free-form `command` tool (the
terminal surface) parses the leading binary: known binaries route through full governance,
unknown ones are refused by allowlist and the attempt is recorded on the agent chain.

The gateway shares the **same ShadowAuditor singleton** as the live handoff gate, so an
agent's tool-capability assertions and its control-transfers land on one unified,
seed-deterministic agent chain — cross-linked (by reference) to KKI's separate HMAC tool
chain. Two verifiable records, one chokepoint.

## Deploy (one command)

```bash
# KKI checked out beside this repo (or set KKI_PATH).  Brings up gateway + kali + victim.
make up
# then launch the swarm pointed at the gateway (MCP_CONFIG selects the gateway topology):
make frontend      # or: make web
```

`make up` runs `docker compose -f docker-compose.yml -f docker-compose.governed.yml
--profile governed up`. The gateway image is built **on the Kali base** so the tools live in
the same container as the gateway — binary attestation and execution are real and co-located.
Both audit chains persist to `./logs/` (`kki-audit.json`, `agent-audit.json`) and are flushed
on SIGTERM (`docker stop`).

## Try it without containers

```bash
KKI_PATH=../kali-kimi-interface python examples/gateway_demo.py   # both layers, one chokepoint
make verify                                                       # all self-tests + AV bundle
```

## Configuration

| Env | Meaning |
|-----|---------|
| `MCP_CONFIG` | config the loader reads; set to `mcp_config.gateway.json` for the gateway topology |
| `GATEWAY_PORT` | gateway endpoint port (default 3000) |
| `GATEWAY_ENFORCE_AGENT` | `1` (default) runs Stage-1 agent-integrity; `0` tool-governance only |
| `KKI_NETWORK_SCOPE` | engagement CIDRs (tool-governance scope gate) |
| `KKI_CONSENT_MODE` | `deny` / `broker` / `preauth` for DANGER tool calls |
| `KKI_AUDIT_PATH`, `SWARM_INTEGRITY_AUDIT_PATH` | where the two chains are written on exit |

## Honest limits (this slice)

- **Agent identity is currently an argument** the caller supplies; a lying agent could claim
  another identity. The next hardening binds identity to the MCP session/transport rather
  than trusting the `agent` parameter.
- The gateway is a new **single point of failure** and a latency hop on every call — the
  intended trade for a non-bypassable monitor. It fails closed.
- It does not defend against a compromised **gateway host**; that is what externally-anchored
  audit (a later slice) is for.
- `command` gating is **binary-allowlist**, not a full shell grammar — pipelines/quoting are
  refused rather than parsed. Extending to a real command policy is future work.

## Files

| Path | Role |
|------|------|
| `src/governance_gateway/core.py` | `GovernanceGateway` — the two-stage dispatch core (no mcp/langgraph needed) |
| `src/governance_gateway/server.py` | FastMCP single-endpoint server (the one URL) |
| `mcp_config.gateway.json` | Points every agent at the gateway |
| `src/utils/mcp/mcp_loader.py` | Honors `MCP_CONFIG` so the governed topology is selectable |
| `deploy/Dockerfile.gateway` | Kali-based gateway image (tools co-located for real attestation) |
| `docker-compose.governed.yml` | `--profile governed` overlay adding the gateway |
| `Makefile` | `make up` / `frontend` / `demo` / `verify` / `audit` |
| `examples/gateway_demo.py` | End-to-end both-layers demonstration |
