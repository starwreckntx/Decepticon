# Governing Decepticon with the Kali Kimi Interface (KKI)

**Proof of concept: a human-apex governance layer for an autonomous red-team swarm.**

Decepticon drives offensive security tools with autonomous LLM agents ("vibe hacking").
That autonomy is the point — and the risk. This integration puts the
[Kali Kimi Interface](https://github.com/starwreckntx/kali-kimi-interface) **IRP
governance layer** in front of every tool call the swarm makes, so that running Decepticon
"in the wild" means running it under validation, scope control, human consent, and a
tamper-evident audit trail — not unsupervised shell access.

---

## The gap this closes

Decepticon's stock recon/terminal MCP servers execute whatever string an agent produces,
straight inside the attacker container:

```python
# src/tools/mcp/Reconnaissance.py
subprocess.run(["docker", "exec", CONTAINER_NAME, "sh", "-c", command])
```

There is **no input validation, no target scoping, no human approval, and no audit**. An
agent that hallucinates a target, gets prompt-injected by a scan result, or simply makes a
mistake can run an arbitrary command against an arbitrary host, and nothing records or
gates it. For a self-driving offensive system, that is the whole ballgame.

## What governance adds

Every proposed tool call is routed through KKI's `GovernedExecutor`, which enforces this
pipeline and **fails closed** at the first gate that refuses:

| Gate | Enforces | Example refusal |
|------|----------|-----------------|
| Positive allowlist validation | No shell metacharacters; flags from a per-tool allowlist | `target '...; rm -rf /'` → blocked |
| Permission-as-code policy | `danger-full-access` ⇒ requires consent | nmap classified DANGER |
| Network-scope allowlist | Target must be inside the engagement CIDRs | `8.8.8.8` outside scope → blocked |
| Per-invocation binary attestation | The exact binary bytes are hashed (PATH/symlink-hijack defense) | missing/altered binary → blocked |
| Mirror_RTC human consent | Per-action `APPROVE <nonce>`, default-deny | no operator → blocked |
| Mnemosyne audit | Append-only, HMAC hash-chained record of every step | tamper → `chain_valid: false` |

The core invariant: **a DANGER tool never reaches execution without an operator
approving the exact attested binary hash.** Policy alone cannot grant it.

## Architecture

```
 Decepticon swarm (LangGraph agents)
        │  MCP tool call: nmap(target, options)
        ▼
 governed_recon.py        ← drop-in MCP server (replaces Reconnaissance.py)
        │
        ▼
 kki_gov.GovernedKaliBridge
        │  maps tool+params, selects consent strategy
        ▼
 KKI governance.GovernedExecutor   ← imported unmodified from kali-kimi-interface
   validation → policy → scope → attestation → consent → AUDIT → execute
        │
        ▼
 Kali tool (nmap/gobuster/nikto/sqlmap) — runs only if every gate cleared
```

KKI is consumed as a library and **is not modified** — none of its security guarantees are
altered. The integration lives entirely in this repo under `src/kki_gov/` and
`src/tools/mcp/governed_recon.py`.

### Execution model

KKI runs its wrapped tools as local subprocesses, so the governed MCP server must run
**where the Kali binaries live** — e.g. inside the same attacker container Decepticon
already provisions, or on a Kali host. Co-locating governance with execution is what makes
binary attestation meaningful: the bytes hashed and consented to are the bytes that run.

## Consent in an autonomous context

Autonomous agents have no TTY, so KKI's interactive consent prompt would deny everything.
`KKI_CONSENT_MODE` selects how DANGER actions are authorized:

- **`broker`** (default) — out-of-band human approval. When a DANGER action reaches the
  gate, `FileConsentBroker` writes the pending request (tool, target, nonce) to a spool
  directory and waits. The operator approves from any other terminal:

  ```bash
  python -m kki_gov.consent_broker --list
  python -m kki_gov.consent_broker --approve <action_id>
  ```

  The **nonce is never shown to the agent**, so a runaway or prompt-injected agent cannot
  self-authorize — only something with write access to the spool dir (the operator) can.

- **`deny`** — refuse all DANGER actions unattended. The swarm can still do read-only work;
  nothing dangerous runs without a human. Safest default for unattended CI-style runs.

- **`preauth`** — for *authorized*, scoped, unattended runs. Honored only when the operator
  explicitly sets `KKI_SESSION_AUTHORIZED=1`, accepting responsibility for the engagement.
  Even then, **every other gate still applies** (allowlist, scope, attestation, audit) —
  "pre-authorized" is not "ungoverned".

## Setup

1. Check out `kali-kimi-interface` next to this repo (or set `KKI_PATH`).
2. Copy and edit env: `cp .env.example .env` — set at least `KKI_NETWORK_SCOPE`.
3. Start the governed recon server **in place of** `Reconnaissance.py`, on the same port:

   ```bash
   KKI_NETWORK_SCOPE=192.168.56.0/24 KKI_CONSENT_MODE=broker \
     python src/tools/mcp/governed_recon.py        # serves :3001, drop-in for stock recon
   ```

4. Point Decepticon at it. The stock `mcp_config.json` recon URL (`http://localhost:3001/mcp`)
   is unchanged, so no config edit is required; `mcp_config.governed.json` is provided as an
   explicit reference.

## Try it without Kali installed

The demo runs real proposals through the real governance engine and prints each decision
plus the audit state. Where a binary is absent the DANGER gate fails closed at attestation
(a correct outcome); the injection, scope, and flag-allowlist refusals hold everywhere:

```bash
KKI_PATH=../kali-kimi-interface python examples/governed_kki_demo.py
```

Deterministic tests of the gate behavior (allow-with-consent, injection block, scope block,
default-deny, unknown-tool refusal) run with no Kali present:

```bash
KKI_PATH=../kali-kimi-interface python -m kki_gov.selftest
```

## Files

| Path | Role |
|------|------|
| `src/kki_gov/kki_bridge.py` | Locates KKI, maps Decepticon tool calls to governed KKI calls, selects consent strategy |
| `src/kki_gov/consent_broker.py` | Out-of-band file-based human consent + operator CLI |
| `src/tools/mcp/governed_recon.py` | Governed drop-in MCP server (replaces `Reconnaissance.py`) |
| `mcp_config.governed.json` | Reference config wiring agents to the governed server |
| `examples/governed_kki_demo.py` | End-to-end demonstration against the real engine |
| `src/kki_gov/selftest.py` | Deterministic governance-behavior tests (no Kali needed) |

## Scope & limitations (PoC)

- Governs the **KKI-wrapped tools** (nmap, gobuster, nikto, sqlmap, masscan). The stock
  `terminal.py` arbitrary-`command_exec` surface is intentionally **not** bridged — gating
  free-form shell needs a policy model of its own and is the obvious next step.
- Attestation is fully meaningful only when the server is co-located with the tools (see
  Execution model). Running it remote from the binaries weakens that one gate; the others
  are transport-independent.
- This is authorized-testing tooling. Set `KKI_NETWORK_SCOPE` to the engagement's CIDRs and
  keep an operator on the consent broker for any DANGER action.
