# Preventive Pre-Authorization — stop it before the damage, not after

Every earlier layer either **prevented** a known-bad call (KKI gates, agent strip, egress
jail) or **recorded** what happened (the hash chains, the transparency-log idea). The
transparency log is honest but post-hoc: it proves what occurred *after* it occurred. This
layer closes that gap by **inverting the log into a precondition**: the action cannot execute
until an out-of-process authority has committed the decision and issued a capability for it.

## The inversion

Instead of *execute → log*, the order is **log → grant → execute → revoke**, all on the
critical path before any side effect:

```
agent tool call ─► gateway
   1. WRITE-AHEAD   broker appends the authorization intent to an append-only ledger
                    (the record exists BEFORE anything can act; fail-closed if interrupted)
   2. JIT GRANT     broker opens a narrow, single-destination egress path for THIS action
                    (default state = no access; blast radius = one host, for a few seconds)
   3. TOKEN         broker mints an action-bound, short-TTL, signed capability token
   4. GATE          the executor refuses to run without a valid token for the exact action
   5. EXECUTE       the tool runs (under the open JIT grant)
   6. REVOKE        the JIT grant is torn down on completion/timeout
```

The broker's "yes" is a **gate, not a receipt**. No token ⇒ the process is never spawned.

## What it stops, and the honest line

- **Mis-aligned / prompt-injected agent (common case): fully prevented.** The token is never
  issued (or is bound to a different action / expired), so `executor.enforce` refuses and the
  tool never runs. The bad action doesn't happen — not "happens and is logged".
- **Compromised executor/host (hard case): blast-radius collapse, not prevention.** A
  fully-owned host can ignore the token check — nothing software-only stops that. But the JIT
  egress means it can only reach the *one destination* granted for the *one action*, for a few
  seconds, and only after that grant is on the write-ahead ledger. Standing scope ("anything
  in-scope, anytime") shrinks to "this host, this action, now". The kernel-side `timeout` on
  each grant reaps it even if revoke never runs.

## How it composes with the rest of the chokepoint

Pre-authorization is Stage 3 of the gateway, after agent identity/integrity (Stage 1) and
before/around tool governance + execution (Stage 2). One call now traverses: **session-bound
identity → agent capability → write-ahead + token + JIT → KKI tool governance → execute →
revoke**, recorded across the agent chain, the KKI tool chain, and the pre-auth ledger.

## Action binding (why a token can't be reused)

A token is bound by digest to `tool + agent + args + attested binary + destination + nonce`,
plus the ledger entry (seq, hash) and a TTL. Change any of them and the digest no longer
matches — so a token minted to `nmap 192.168.56.10` can't authorize `sqlmap 8.8.8.8`, can't
be replayed after expiry, and can't be lifted to a different agent.

## Run it (no docker/mcp/LLMs)

```bash
KKI_PATH=../kali-kimi-interface python examples/preauth_demo.py   # or: make preauth-demo
```

Proves: write-ahead ordering (ledger entry precedes the token), token-gated execution
(no/expired/mismatched token ⇒ tool never runs), single-destination JIT lifecycle
(open-on-grant, revoke-on-complete), and the exact nft set commands a grant issues.

## Deploy

Enabled in the governed overlay via `PREAUTH_ENABLE=1` (software token gate + write-ahead).
For kernel JIT grants, also set `EGRESS_JIT=1` (adds the empty `jit_allow` nft set to the
jail) and `PREAUTH_JIT_NFT=1` (the broker adds/removes single destinations in that set, each
with a kernel timeout). Set a stable `PREAUTH_SECRET` so tokens verify across restarts. The
pre-auth ledger persists to `logs/preauth-ledger.json` on shutdown.

| Env | Meaning |
|-----|---------|
| `PREAUTH_ENABLE` | `1` turns on write-ahead + token-gated execution |
| `PREAUTH_TTL` | token lifetime in seconds (shorter = tighter window) |
| `PREAUTH_JIT_NFT` | `1` also opens per-action kernel egress grants (needs `EGRESS_JIT=1`) |
| `PREAUTH_SECRET` | stable HMAC signing key (blank = ephemeral) |
| `PREAUTH_LEDGER_PATH` | where the write-ahead ledger is persisted |

## Honest limits

- HMAC tokens mean a verifier must hold the key; **ed25519** is the production upgrade so a
  third party can verify without it (pairs naturally with the transparency-log idea).
- The broker host is the trust root; distribute it (quorum co-sign) to reduce, can't eliminate.
- JIT only confines a compromised executor if grants are **as narrow as the action**; this
  slice grants single-destination (host) — tighten to host+port where the tool allows.
- A latency round-trip per action and grant/revoke churn — the deliberate "at swarm latency
  cost" trade.

## Files

| Path | Role |
|------|------|
| `src/preauth/tokens.py` | Action-bound, TTL, HMAC-signed capability tokens (mint/verify) |
| `src/preauth/ledger.py` | `WriteAheadLedger` — log-before-execute, hash-chained |
| `src/preauth/jit_egress.py` | Per-action single-destination grants + nft set hooks |
| `src/preauth/broker.py` | `PreAuthBroker` — write-ahead → JIT → token → revoke |
| `src/preauth/executor.py` | `enforce` — token-gated execution (fail closed) |
| `src/governance_gateway/core.py` | Stage-3 pre-auth wired into the chokepoint |
| `examples/preauth_demo.py` | Proves write-ahead, token gate, JIT lifecycle, nft hooks |
