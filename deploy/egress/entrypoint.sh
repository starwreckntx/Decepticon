#!/bin/sh
# Egress jail entrypoint for the governance gateway container.
#
# Applies a kernel egress allowlist from KKI_NETWORK_SCOPE (the SAME scope KKI's software gate
# uses) before launching the gateway, then exec's the real command. Default-drop egress: only
# loopback, established/related, DNS, and in-scope CIDRs leave the box. This is the kernel
# backstop — out-of-scope packets are dropped even if a tool call slips the software gate.
#
# EGRESS_ENFORCE: 1 (default) = must apply or refuse to start (fail closed);
#                 warn        = try, continue on failure (logs loudly);
#                 0           = skip (software-only scope; dev).
set -e

MODE="${EGRESS_ENFORCE:-1}"

if [ "$MODE" = "0" ]; then
    echo "[egress] DISABLED (EGRESS_ENFORCE=0) — network scope is SOFTWARE-ONLY" >&2
    exec "$@"
fi

if [ -z "${KKI_NETWORK_SCOPE:-}" ]; then
    echo "[egress] KKI_NETWORK_SCOPE is empty — refusing to apply an open ruleset" >&2
    [ "$MODE" = "warn" ] && exec "$@"
    exit 1
fi

# EGRESS_JIT=1 adds the empty jit_allow set the pre-auth broker grants single destinations
# into per action (requires PREAUTH_JIT_NFT=1 on the gateway to actually populate it).
JIT_FLAG=""
[ "${EGRESS_JIT:-0}" = "1" ] && JIT_FLAG="--jit"

RULES="$(python3 /app/deploy/egress/egress_rules.py \
            --chain "${EGRESS_CHAIN:-output}" --dns "${EGRESS_DNS:-}" $JIT_FLAG --format nft)" || {
    echo "[egress] failed to generate ruleset" >&2
    [ "$MODE" = "warn" ] && exec "$@"
    exit 1
}

if printf '%s\n' "$RULES" | nft -f -; then
    echo "[egress] kernel egress scope applied (default-drop): ${KKI_NETWORK_SCOPE}" >&2
else
    echo "[egress] FAILED to apply nft ruleset (need NET_ADMIN + nftables in this container)" >&2
    [ "$MODE" = "warn" ] && exec "$@"
    exit 1
fi

exec "$@"
