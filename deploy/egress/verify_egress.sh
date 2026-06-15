#!/bin/sh
# Verify the egress jail from INSIDE the gateway container.
#
#   docker exec governance_gateway /app/deploy/egress/verify_egress.sh <out_of_scope_host> [port] [in_scope_host]
#
# Asserts: the kki_egress table is loaded; a connection to an OUT-OF-SCOPE host is dropped
# (times out); and, if given, an IN-SCOPE host is permitted. Exit 0 = jail holds, 1 = leak.
OUT="${1:?usage: verify_egress.sh <out_of_scope_host> [port] [in_scope_host]}"
PORT="${2:-80}"
IN="${3:-}"
RC=0

echo "== loaded ruleset =="
nft list table inet kki_egress 2>/dev/null || { echo "FAIL: kki_egress table not loaded"; exit 1; }

echo "\n== out-of-scope $OUT:$PORT (expect BLOCKED) =="
if nc -z -w 3 "$OUT" "$PORT" 2>/dev/null; then
    echo "FAIL: reached out-of-scope $OUT:$PORT — egress jail is LEAKING"
    RC=1
else
    echo "OK: out-of-scope $OUT:$PORT was blocked (dropped/timed out)"
fi

if [ -n "$IN" ]; then
    echo "\n== in-scope $IN:$PORT (expect REACHABLE if a listener exists) =="
    if nc -z -w 3 "$IN" "$PORT" 2>/dev/null; then
        echo "OK: in-scope $IN:$PORT reachable"
    else
        echo "NOTE: in-scope $IN:$PORT not reachable (no listener, or target down) — not a jail failure"
    fi
fi

[ "$RC" = 0 ] && echo "\nEGRESS JAIL OK" || echo "\nEGRESS JAIL LEAKING"
exit $RC
