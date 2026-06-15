"""
Action-bound capability tokens for pre-authorization.

A token is the broker's signed "yes" for ONE specific action. It is bound to the exact
action (tool + agent + args + attested binary + destination + nonce), to the write-ahead
ledger entry that recorded the authorization, and to a short TTL. The executor refuses to
run unless it is handed a token that verifies against the action it is about to perform —
so the authority's decision is a *gate*, not a receipt, and it cannot be replayed for a
different action or after it expires.

HMAC-signed for the PoC (the broker holds the key). Asymmetric (ed25519) is the production
upgrade so a verifier need not hold the signing key — see docs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Tuple

# The fields that BIND a token to an action. A token minted for one of these is useless for
# any other — change the target, the tool, the binary, or the agent and the digest changes.
_BINDING_KEYS = ("tool", "agent", "args_digest", "binary_sha256", "dst", "nonce")


def args_digest(params: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()


def action_digest(action: Dict[str, Any]) -> str:
    canon = {k: action.get(k) for k in _BINDING_KEYS}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class CapabilityToken:
    action_digest: str
    ledger_seq: int
    ledger_hash: str
    issued_at: float
    expires_at: float
    nonce: str
    sig: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _sign(secret: bytes, payload: Dict[str, Any]) -> str:
    msg = json.dumps(payload, sort_keys=True, default=str).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def mint(secret: bytes, action: Dict[str, Any], ttl: float,
         ledger_seq: int, ledger_hash: str, now: float = None) -> CapabilityToken:
    """Issue a token for ``action``, bound to the write-ahead ledger entry (seq, hash) that
    recorded its authorization. Call this ONLY after the ledger append has committed."""
    now = time.time() if now is None else now
    nonce = action.get("nonce") or secrets.token_hex(8)
    payload = {
        "action_digest": action_digest(action),
        "ledger_seq": ledger_seq,
        "ledger_hash": ledger_hash,
        "issued_at": now,
        "expires_at": now + ttl,
        "nonce": nonce,
    }
    return CapabilityToken(sig=_sign(secret, payload), **payload)


def verify(secret: bytes, token: CapabilityToken, action: Dict[str, Any],
           now: float = None) -> Tuple[bool, str]:
    """Return (ok, reason). Checks signature, action binding, and expiry — fail closed."""
    if token is None:
        return False, "no token"
    now = time.time() if now is None else now
    payload = {k: getattr(token, k) for k in
               ("action_digest", "ledger_seq", "ledger_hash", "issued_at", "expires_at", "nonce")}
    if not hmac.compare_digest(_sign(secret, payload), token.sig):
        return False, "bad signature"
    if action_digest(action) != token.action_digest:
        return False, "action mismatch: token is bound to a different action"
    if now > token.expires_at:
        return False, "expired"
    return True, "ok"
