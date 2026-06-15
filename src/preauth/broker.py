"""
PreAuthBroker — the out-of-process authority that turns "log after" into "authorize before".

For each action the broker, in order:
    1. WRITE-AHEAD: append the authorization intent to the ledger (record before capability).
    2. OPEN a just-in-time, single-destination egress grant for exactly this action.
    3. MINT an action-bound, short-TTL capability token (only after the ledger commit).
and on completion REVOKES the JIT grant and records the close. Execution is gated on the
token (see executor.enforce), so without the broker's signed yes nothing runs — and the
durable record always precedes the act.

The broker assumes the policy gates (agent integrity, KKI tool governance) have already
passed; it is the commit+capability+token authority, not a second policy engine. Designed to
run as a separate service (its own keypair/trust boundary); used in-process here for the PoC.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .ledger import WriteAheadLedger
from .jit_egress import JitEgress
from .tokens import CapabilityToken, action_digest, mint


@dataclass
class Grant:
    allowed: bool
    action_id: str
    ledger_seq: int
    ledger_hash: str
    dst: Optional[str]
    expires_at: float
    token: Optional[CapabilityToken] = None
    reason: str = "ok"

    def to_envelope(self) -> Dict[str, Any]:
        return {
            "granted": self.allowed, "action_id": self.action_id,
            "ledger_seq": self.ledger_seq, "dst": self.dst,
            "expires_at": self.expires_at, "reason": self.reason,
            "token_bound": bool(self.token),
        }


class PreAuthBroker:
    def __init__(self, secret: bytes, ledger: Optional[WriteAheadLedger] = None,
                 jit: Optional[JitEgress] = None, default_ttl: float = 10.0):
        if not secret:
            raise ValueError("PreAuthBroker requires a non-empty signing secret")
        self.secret = secret
        self.ledger = ledger or WriteAheadLedger()
        self.jit = jit or JitEgress()
        self.default_ttl = default_ttl

    def authorize(self, action: Dict[str, Any], ttl: Optional[float] = None,
                  now: float = None) -> Grant:
        """Write-ahead, open the JIT path, then mint the token. Order matters: the record is
        committed BEFORE any capability or token exists (fail-closed if interrupted)."""
        now = time.time() if now is None else now
        ttl = self.default_ttl if ttl is None else ttl
        action_id = action.get("nonce") or secrets.token_hex(8)

        # 1. WRITE-AHEAD COMMIT — before anything can act.
        seq, h = self.ledger.append({
            "event": "authorize", "action_id": action_id,
            "action_digest": action_digest(action),
            "tool": action.get("tool"), "agent": action.get("agent"),
            "dst": action.get("dst"), "issued_at": now, "ttl": ttl,
        })

        # 2. OPEN the just-in-time, single-destination capability.
        dst_ip = action.get("dst_ip") or action.get("dst")
        if dst_ip:
            self.jit.grant(action_id, dst_ip, action.get("dport"))

        # 3. MINT the action-bound token AFTER the commit.
        token = mint(self.secret, {**action, "nonce": action_id}, ttl, seq, h, now=now)
        return Grant(allowed=True, action_id=action_id, ledger_seq=seq, ledger_hash=h,
                     dst=action.get("dst"), expires_at=token.expires_at, token=token)

    def complete(self, grant: Grant, now: float = None) -> None:
        """Revoke the JIT grant and record the close. Always called (finally) after exec."""
        if grant is None:
            return
        self.jit.revoke(grant.action_id)
        self.ledger.append({
            "event": "complete", "action_id": grant.action_id,
            "ledger_seq": grant.ledger_seq, "at": time.time() if now is None else now,
        })
