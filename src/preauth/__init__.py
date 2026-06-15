"""
preauth — preventive pre-authorization for the governance gateway.

Inverts "execute then log" into "authorize before, with capability on demand":
  * WriteAheadLedger  — record the authorization BEFORE anything can act (log-before-execute)
  * PreAuthBroker     — commit, open a just-in-time per-action egress grant, mint an
                        action-bound short-TTL token, revoke on completion
  * JitEgress         — narrow, single-destination, auto-revoked network capability
  * executor.enforce  — refuse to run without a valid token for the exact action

Stops the bad action before damage for the agent threat (no token / no capability -> no
process), and collapses the blast radius to one destination for a few seconds for the host
threat. Stdlib-only; designed to run as a separate authority service.
"""
from __future__ import annotations

from .broker import PreAuthBroker, Grant
from .ledger import WriteAheadLedger
from .jit_egress import JitEgress, narrow_nft_rule
from .tokens import CapabilityToken, mint, verify, action_digest, args_digest
from .executor import enforce, ExecutionDenied

__all__ = [
    "PreAuthBroker", "Grant", "WriteAheadLedger", "JitEgress", "narrow_nft_rule",
    "CapabilityToken", "mint", "verify", "action_digest", "args_digest",
    "enforce", "ExecutionDenied",
]
