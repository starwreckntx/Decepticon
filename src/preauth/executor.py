"""
Token-gated execution.

The point where "stop it before damage" is enforced: the executor refuses to run unless it
is handed a valid, fresh, matching capability token for the exact action it is about to
perform. No token, an expired token, or a token bound to a different action -> the process is
never spawned. This is what makes the broker's decision a gate rather than a receipt.
"""
from __future__ import annotations

from typing import Any, Dict

from .tokens import CapabilityToken, verify


class ExecutionDenied(Exception):
    """Raised when an action is attempted without a valid capability token."""


def enforce(secret: bytes, token: CapabilityToken, action: Dict[str, Any],
            now: float = None) -> None:
    """Raise ExecutionDenied unless ``token`` authorizes ``action`` right now. Fail closed."""
    ok, reason = verify(secret, token, action, now=now)
    if not ok:
        raise ExecutionDenied(f"execution refused: {reason}")
