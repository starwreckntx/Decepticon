"""
Just-in-time per-action egress capability.

Inverts the standing scope allowlist: default state is that the executor can reach *nothing*;
the broker opens a NARROW path (single destination, optional port) for exactly one action,
and revokes it the instant the action completes or times out. The window of possible damage
collapses from "anything in scope, anytime" to "exactly this destination, for this action,
for a few seconds".

The apply/revoke hooks are pluggable: in deployment they shell out to nftables (one rule per
grant in the kki_jit chain); in tests a recorder captures the rule lifecycle. Generation and
lifecycle are pure and testable; only the apply/revoke side effects need the host.
"""
from __future__ import annotations

import ipaddress
from typing import Callable, Dict, Optional


def narrow_nft_rule(dst: str, dport: Optional[int], proto: str, action_id: str) -> str:
    """A single-destination accept rule. dst may be an IP/CIDR; a hostname is passed through
    (the deployment resolves/handles it). Far narrower than the engagement-wide scope set."""
    fam = "ip"
    try:
        fam = "ip6" if ipaddress.ip_address(dst.split("/")[0]).version == 6 else "ip"
    except ValueError:
        fam = "ip"  # hostname; let the applier resolve
    rule = f"{fam} daddr {dst}"
    if dport:
        rule += f" {proto} dport {dport}"
    return rule + f' accept comment "jit:{action_id}"'


class JitEgress:
    """Tracks active per-action grants and drives apply/revoke side effects."""

    def __init__(self, apply_fn: Optional[Callable[[str], None]] = None,
                 revoke_fn: Optional[Callable[[str], None]] = None):
        self._apply = apply_fn
        self._revoke = revoke_fn
        self._active: Dict[str, str] = {}

    def grant(self, action_id: str, dst: str, dport: Optional[int] = None,
              proto: str = "tcp") -> str:
        rule = narrow_nft_rule(dst, dport, proto, action_id)
        if self._apply:
            self._apply(rule)
        self._active[action_id] = rule
        return rule

    def revoke(self, action_id: str) -> Optional[str]:
        rule = self._active.pop(action_id, None)
        if rule and self._revoke:
            self._revoke(rule)
        return rule

    def revoke_all(self) -> None:
        for action_id in list(self._active):
            self.revoke(action_id)

    @property
    def active(self) -> Dict[str, str]:
        return dict(self._active)


def _daddr(rule: str) -> str:
    """Extract the destination address from a generated narrow rule ('... daddr <ip> ...')."""
    return rule.split("daddr", 1)[1].split()[0]


def nft_set_hooks(table: str = "kki_egress", set_name: str = "jit_allow",
                  ttl: int = 10, runner=None):
    """Apply/revoke hooks that add/remove single destinations in the jail's dynamic ``jit_allow``
    nft set (created by ``egress_rules.py --jit``). Each grant carries a kernel-side ``timeout``
    so it auto-expires even if revoke never runs — defense in depth around the broker's revoke.

    ``runner`` is injectable for tests; defaults to subprocess. Apply failures propagate (fail
    closed: a grant that can't be installed must not be treated as open); revoke failures are
    swallowed (best-effort teardown; the timeout still reaps it)."""
    import subprocess
    run = runner or (lambda args: subprocess.run(args, check=True))

    def apply(rule: str) -> None:
        ip = _daddr(rule)
        run(["nft", "add", "element", "inet", table, set_name, "{ %s timeout %ds }" % (ip, ttl)])

    def revoke(rule: str) -> None:
        ip = _daddr(rule)
        try:
            run(["nft", "delete", "element", "inet", table, set_name, "{ %s }" % ip])
        except Exception:
            pass

    return apply, revoke
