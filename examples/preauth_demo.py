#!/usr/bin/env python3
"""
Preventive pre-authorization demo/test — stop it before the damage, not after.

Proves the three load-bearing properties against the real engines (no mcp/langgraph/docker):
  1. write-ahead: the authorization is on the ledger BEFORE the token exists;
  2. token-gated execution: no / expired / mismatched token -> the action is refused and
     the tool is never executed (fail closed);
  3. just-in-time egress: a grant opens exactly ONE narrow destination rule and revokes it on
     completion — default is no access, blast radius is the single authorized action.

Asserts throughout; exits nonzero on any failure.

Run:  KKI_PATH=../kali-kimi-interface python examples/preauth_demo.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from preauth import (
    PreAuthBroker, WriteAheadLedger, JitEgress, mint, verify, enforce, ExecutionDenied,
    action_digest,
)
from governance_gateway.core import GovernanceGateway
from swarm_integrity.handoff_gate import get_auditor, reset_auditor


SECRET = b"poc-broker-secret"
ACTION = {"tool": "sqlmap_scan", "agent": "Initial_Access", "args_digest": "abc",
          "binary_sha256": "", "dst": "192.168.56.10", "dst_ip": "192.168.56.10", "dport": 80}


def part_tokens():
    led = WriteAheadLedger()
    seq, h = led.append({"event": "authorize", "action_digest": action_digest(ACTION)})
    tok = mint(SECRET, ACTION, ttl=10, ledger_seq=seq, ledger_hash=h)
    assert verify(SECRET, tok, ACTION)[0], "fresh token must verify"
    # tampered action -> mismatch
    other = dict(ACTION, dst="8.8.8.8", dst_ip="8.8.8.8")
    assert verify(SECRET, tok, other) == (False, "action mismatch: token is bound to a different action")
    # expired
    old = mint(SECRET, ACTION, ttl=-1, ledger_seq=seq, ledger_hash=h)
    assert verify(SECRET, old, ACTION)[0] is False
    # none
    assert verify(SECRET, None, ACTION)[0] is False
    print("PASS tokens: fresh verifies; tampered/expired/none all fail closed")


def part_write_ahead():
    led = WriteAheadLedger()
    broker = PreAuthBroker(SECRET, ledger=led, jit=JitEgress())
    n_before = len(led.entries)
    grant = broker.authorize(ACTION)
    # The authorization entry exists, and the token is bound to that exact ledger entry.
    assert len(led.entries) == n_before + 1, "ledger must be written before the token is returned"
    assert grant.token.ledger_seq == led.entries[-1]["seq"], "token must bind the ledger entry"
    assert grant.token.ledger_hash == led.entries[-1]["hash"]
    assert led.verify()[0], "ledger chain must verify"
    print("PASS write-ahead: authorization committed to the ledger BEFORE the token is issued")


def part_jit_lifecycle():
    applied, revoked = [], []
    jit = JitEgress(apply_fn=applied.append, revoke_fn=revoked.append)
    broker = PreAuthBroker(SECRET, jit=jit)
    grant = broker.authorize(ACTION)
    assert len(jit.active) == 1, "exactly one grant active during the action"
    rule = next(iter(jit.active.values()))
    assert "192.168.56.10" in rule and "192.168.56.0/24" not in rule, \
        f"JIT rule must be the single destination, not the whole scope: {rule}"
    broker.complete(grant)
    assert jit.active == {}, "grant must be revoked on completion (default = no access)"
    assert len(applied) == 1 and len(revoked) == 1
    print(f"PASS JIT: opened ONE narrow rule for the action, revoked on completion ({rule!r})")


def part_nft_hooks():
    # The deployment hooks add/remove single destinations in the jail's dynamic jit_allow set,
    # each with a kernel-side timeout. Verify the exact nft commands with a fake runner.
    from preauth.jit_egress import nft_set_hooks
    calls = []
    apply_fn, revoke_fn = nft_set_hooks(ttl=7, runner=lambda args: calls.append(args))
    jit = JitEgress(apply_fn=apply_fn, revoke_fn=revoke_fn)
    broker = PreAuthBroker(SECRET, jit=jit)
    g = broker.authorize(ACTION)
    broker.complete(g)
    add = next(c for c in calls if c[1] == "add")
    dele = next(c for c in calls if c[1] == "delete")
    assert add[:6] == ["nft", "add", "element", "inet", "kki_egress", "jit_allow"], add
    assert "192.168.56.10 timeout 7s" in add[-1], add
    assert "192.168.56.10" in dele[-1], dele
    print("PASS nft hooks: grant adds a single-dst element with timeout; complete deletes it")


def part_gateway_end_to_end():
    reset_auditor(); get_auditor().elect_coordinator()
    applied, revoked = [], []
    jit = JitEgress(apply_fn=applied.append, revoke_fn=revoked.append)

    # Authorized path: preauth grants, JIT opens for the scan, then is revoked.
    gw = GovernanceGateway(network_scope=["192.168.56.0/24"], consent_mode="deny",
                           preauth=PreAuthBroker(SECRET, jit=jit, default_ttl=10))
    env = gw.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                      agent="Initial_Access", identity_source="token")
    assert env["preauth"]["granted"] is True, env
    assert env["denied_stage"] != "preauth", f"valid token must PASS the preauth gate: {env}"
    assert jit.active == {}, "JIT must be revoked after the call (open only during execution)"
    assert len(applied) == 1 and len(revoked) == 1, "exactly one grant opened and revoked"
    # (tool stage may still block at attestation in this bare container — that's fine; the
    #  point is preauth granted, the token gate PASSED, the record preceded the act, and the
    #  capability was opened only for the call and revoked.)
    print(f"PASS gateway: preauth granted + token gate PASSED; JIT opened for the call and "
          f"revoked after (tool stage: {env.get('denied_stage') or 'allowed'})")

    # Token-gated denial: a broker that mints already-expired tokens -> execution refused at
    # the preauth stage; the tool is NEVER reached (tool_governance stays None).
    jit2_applied, jit2_revoked = [], []
    jit2 = JitEgress(apply_fn=jit2_applied.append, revoke_fn=jit2_revoked.append)
    gw2 = GovernanceGateway(network_scope=["192.168.56.0/24"], consent_mode="deny",
                            preauth=PreAuthBroker(SECRET, jit=jit2, default_ttl=-1))
    env2 = gw2.dispatch("sqlmap_scan", {"url": "http://192.168.56.10/", "target": "192.168.56.10"},
                        agent="Initial_Access", identity_source="token")
    assert env2["denied_stage"] == "preauth", env2
    assert "expired" in env2["denial_reason"], f"expected expiry refusal, got {env2['denial_reason']}"
    assert env2["tool_governance"] is None, "tool must not be reached without a valid token"
    assert env2["result"] is None
    assert jit2.active == {}, "JIT revoked even on the denied path"
    print(f"PASS gateway: expired token -> blocked@preauth, tool NEVER executed "
          f"({env2['denial_reason']})")


def main() -> int:
    part_tokens()
    part_write_ahead()
    part_jit_lifecycle()
    part_nft_hooks()
    part_gateway_end_to_end()
    print("\nAll preventive pre-authorization checks passed — the record precedes the act, "
          "execution is\ngated on an action-bound token, and the network capability is "
          "per-action and auto-revoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
