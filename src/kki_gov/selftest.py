#!/usr/bin/env python3
"""
Deterministic tests for the Decepticon -> KKI governance bridge.

These exercise the full governance gate WITHOUT needing Kali binaries installed, by
injecting a permissive fake registry (so attestation passes) and a fake executor (so a
"cleared" call returns a canned result instead of running a real scan). What is being
tested is the *governance behavior* the bridge relies on:

    * a clean, in-scope DANGER call is allowed only after consent is granted
    * command injection in the target is refused at the policy layer
    * an out-of-scope target is refused at the network-scope layer
    * a denied / absent consent decision blocks execution (default-deny)
    * an unknown tool is refused before reaching the executor

Run:  python -m kki_gov.selftest     (or: python src/kki_gov/selftest.py)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]   # .../Decepticon/src
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from kki_gov.kki_bridge import _locate_kki  # noqa: E402

# Put KKI's own ``src`` on the path up front so the test can patch its attestation module
# before any bridge is built (the bridge only adds it during construction).
_KKI_SRC = _locate_kki()
if str(_KKI_SRC) not in sys.path:
    sys.path.insert(0, str(_KKI_SRC))

from kki_gov.kki_bridge import GovernedKaliBridge  # noqa: E402


# --- test doubles --------------------------------------------------------------------

class _FakeSpec:
    required_permission = "danger-full-access"


class _FakeExecutor:
    """Stands in for KKI's SecurityToolExecutor: records calls, returns a canned result."""
    def __init__(self):
        self.calls = []

    def get_tool_spec(self, name):
        return _FakeSpec()

    def execute(self, tool_name, params):
        self.calls.append((tool_name, params))
        return {"success": True, "returncode": 0, "output": f"ran {tool_name} {params}"}


class _FakeTV:
    """A registry record whose binary is 'present' and attests cleanly."""
    def __init__(self, binary):
        self.binary = binary
        self.binary_path = f"/usr/bin/{binary}"
        self.permission = "danger-full-access"
        self.expected_sha256 = None
        self.sha256 = None
        self.boot_status = "ok"


class _FakeRegistry:
    manifest_mode = False
    require_signed = False
    root_of_trust = "tofu"

    def get(self, binary):
        return _FakeTV(binary)


def _bridge(consent_prompt, scope=("192.168.56.0/24",)):
    # attest_binary is the one real-world dependency we must neutralize for hermetic tests:
    # patch it in the imported governance.attestation so the fake binary "verifies".
    import governance.attestation as att

    class _Att:
        verified = True
        reason = "ok"
        sha256 = "deadbeef" * 8
        def to_dict(self):
            return {"verified": True, "sha256": self.sha256, "reason": "ok"}

    att.attest_binary = lambda *a, **k: _Att()  # type: ignore

    # pin_binary is used on the enforced (danger/write) path; make it a no-op context.
    import contextlib

    class _Pinned:
        attestation = _Att()
        pinned = True
        def recheck(self):
            return True

    @contextlib.contextmanager
    def _pin(*a, **k):
        yield _Pinned()

    @contextlib.contextmanager
    def _active(*a, **k):
        yield

    att.pin_binary = _pin           # type: ignore
    att.active_pin = _active        # type: ignore

    # engine.py imported these names at module load, so patch them there too.
    import governance.engine as eng
    eng.attest_binary = att.attest_binary  # type: ignore
    eng.pin_binary = _pin                   # type: ignore
    eng.active_pin = _active                # type: ignore

    return GovernedKaliBridge(
        network_scope=list(scope),
        consent_prompt=consent_prompt,
        executor=_FakeExecutor(),
        registry=_FakeRegistry(),
    )


# --- approve / deny prompt helpers ---------------------------------------------------

def _approve(req):
    return f"APPROVE {req.nonce}"


def _deny(_req):
    return None


# --- tests ---------------------------------------------------------------------------

def test_clean_inscope_call_allowed_with_consent():
    bridge = _bridge(_approve)
    out = bridge.nmap("192.168.56.101", options="-sS -p 1-1000")
    assert out["allowed"] is True, out
    assert out["result"]["success"] is True
    assert out["audit_seq"], "expected audit entries"
    print("PASS clean in-scope call allowed with consent")


def test_injection_blocked_at_policy():
    bridge = _bridge(_approve)
    out = bridge.nmap("192.168.56.101; rm -rf /", options="-sS")
    assert out["allowed"] is False
    assert "policy_violation" in (out["denial_reason"] or "")
    print("PASS command injection blocked at policy")


def test_out_of_scope_blocked():
    bridge = _bridge(_approve)
    out = bridge.nmap("8.8.8.8", options="-sS")
    assert out["allowed"] is False
    assert "scope" in (out["denial_reason"] or "").lower()
    print("PASS out-of-scope target blocked")


def test_no_consent_blocks_execution():
    bridge = _bridge(_deny)
    out = bridge.nmap("192.168.56.101", options="-sS")
    assert out["allowed"] is False
    assert out["result"] is None
    print("PASS default-deny: missing consent blocks execution")


def test_unknown_tool_refused():
    bridge = _bridge(_approve)
    out = bridge.scan("metasploit", {"target": "192.168.56.101"})
    assert out["allowed"] is False
    assert "not governed" in (out["denial_reason"] or "")
    print("PASS unknown/ungoverned tool refused")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} governance bridge tests passed.")


if __name__ == "__main__":
    _run_all()
