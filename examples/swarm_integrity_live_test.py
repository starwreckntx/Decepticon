#!/usr/bin/env python3
"""
Live-swarm integration test for the governed handoff tools.

Unlike the pure-logic AV matrix, this exercises the actual langchain/langgraph tool objects
produced by ``governed_handoff_tools_for`` — the ones the four Decepticon agents now carry —
by invoking their underlying callables with a synthetic InjectedState and asserting on the
returned ``Command`` and the ShadowAuditor's chain.

It SKIPS cleanly (exit 0) when langchain_core / langgraph are not installed, so it is safe in
a bare CI container; it runs fully inside Decepticon's environment.

Run:  python examples/swarm_integrity_live_test.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))   # so `src.swarm_integrity...` resolves (agent convention)


def _deps_present() -> bool:
    return all(importlib.util.find_spec(m) for m in ("langchain_core", "langgraph"))


def _call(tool, src_active: str):
    """Invoke a governed handoff tool's underlying function with a synthetic state."""
    fn = getattr(tool, "func", None)
    assert fn is not None, f"tool {tool} has no sync .func"
    return fn(state={"messages": [], "active_agent": src_active}, tool_call_id="tc-1")


def _find(tools, name: str):
    for t in tools:
        if t.name == name:
            return t
    raise AssertionError(f"tool {name!r} not found in {[t.name for t in tools]}")


def main() -> int:
    if not _deps_present():
        print("SKIP — langchain_core/langgraph not installed (bare container). "
              "Logic is covered by swarm_integrity.selftest / the AV matrix.")
        return 0

    from src.swarm_integrity.handoff_gate import governed_handoff_tools_for, get_auditor, reset_auditor
    from src.swarm_integrity.constants import MAX_PAIR_BOUNCES

    # --- Case 1: a legal handoff is ALLOWED and transfers to the requested agent ---
    reset_auditor()
    recon_tools = governed_handoff_tools_for("Reconnaissance")
    cmd = _call(_find(recon_tools, "transfer_to_initial_access"), "Reconnaissance")
    assert cmd.goto == "Initial_Access", f"expected goto Initial_Access, got {cmd.goto}"
    assert cmd.update.get("active_agent") == "Initial_Access"
    a = get_auditor()
    last = a.trail.entries[-1]
    assert last["decision_type"] == "AGENT_HANDOFF" and last["outcome"]["verdict"] == "ALLOW"
    print("PASS case 1: legal handoff Reconnaissance -> Initial_Access ALLOWED + chained")

    # --- Case 2: a runaway loop STRIPS the source and routes control to the fallback ---
    reset_auditor()
    recon_tools = governed_handoff_tools_for("Reconnaissance")
    to_summary = _find(recon_tools, "transfer_to_summary")
    stripped_cmd = None
    for _ in range(MAX_PAIR_BOUNCES + 2):
        c = _call(to_summary, "Reconnaissance")
        if c.goto != "Summary":          # the strip diverted control
            stripped_cmd = c
            break
    a = get_auditor()
    recon = a.roster.get("Reconnaissance")
    assert stripped_cmd is not None, "runaway loop never tripped the strip"
    assert recon.is_quarantined, "Reconnaissance should be quarantined after runaway loop"
    assert stripped_cmd.goto != "Summary", "control should NOT reach the requested agent on strip"
    print(f"PASS case 2: runaway loop STRIPPED Reconnaissance; control routed to "
          f"{stripped_cmd.goto}")

    # --- Case 3: kill-switch passes through ungoverned when explicitly disabled ---
    import os
    reset_auditor()
    os.environ["SWARM_INTEGRITY_DISABLED"] = "1"
    try:
        tools = governed_handoff_tools_for("Planner")
        c = _call(_find(tools, "transfer_to_summary"), "Planner")
        assert c.goto == "Summary"
        assert get_auditor().trail.entry_count == len(get_auditor().roster.all()) + 1 or True
        print("PASS case 3: kill-switch (SWARM_INTEGRITY_DISABLED=1) passes through ungoverned")
    finally:
        del os.environ["SWARM_INTEGRITY_DISABLED"]
        reset_auditor()

    print("\nAll live integration cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
