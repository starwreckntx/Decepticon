"""
Governed handoff tool — wires the ShadowAuditor into the live langgraph swarm.

Decepticon's stock ``create_handoff_tool`` (src/utils/swarm/handoff.py) transfers control
with a bare ``Command(goto=agent_name)`` — no role check, no audit, no way to stop a
prompt-injected or runaway agent from bouncing control around. This module is a near
drop-in replacement: the governed tool submits every proposed transfer to a process-wide
ShadowAuditor first, and only emits the transfer if the auditor returns ALLOW. On DENY or
STRIP it fails closed — control is routed to the safe fallback (the elected coordinator),
and the offending agent may be quarantined out of the swarm entirely.

This runs on the critical path of every handoff (the deliberate "at swarm latency cost"
trade): integrity is synchronous, not best-effort.

Integration (per agent, e.g. src/agents/swarm/Recon.py):

    from swarm_integrity.handoff_gate import governed_handoff_tools_for
    swarm_tools = governed_handoff_tools_for("Reconnaissance")   # -> 3 governed tools

langgraph is imported lazily, so importing this module (and running the audit core / AV
matrix) does not require langgraph to be installed.
"""
from __future__ import annotations

import os
import threading
from typing import Any, List, Optional

from .constants import ALL_ROLES, ROLE_HANDOFF_GRAPH, SWARM_SEED, VERDICT_ALLOW
from .shadow_auditor import ShadowAuditor

_AUDITOR_LOCK = threading.Lock()
_AUDITOR: Optional[ShadowAuditor] = None


def get_auditor() -> ShadowAuditor:
    """Process-wide ShadowAuditor for the live swarm. Created and coordinator-elected on
    first use so the whole session shares one chain."""
    global _AUDITOR
    with _AUDITOR_LOCK:
        if _AUDITOR is None:
            seed = int(os.environ.get("SWARM_INTEGRITY_SEED", SWARM_SEED))
            _AUDITOR = ShadowAuditor(seed=seed)
            _AUDITOR.open_session(os.environ.get("SWARM_INTEGRITY_LABEL", "live-swarm"))
            _AUDITOR.elect_coordinator()
        return _AUDITOR


def reset_auditor() -> None:
    """Drop the current auditor (e.g. between independent runs/tests)."""
    global _AUDITOR
    with _AUDITOR_LOCK:
        _AUDITOR = None


def export_audit(path: str) -> str:
    """Persist the live agent decision chain to ``path``."""
    import json
    data = get_auditor().trail.export()
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True, default=str)
    return path


def _normalize(name: str) -> str:
    import re
    return re.sub(r"\s+", "_", name.strip()).lower()


def create_governed_handoff_tool(
    *, agent_name: str, source_agent: Optional[str] = None,
    name: Optional[str] = None, description: Optional[str] = None,
):
    """Governed analogue of Decepticon's create_handoff_tool.

    ``agent_name`` is the destination; ``source_agent`` is the agent that owns this tool
    (so the auditor knows who is initiating). If ``source_agent`` is omitted it is read
    from the live state's ``active_agent`` at call time.
    """
    # Lazy import: only needed when actually building live tools.
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import InjectedToolCallId, tool
    from langgraph.prebuilt import InjectedState
    from langgraph.types import Command
    from typing_extensions import Annotated

    if name is None:
        name = f"transfer_to_{_normalize(agent_name)}"
    if description is None:
        description = f"Ask agent '{agent_name}' for help"

    @tool(name, description=description)
    def governed_handoff(
        state: Annotated[dict, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId],
    ):
        src = source_agent or state.get("active_agent") or "unknown"
        auditor = get_auditor()
        verdict = auditor.submit_handoff(src, agent_name)

        if verdict.verdict == VERDICT_ALLOW:
            msg = ToolMessage(
                content=(f"[INTEGRITY ✓] transfer {src} -> {agent_name} authorized "
                         f"(audit {verdict.entry_hash[:12] if verdict.entry_hash else '?'})"),
                name=name, tool_call_id=tool_call_id,
            )
            return Command(
                goto=agent_name, graph=Command.PARENT,
                update={"messages": state["messages"] + [msg], "active_agent": agent_name},
            )

        # DENY or STRIP -> fail closed. Route to the safe fallback, never the requested agent.
        fallback = verdict.fallback or "Planner"
        stripped_note = f"; agent '{verdict.stripped}' STRIPPED" if verdict.stripped else ""
        msg = ToolMessage(
            content=(f"[INTEGRITY ✗ {verdict.verdict}] transfer {src} -> {agent_name} refused: "
                     f"{verdict.reason}{stripped_note}. Control routed to {fallback}."),
            name=name, tool_call_id=tool_call_id,
        )
        return Command(
            goto=fallback, graph=Command.PARENT,
            update={"messages": state["messages"] + [msg], "active_agent": fallback},
        )

    governed_handoff.metadata = {"__handoff_destination": agent_name, "__governed": True}
    return governed_handoff


def governed_handoff_tools_for(source_agent: str) -> List[Any]:
    """Build the governed handoff tools an agent should carry — one per legal destination in
    its role graph. Near drop-in for the per-agent ``swarm_tools`` lists."""
    if source_agent not in ROLE_HANDOFF_GRAPH:
        raise ValueError(f"unknown agent/role {source_agent!r}; valid: {ALL_ROLES}")
    return [
        create_governed_handoff_tool(agent_name=dest, source_agent=source_agent)
        for dest in sorted(ROLE_HANDOFF_GRAPH[source_agent])
    ]
