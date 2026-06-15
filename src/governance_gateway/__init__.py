"""
governance_gateway — the single non-bypassable chokepoint for the governed Decepticon swarm.

Every agent's MCP client points at one gateway endpoint; the gateway enforces agent-level
integrity (swarm_integrity.ShadowAuditor) and tool-level governance (kki_gov / KKI) on every
call and records both chains. See ``core.GovernanceGateway`` and ``server`` (FastMCP).
"""
from __future__ import annotations

from .core import GovernanceGateway, TOOL_REQUIRED_CAPABILITY

__all__ = ["GovernanceGateway", "TOOL_REQUIRED_CAPABILITY"]
