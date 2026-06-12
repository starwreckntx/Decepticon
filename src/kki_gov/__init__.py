#!/usr/bin/env python3
"""
Decepticon governance integration.

Wraps Decepticon's autonomous red-team tool calls in the Kali Kimi Interface (KKI) IRP
governance layer — positive allowlist validation, permission-as-code policy, network-scope
enforcement, per-invocation binary attestation, human consent (Mirror_RTC), and an
append-only HMAC hash-chained audit trail — so a self-driving offensive swarm cannot run
an unvalidated, out-of-scope, or unattended-dangerous action "in the wild".

KKI is consumed unmodified; see ``kki_bridge.GovernedKaliBridge`` and the governed MCP
server in ``src/tools/mcp/governed_recon.py``.
"""

from __future__ import annotations

from .kki_bridge import GovernedKaliBridge, TOOL_ALIASES

__all__ = ["GovernedKaliBridge", "TOOL_ALIASES"]
