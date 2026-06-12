#!/usr/bin/env python3
"""
FileConsentBroker — an out-of-band, human-in-the-loop consent channel for governing an
autonomous Decepticon swarm "in the wild".

The problem: KKI's Mirror_RTC gate authorizes DANGER actions via an interactive stdin
prompt. An MCP server driven by autonomous agents has no TTY, so the stock prompt would
resolve to NO_OPERATOR (deny) every time — safe, but it means nothing dangerous can ever
run, even when an operator IS watching and wants to approve a specific action.

This broker gives the operator a real approval surface without putting them on the agent's
stdin. When a DANGER action reaches the gate, the broker:

  1. writes the pending request (tool, target, blast radius, nonce) to
     ``<dir>/pending/<action_id>.json`` and prints a one-line banner to stderr, then
  2. polls ``<dir>/responses/<action_id>`` until the operator writes ``APPROVE <nonce>``
     (or ``DENY``), or the timeout elapses (default-deny on timeout).

An operator approves from any other terminal / tool / web hook by dropping the response
file — e.g. via the bundled CLI:

    python -m kki_gov.consent_broker --list
    python -m kki_gov.consent_broker --approve <action_id>
    python -m kki_gov.consent_broker --deny <action_id>

The nonce is never shown to the agent and is required to approve, so a compromised or
runaway agent cannot self-authorize: only something with write access to the broker
directory (the operator) can.

Usage (as a KKI consent prompt_fn):
    from kki_gov.consent_broker import FileConsentBroker
    broker = FileConsentBroker(timeout=120)
    gate = ConsentGate(prompt_fn=broker.prompt, timeout=120)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _default_dir() -> Path:
    return Path(os.environ.get("KKI_CONSENT_DIR", "/tmp/kki-consent"))


class FileConsentBroker:
    def __init__(self, base_dir: Optional[str] = None, timeout: float = 120.0,
                 poll_interval: float = 0.5):
        self.base = Path(base_dir) if base_dir else _default_dir()
        self.pending_dir = self.base / "pending"
        self.responses_dir = self.base / "responses"
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.responses_dir.mkdir(parents=True, exist_ok=True)

    # -- the prompt_fn KKI's ConsentGate calls ----------------------------------------

    def prompt(self, req) -> Optional[str]:
        """Publish the request, wait for an out-of-band operator response, return the raw
        line ("APPROVE <nonce>" / "DENY") or None on timeout (which the gate denies)."""
        record = {
            "action_id": req.action_id,
            "tool": req.tool,
            "target": req.target,
            "blast_radius": req.blast_radius,
            "nonce": req.nonce,
            "est_impact": req.est_impact,
            "created_at": req.created_at,
            "expires_in_s": self.timeout,
        }
        pending_path = self.pending_dir / f"{req.action_id}.json"
        pending_path.write_text(json.dumps(record, indent=2))
        response_path = self.responses_dir / req.action_id

        sys.stderr.write(
            f"\n[Mirror_RTC] CONSENT REQUIRED action={req.action_id} "
            f"tool={req.tool} target={req.target} radius={req.blast_radius}\n"
            f"             approve: python -m kki_gov.consent_broker "
            f"--approve {req.action_id}\n"
        )
        sys.stderr.flush()

        deadline = time.monotonic() + self.timeout
        try:
            while time.monotonic() < deadline:
                if response_path.exists():
                    raw = response_path.read_text().strip()
                    self._cleanup(req.action_id)
                    return raw
                time.sleep(self.poll_interval)
        finally:
            # Whether approved, denied, or timed out, the request is no longer pending.
            if pending_path.exists():
                try:
                    pending_path.unlink()
                except OSError:
                    pass
        return None  # timeout -> default-deny

    def _cleanup(self, action_id: str) -> None:
        for p in (self.pending_dir / f"{action_id}.json", self.responses_dir / action_id):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass

    # -- operator-side helpers --------------------------------------------------------

    def list_pending(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for p in sorted(self.pending_dir.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
        return out

    def respond(self, action_id: str, approve: bool) -> bool:
        """Write the operator's decision. For APPROVE we read the pending record to recover
        the nonce, since the protocol requires ``APPROVE <nonce>`` exactly."""
        pending_path = self.pending_dir / f"{action_id}.json"
        if not pending_path.exists():
            return False
        if approve:
            try:
                nonce = json.loads(pending_path.read_text())["nonce"]
            except (OSError, json.JSONDecodeError, KeyError):
                return False
            body = f"APPROVE {nonce}"
        else:
            body = "DENY"
        (self.responses_dir / action_id).write_text(body)
        return True


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Operator console for the KKI out-of-band consent broker."
    )
    parser.add_argument("--dir", help="broker directory (default: $KKI_CONSENT_DIR or /tmp/kki-consent)")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="list pending consent requests")
    g.add_argument("--approve", metavar="ACTION_ID", help="approve a pending request")
    g.add_argument("--deny", metavar="ACTION_ID", help="deny a pending request")
    args = parser.parse_args(argv)

    broker = FileConsentBroker(base_dir=args.dir)

    if args.list:
        pending = broker.list_pending()
        if not pending:
            print("(no pending consent requests)")
            return 0
        for r in pending:
            print(f"{r['action_id']}  {r['tool']:>12}  target={r['target']}  "
                  f"radius={r['blast_radius']}  asked={r.get('created_at','?')}")
        return 0

    action_id = args.approve or args.deny
    approve = args.approve is not None
    ok = broker.respond(action_id, approve)
    if not ok:
        print(f"no pending request with id {action_id!r}", file=sys.stderr)
        return 1
    print(f"{'APPROVED' if approve else 'DENIED'} {action_id} at {datetime.now().isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
