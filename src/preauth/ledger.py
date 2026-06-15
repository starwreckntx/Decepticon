"""
WriteAheadLedger — the "log-before-execute" record.

The broker appends the authorization intent here BEFORE it issues a token or opens any
capability. So the durable record provably precedes the side effect: if the authority dies
mid-handshake there is a record of intent but no token, hence no execution (fail closed),
and the act can never happen without its record existing first. Append-only, hash-chained,
independently verifiable.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Tuple


class WriteAheadLedger:
    def __init__(self, seed: str = "preauth"):
        self._entries: List[Dict[str, Any]] = []
        self._head = hashlib.sha256(f"WAL:{seed}".encode()).hexdigest()
        self._seed = seed

    def append(self, record: Dict[str, Any]) -> Tuple[int, str]:
        """Append a record; return (seq, entry_hash). Called before token issuance."""
        entry = {"seq": len(self._entries), "prev": self._head, **record}
        h = self._hash(entry)
        entry["hash"] = h
        self._entries.append(entry)
        self._head = h
        return entry["seq"], h

    def verify(self) -> Tuple[bool, str]:
        prev = hashlib.sha256(f"WAL:{self._seed}".encode()).hexdigest()
        for i, e in enumerate(self._entries):
            if e.get("prev") != prev:
                return False, f"break at {i}: prev mismatch"
            if self._hash({k: v for k, v in e.items() if k != "hash"}) != e.get("hash"):
                return False, f"break at {i}: hash mismatch"
            prev = e["hash"]
        return True, "ok"

    @staticmethod
    def _hash(entry: Dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return self._entries

    @property
    def head(self) -> str:
        return self._head
