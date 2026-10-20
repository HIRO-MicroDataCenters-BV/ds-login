"""In-memory challenge store with TTL. Single-use nonces, consumed on verify."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Challenge:
    aid: str
    nonce: bytes
    issued_at: float
    # KEL state resolved at challenge issue time, cached so verify doesn't
    # re-fetch (saves one OOBI round-trip + keeps the key the user signed
    # against identical to the key we check with). None when the resolver
    # didn't have a reachable path at challenge time (verify will retry).
    kel: dict[str, Any] | None = field(default=None)


class ChallengeStore:
    def __init__(self, ttl_seconds: int, nonce_bytes: int):
        self.ttl_seconds = ttl_seconds
        self.nonce_bytes = nonce_bytes
        self._store: dict[str, Challenge] = {}

    def issue(self, aid: str, kel: dict[str, Any] | None = None) -> Challenge:
        c = Challenge(
            aid=aid,
            nonce=secrets.token_bytes(self.nonce_bytes),
            issued_at=time.time(),
            kel=kel,
        )
        self._store[aid] = c
        return c

    def consume(self, aid: str, provided_nonce: bytes) -> Challenge | None:
        """Return the matching challenge if valid; always removes the entry
        so the nonce cannot be used twice."""
        entry = self._store.pop(aid, None)
        if entry is None:
            return None
        if time.time() - entry.issued_at > self.ttl_seconds:
            return None
        if provided_nonce != entry.nonce:
            return None
        return entry
