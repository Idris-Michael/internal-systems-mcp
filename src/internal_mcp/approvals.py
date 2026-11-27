"""Signed, expiring, single-use approvals for the one write tool.

An agent can't approve its own write. A person approves a specific draft in the approval gateway
(see the agent-approval-gateway repo), which returns a token binding that exact draft's hash, an
expiry and a nonce, signed with a key the agent never sees. The server checks all four and burns
the nonce, so a token can't be reused, edited after approval, or lifted onto a different draft.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any


def draft_hash(draft: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(draft, sort_keys=True).encode()).hexdigest()


class Approvals:
    def __init__(self, key: str, clock: Any = time.time) -> None:
        if len(key) < 32:
            raise ValueError("approval key must be at least 32 characters")
        self._key = key.encode()
        self._clock = clock
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def issue(self, draft: dict[str, Any], approver: str, ttl_s: int = 600) -> str:
        """What the approval gateway does when a person taps Approve."""
        body = {
            "draft": draft_hash(draft),
            "approver": approver,
            "exp": int(self._clock()) + ttl_s,
            "nonce": secrets.token_hex(8),
        }
        payload = json.dumps(body, sort_keys=True).encode()
        return base64.urlsafe_b64encode(payload).decode() + "." + self._sign(payload)

    def redeem(self, token: str, draft: dict[str, Any]) -> str:
        """Return the approver if the token is valid for this draft, else raise ValueError."""
        try:
            b64, sig = token.rsplit(".", 1)
            payload = base64.urlsafe_b64decode(b64.encode())
            body = json.loads(payload)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError("approval token is malformed") from e
        if not hmac.compare_digest(sig, self._sign(payload)):
            raise ValueError("approval token signature is invalid")
        if body.get("exp", 0) < self._clock():
            raise ValueError("approval token has expired")
        if body.get("draft") != draft_hash(draft):
            raise ValueError("approval token was issued for a different draft")
        with self._lock:
            if body["nonce"] in self._used:
                raise ValueError("approval token has already been used")
            self._used.add(body["nonce"])
        return str(body["approver"])
