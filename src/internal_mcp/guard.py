"""The checks every tool call passes through: scope, rate limit, audit.

Tools declare the scope they need with :func:`guarded`. A call without that scope, or over the
caller's rate, fails with a :class:`ToolError` the agent can read, and both outcomes are written to
the audit log. Arguments are logged as a hash, never in full, so the log holds no customer data.
"""

from __future__ import annotations

import functools
import hashlib
import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError

P = ParamSpec("P")
R = TypeVar("R")


class AuditLog:
    """Append-only JSON lines: who called what, with which outcome."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **entry: Any) -> None:
        line = json.dumps({"ts": round(time.time(), 3), **entry}, sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x]


class RateLimiter:
    """Token bucket per client: ``rate`` calls per minute, bursts up to ``burst``."""

    def __init__(self, rate_per_min: float, burst: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        with self._lock:
            now = self.clock()
            tokens, last = self._buckets.get(client_id, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[client_id] = (tokens, now)
                return False
            self._buckets[client_id] = (tokens - 1, now)
            return True


def args_hash(kwargs: dict[str, Any]) -> str:
    raw = json.dumps(kwargs, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def make_guard(
    audit: AuditLog, limiter: RateLimiter
) -> Callable[[str], Callable[[Callable[P, R]], Callable[P, R]]]:
    def guarded(scope: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def wrap(fn: Callable[P, R]) -> Callable[P, R]:
            @functools.wraps(fn)
            def inner(*args: P.args, **kwargs: P.kwargs) -> R:
                tok = get_access_token()
                client = tok.client_id if tok else "anonymous"
                base = {"client": client, "tool": fn.__name__, "args": args_hash(dict(kwargs))}
                if tok is None or scope not in tok.scopes:
                    audit.write(**base, outcome="denied_scope", needed=scope)
                    raise ToolError(f"forbidden: this tool needs the '{scope}' scope")
                if not limiter.allow(client):
                    audit.write(**base, outcome="rate_limited")
                    raise ToolError("rate limit exceeded: slow down and retry in a minute")
                try:
                    result = fn(*args, **kwargs)
                except ToolError as e:
                    audit.write(**base, outcome="rejected", detail=str(e)[:200])
                    raise
                except Exception as e:
                    audit.write(**base, outcome="error", detail=type(e).__name__)
                    raise
                audit.write(**base, outcome="ok")
                return result

            return inner

        return wrap

    return guarded
