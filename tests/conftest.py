"""A real server on a random local port, called through the official MCP client over HTTP."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from internal_mcp.auth import mint_token
from internal_mcp.guard import AuditLog
from internal_mcp.server import Config, build

SECRET = "t" * 40
APPROVAL_KEY = "a" * 40


@dataclass
class Live:
    url: str
    cfg: Config
    audit: AuditLog

    def token(self, *scopes: str, client: str = "agent-1", ttl: int = 600) -> str:
        return mint_token(SECRET, client, list(scopes), ttl)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Live]:
    port = _free_port()
    cfg = Config(
        token_secret=SECRET,
        approval_key=APPROVAL_KEY,
        data_dir=Path(tmp_path_factory.mktemp("data")),
        allow_writes=True,
        rate_per_min=600,
        burst=200,
        public_url=f"http://127.0.0.1:{port}",
    )
    mcp, audit = build(cfg)
    app = mcp.streamable_http_app(host="127.0.0.1")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield Live(f"http://127.0.0.1:{port}/mcp", cfg, audit)
    server.should_exit = True
    th.join(timeout=5)


@asynccontextmanager
async def session(url: str, token: str | None) -> AsyncIterator[ClientSession]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=30) as http,
        streamable_http_client(url, http_client=http) as (read, write, *_),
        ClientSession(read, write) as s,
    ):
        await s.initialize()
        yield s


async def call(url: str, token: str, tool: str, **args: Any) -> tuple[bool, Any]:
    """(ok, payload). payload is the parsed result, or the error text the agent would see."""
    async with session(url, token) as s:
        res = await s.call_tool(tool, args)
    text = "".join(getattr(c, "text", "") for c in res.content)
    if res.is_error:
        return False, text
    if res.structured_content is not None:
        sc = res.structured_content
        return True, sc.get("result", sc)
    return True, json.loads(text) if text[:1] in "[{" else text
