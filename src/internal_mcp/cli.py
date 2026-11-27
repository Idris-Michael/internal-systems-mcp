"""internal-mcp: run the server, mint a dev token, or scan any MCP server for tool poisoning.

    internal-mcp serve [--port 8765] [--allow-writes]
    internal-mcp token CLIENT_ID SCOPE [SCOPE ...] [--ttl 900]
    internal-mcp scan URL [--token T]
    internal-mcp scan "node server.js" --stdio

Secrets come from the environment: MCP_TOKEN_SECRET and MCP_APPROVAL_KEY (32+ characters each).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from internal_mcp.auth import mint_token
from internal_mcp.poison import scan_tools


def _secret(name: str) -> str:
    v = os.environ.get(name, "")
    if len(v) < 32:
        raise SystemExit(f"{name} must be set to at least 32 characters")
    return v


async def _list_tools(url: str, token: str | None) -> list[dict[str, object]]:
    import httpx2
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=30) as http,
        streamable_http_client(url, http_client=http) as (read, write, *_),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        res = await session.list_tools()
        return [t.model_dump() for t in res.tools]


async def _list_tools_stdio(command: list[str]) -> list[dict[str, object]]:  # pragma: no cover - bench only
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(command=command[0], args=command[1:])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.list_tools()
        return [t.model_dump() for t in res.tools]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="internal-mcp", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--allow-writes", action="store_true")
    s.add_argument("--data", type=Path, default=Path("var"))
    t = sub.add_parser("token")
    t.add_argument("client_id")
    t.add_argument("scopes", nargs="+")
    t.add_argument("--ttl", type=int, default=900)
    c = sub.add_parser("scan")
    c.add_argument("url", help="server URL, or the command to start a stdio server when --stdio is set")
    c.add_argument("--token")
    c.add_argument("--stdio", action="store_true", help="start URL as a local stdio server command")
    c.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "token":
        print(mint_token(_secret("MCP_TOKEN_SECRET"), a.client_id, a.scopes, a.ttl))
        return 0
    if a.cmd == "scan":
        if a.stdio:  # pragma: no cover - bench only
            import shlex

            tools = asyncio.run(_list_tools_stdio(shlex.split(a.url, posix=False)))
        else:
            tools = asyncio.run(_list_tools(a.url, a.token))
        findings = scan_tools(tools)
        if a.json:  # pragma: no cover - bench only
            import json
            from dataclasses import asdict

            print(json.dumps({"tools": len(tools), "findings": [asdict(f) for f in findings]}))
            return 1 if findings else 0
        for f in findings:
            print(f"FLAG {f.tool:24} {f.field:18} {f.rule:16} {f.excerpt!r}")
        print(f"{len(tools)} tools scanned, {len(findings)} finding(s)")
        return 1 if findings else 0

    from internal_mcp.server import Config, build  # pragma: no cover - exercised by the live demo

    cfg = Config(  # pragma: no cover
        token_secret=_secret("MCP_TOKEN_SECRET"),
        approval_key=_secret("MCP_APPROVAL_KEY"),
        data_dir=a.data,
        allow_writes=a.allow_writes,
        public_url=f"http://127.0.0.1:{a.port}",
    )
    mcp, _ = build(cfg)  # pragma: no cover
    print(
        f"serving on http://127.0.0.1:{a.port}/mcp (writes {'on' if a.allow_writes else 'off'})",
        file=sys.stderr,
    )
    mcp.run(transport="streamable-http", host="127.0.0.1", port=a.port)  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
