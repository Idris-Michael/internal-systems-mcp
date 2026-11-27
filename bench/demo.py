"""A short live session against the server, for the README GIF. Every line is a real MCP call over HTTP."""

from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "tests"))

import uvicorn  # noqa: E402
from conftest import APPROVAL_KEY, SECRET, call  # noqa: E402

from internal_mcp.approvals import Approvals  # noqa: E402
from internal_mcp.auth import mint_token  # noqa: E402
from internal_mcp.server import Config, build  # noqa: E402

AD = {
    "template_id": "meta-feed-1x1",
    "headline": "Bookkeeping that keeps up",
    "body": "Send invoices and see cash flow in one place.",
    "cta": "Start free trial",
    "legal_line": "Terms apply. See ledgerly.example/terms.",
    "colours": ["#0B1F33"],
}


def show(label: str, ok: bool, out: object) -> None:
    mark = "ok     " if ok else "REFUSED"
    text = str(out).split(": ", 1)[-1] if not ok else str(out)
    text = (
        text
        if not isinstance(out, list)
        else f"{len(out)} row(s) {[r.get('name', r.get('id')) for r in out]}"
    )
    print(f"{mark} {label:44} {text[:70]}", flush=True)


async def session(url: str) -> None:
    agent = mint_token(SECRET, "ops-agent", ["brand:read", "crm:read"])
    writer = mint_token(SECRET, "ops-agent", ["brand:read", "drafts:write"])
    show("find_accounts('Halden')", *await call(url, agent, "find_accounts", query="Halden"))
    show("find_accounts(\"' OR '1'='1\")", *await call(url, agent, "find_accounts", query="' OR '1'='1"))
    show(
        "list_campaigns('../../etc/passwd')",
        *await call(url, agent, "list_campaigns", account_id="../../etc/passwd"),
    )
    show(
        "save_ad_draft with a read-only token",
        *await call(url, agent, "save_ad_draft", account_id="ACC-1002", **AD, approval_token="x"),
    )
    draft = {"account_id": "ACC-1002", **AD}
    approval = Approvals(APPROVAL_KEY).issue(draft, approver="marketing-lead")
    edited = {**draft, "body": draft["body"] + " 50% off!"}
    show(
        "save_ad_draft, body edited after approval",
        *await call(url, writer, "save_ad_draft", **edited, approval_token=approval),
    )
    show(
        "save_ad_draft, approved draft",
        *await call(url, writer, "save_ad_draft", **draft, approval_token=approval),
    )
    show(
        "save_ad_draft, same approval again",
        *await call(url, writer, "save_ad_draft", **draft, approval_token=approval),
    )


def main() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = Config(
        SECRET,
        APPROVAL_KEY,
        Path(tempfile.mkdtemp()),
        allow_writes=True,
        public_url=f"http://127.0.0.1:{port}",
    )
    mcp, _ = build(cfg)
    server = uvicorn.Server(
        uvicorn.Config(mcp.streamable_http_app(host="127.0.0.1"), port=port, log_level="error")
    )
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    asyncio.run(session(f"http://127.0.0.1:{port}/mcp"))
    server.should_exit = True


if __name__ == "__main__":
    main()
