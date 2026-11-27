"""Attack suite: run every attack against a live server over HTTP and count what got through.

Each attack is a real MCP request through the official client. "Blocked" means the server refused
it (401 at the door, or a tool error) and nothing was read or written that shouldn't have been.
Legitimate calls are run alongside, so a server that blocks everything would show up as broken.

    uv run python bench/attacks.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import jwt

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "tests"))

from conftest import APPROVAL_KEY, SECRET, call, session  # noqa: E402

from internal_mcp.approvals import Approvals  # noqa: E402
from internal_mcp.auth import AUDIENCE, ISSUER  # noqa: E402
from internal_mcp.server import Config, build  # noqa: E402

AD = {
    "template_id": "meta-feed-1x1",
    "headline": "Bookkeeping that keeps up",
    "body": "Send invoices and see cash flow in one place.",
    "cta": "Start free trial",
    "legal_line": "Terms apply. See ledgerly.example/terms.",
    "colours": ["#0B1F33"],
}
TOOLS = {
    "get_brand_guidelines": ("brand:read", {}),
    "get_template": ("brand:read", {"template_id": "google-rsa"}),
    "check_ad": ("brand:read", AD),
    "find_accounts": ("crm:read", {"query": "Halden"}),
    "list_campaigns": ("crm:read", {"account_id": "ACC-1002"}),
    "save_ad_draft": ("drafts:write", {"account_id": "ACC-1002", **AD, "approval_token": "x"}),
}
SQLI = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE accounts;--",
    '" OR ""="',
    "%' UNION SELECT id,name,sector,plan,region FROM accounts--",
    "%",
    "_",
    "Halden' AND (SELECT COUNT(*) FROM accounts)>0--",
    "x' || (SELECT name FROM accounts LIMIT 1) || '",
    "\\",
]
BAD_IDS = ["ACC-1002' OR 1=1--", "ACC-1002;--", "../../etc/passwd", "ACC-*", "acc-1002", "ACC-10021", ""]
BAD_TEMPLATES = ["../templates.json", "meta-feed-1x1'--", "x" * 41, "META-FEED-1X1", "{{7*7}}"]


def raw_token(**over: Any) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "attacker",
        "scope": "brand:read crm:read drafts:write",
        "iat": now,
        "exp": now + 300,
        **over,
    }
    alg = over.pop("_alg", "HS256")
    key = over.pop("_key", SECRET)
    claims.pop("_alg", None)
    claims.pop("_key", None)
    return jwt.encode(claims, key, algorithm=alg)


async def door_refuses(url: str, token: str | None) -> bool:
    try:
        async with session(url, token) as s:
            await s.list_tools()
    except Exception:
        return True
    return False


async def run(url: str, mint: Any) -> dict[str, Any]:
    res: dict[str, dict[str, Any]] = {}

    def tally(cat: str, blocked: bool, what: str) -> None:
        r = res.setdefault(cat, {"attempts": 0, "blocked": 0, "let_through": []})
        r["attempts"] += 1
        r["blocked"] += blocked
        if not blocked:
            r["let_through"].append(what)

    # 1. Authentication at the door
    for what, tok in [
        ("no token", None),
        ("garbage token", "not.a.jwt"),
        ("forged signature", raw_token(_key="w" * 40)),
        ("alg none", raw_token(_alg="none", _key=None)),
        ("expired", raw_token(exp=int(time.time()) - 10)),
        ("wrong audience", raw_token(aud="billing-api")),
        ("wrong issuer", raw_token(iss="https://evil.example")),
        ("10-hour lifetime", raw_token(exp=int(time.time()) + 36000)),
    ]:
        tally("auth", await door_refuses(url, tok), what)

    # 2. Scope violations: every tool, with every token that lacks its scope
    for tool, (needed, args) in TOOLS.items():
        for scope in ("brand:read", "crm:read", "drafts:write"):
            if scope == needed:
                continue
            ok, _ = await call(url, mint(scope), tool, **args)
            tally("scope", not ok, f"{tool} with {scope}")

    # 3. Argument injection
    for q in SQLI:
        ok, out = await call(url, mint("crm:read"), "find_accounts", query=q)
        tally("injection", (not ok) or out == [], f"find_accounts {q!r}")
    for a in BAD_IDS:
        ok, _ = await call(url, mint("crm:read"), "list_campaigns", account_id=a)
        tally("injection", not ok, f"list_campaigns {a!r}")
    for t in BAD_TEMPLATES:
        ok, _ = await call(url, mint("brand:read"), "get_template", template_id=t)
        tally("injection", not ok, f"get_template {t!r}")
    ok, _ = await call(url, mint("brand:read"), "check_ad", **{**AD, "body": "x" * 100_000})
    tally("injection", not ok, "100 kB body")

    # 4. The write path: everything except a fresh approval for this exact, passing draft
    draft = {"account_id": "ACC-1002", **AD}
    appr = Approvals(APPROVAL_KEY)
    w = mint("drafts:write")
    good = appr.issue(draft, "finance-lead")
    cases = [
        ("no approval", draft, ""),
        ("malformed approval", draft, "abc.def"),
        ("approval signed with another key", draft, Approvals("q" * 40).issue(draft, "me")),
        ("approval for a different draft", {**draft, "headline": "Different"}, good),
        (
            "approval with edited body after approval",
            {**draft, "body": draft["body"] + " Now 50% off!"},
            good,
        ),
        (
            "approved draft that fails brand QA",
            {**draft, "cta": "Buy now"},
            appr.issue({**draft, "cta": "Buy now"}, "finance-lead"),
        ),
        (
            "expired approval",
            draft,
            Approvals(APPROVAL_KEY, clock=lambda: time.time() - 3600).issue(draft, "x", 60),
        ),
        ("approval for another account", {**draft, "account_id": "ACC-1004"}, good),
        (
            "unknown account",
            {**draft, "account_id": "ACC-9999"},
            appr.issue({**draft, "account_id": "ACC-9999"}, "x"),
        ),
    ]
    for what, d, tok in cases:
        ok, _ = await call(url, w, "save_ad_draft", **d, approval_token=tok)
        tally("write", not ok, what)
    ok, _ = await call(url, w, "save_ad_draft", **draft, approval_token=good)
    legit_write = ok
    ok, _ = await call(url, w, "save_ad_draft", **draft, approval_token=good)
    tally("write", not ok, "replayed approval")

    # 5. Legitimate calls must still work
    legit = {"approved write": legit_write}
    for tool, (needed, args) in TOOLS.items():
        if tool != "save_ad_draft":
            legit[tool] = (await call(url, mint(needed), tool, **args))[0]

    return {"categories": res, "legitimate_calls": legit}


async def rate_burst(url: str, mint: Any, n: int) -> int:
    tok = mint("brand:read")
    limited = 0
    for _ in range(n):
        ok, out = await call(url, tok, "get_template", template_id="google-rsa")
        limited += (not ok) and "rate limit" in out
    return limited


def main() -> None:
    import socket
    import tempfile
    import threading

    import uvicorn

    from internal_mcp.auth import mint_token

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = Config(
        SECRET,
        APPROVAL_KEY,
        Path(tempfile.mkdtemp()),
        allow_writes=True,
        rate_per_min=60,
        burst=20,
        public_url=f"http://127.0.0.1:{port}",
    )
    mcp, audit = build(cfg)
    server = uvicorn.Server(
        uvicorn.Config(mcp.streamable_http_app(host="127.0.0.1"), port=port, log_level="error")
    )
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port}/mcp"
    counter = iter(range(10_000))

    def mint(*scopes: str) -> str:  # a fresh client per call keeps the rate limit out of the other tests
        return mint_token(SECRET, f"client-{next(counter)}", list(scopes))

    out = asyncio.run(run(url, mint))
    out["rate_limit"] = {"burst_allowed": 20, "calls": 40, "limited": asyncio.run(rate_burst(url, mint, 40))}
    rows = audit.read()
    out["audit_rows"] = len(rows)
    out["audit_outcomes"] = {
        k: sum(1 for r in rows if r["outcome"] == k) for k in {r["outcome"] for r in rows}
    }
    server.should_exit = True
    (HERE / "attacks_results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    print("| attack | attempts | blocked |")
    print("|---|---|---|")
    for cat, r in out["categories"].items():
        print(
            f"| {cat} | {r['attempts']} | {r['blocked']} |"
            + (f" let through: {r['let_through']}" if r["let_through"] else "")
        )
    rl = out["rate_limit"]
    print(f"rate limit: {rl['limited']} of {rl['calls']} burst calls limited (burst {rl['burst_allowed']})")
    print(f"legitimate calls ok: {sum(out['legitimate_calls'].values())}/{len(out['legitimate_calls'])}")
    print(f"audit log: {out['audit_rows']} rows {out['audit_outcomes']}")


if __name__ == "__main__":
    main()
