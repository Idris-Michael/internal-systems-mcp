"""Brand QA benchmark: how often does model-written ad copy pass the hard brand rules, before and after
one repair round driven by check_ad's failures?

Pipeline per brief, every brand call over MCP with a brand:read token:
  get_brand_guidelines + get_template -> Claude Haiku writes one ad as JSON -> check_ad
  -> if it fails: the failures go back to the model once -> check_ad again.
The model writes copy only; pass/fail comes from code. Uses the claude CLI (subscription, tools off).

    uv run python bench/brand_qa.py --n 40
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "tests"))

import uvicorn  # noqa: E402
from conftest import APPROVAL_KEY, SECRET, call  # noqa: E402

from internal_mcp.auth import mint_token  # noqa: E402
from internal_mcp.server import Config, build  # noqa: E402

MODEL = "claude-haiku-5-5"
TEMPLATES = ["meta-feed-1x1", "meta-story-9x16", "google-rsa", "tiktok-video-9x16"]
BRIEFS = [
    "Launch of automatic bank reconciliation for sole traders",
    "Spring promotion: three months at half price for new customers",
    "Reminder that self-assessment tax returns are due on 31 January",
    "New mobile app for snapping receipts on the go",
    "Invoices that chase late payers for you",
    "Payroll for teams of one to ten people",
    "Switching from spreadsheets to proper bookkeeping",
    "VAT returns filed straight to HMRC",
    "Cash-flow forecast for the next 90 days",
    "Accountant access: share your books in one click",
]
SYSTEM = "You write short ad copy. Output only a JSON object, nothing else."


def ask(prompt: str) -> str:
    cli = shutil.which("claude") or "claude"
    args = [
        cli,
        "-p",
        "--model",
        MODEL,
        "--output-format",
        "text",
        "--tools",
        "",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--setting-sources",
        "",
        "--no-session-persistence",
        "--system-prompt",
        SYSTEM,
    ]
    return subprocess.run(
        args,
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=240,
        check=True,
    ).stdout


def parse(raw: str) -> dict[str, Any] | None:
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    keys = {"headline", "body", "cta", "legal_line", "colours"}
    if not keys <= set(d) or not isinstance(d["colours"], list):
        return None
    return {k: (d[k] if k == "colours" else str(d[k])) for k in keys}


def write_prompt(brief: str, guidelines: str, tpl: dict[str, Any]) -> str:
    return (
        f"Brand guidelines:\n{guidelines}\n\nTemplate (limits, palette, approved CTAs, legal line):\n"
        f"{json.dumps(tpl)}\n\nBrief: {brief}\n\nWrite one ad for this template. Return JSON with keys "
        "headline, body, cta, legal_line, colours (a list of hex codes)."
    )


async def one(url: str, token: str, i: int) -> dict[str, Any]:
    brief, tid = BRIEFS[i % len(BRIEFS)], TEMPLATES[i % len(TEMPLATES)]
    _, guide = await call(url, token, "get_brand_guidelines")
    _, tpl = await call(url, token, "get_template", template_id=tid)
    loop = asyncio.get_running_loop()
    first_raw = await loop.run_in_executor(None, ask, write_prompt(brief, guide, tpl))
    ad = parse(first_raw)
    if ad is None:
        return {
            "id": i,
            "template": tid,
            "brief": brief,
            "first": None,
            "repaired": None,
            "parse_error": True,
        }
    _, qa1 = await call(url, token, "check_ad", template_id=tid, **ad)
    out: dict[str, Any] = {"id": i, "template": tid, "brief": brief, "ad": ad, "first": qa1, "repaired": None}
    if not qa1["passed"]:
        fix = (
            write_prompt(brief, guide, tpl) + f"\n\nYour previous ad:\n{json.dumps(ad)}\n\nIt failed these "
            f"brand checks:\n{json.dumps(qa1['failures'])}\nFix every failure and return the corrected JSON."
        )
        ad2 = parse(await loop.run_in_executor(None, ask, fix))
        if ad2 is not None:
            _, qa2 = await call(url, token, "check_ad", template_id=tid, **ad2)
            out["repaired"], out["ad2"] = qa2, ad2
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    a = ap.parse_args()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = Config(
        SECRET,
        APPROVAL_KEY,
        Path(tempfile.mkdtemp()),
        rate_per_min=6000,
        burst=1000,
        public_url=f"http://127.0.0.1:{port}",
    )
    mcp, _ = build(cfg)
    server = uvicorn.Server(
        uvicorn.Config(mcp.streamable_http_app(host="127.0.0.1"), port=port, log_level="error")
    )
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    url, token = f"http://127.0.0.1:{port}/mcp", mint_token(SECRET, "brand-bench", ["brand:read"], 3600)

    def run_i(i: int) -> dict[str, Any]:
        return asyncio.run(one(url, token, i))

    with ThreadPoolExecutor(6) as pool:
        rows = list(pool.map(run_i, range(a.n)))
    server.should_exit = True

    first = sum(1 for r in rows if r["first"] and r["first"]["passed"])
    after = sum(
        1
        for r in rows
        if (r["first"] and r["first"]["passed"]) or (r["repaired"] and r["repaired"]["passed"])
    )
    rules = Counter(f["rule"] for r in rows if r["first"] for f in r["first"]["failures"])
    left = Counter(f["rule"] for r in rows if r["repaired"] for f in r["repaired"]["failures"])
    out = {
        "model": MODEL,
        "ads": len(rows),
        "passed_first_try": first,
        "passed_after_one_repair": after,
        "parse_errors": sum(1 for r in rows if r.get("parse_error")),
        "first_try_failures_by_rule": rules,
        "failures_left_after_repair": left,
        "rows": rows,
    }
    (HERE / "brand_qa_results.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"{len(rows)} ads: {first} passed first try, {after} after one repair round")
    print("first-try failures by rule:", dict(rules))
    print("left after repair:", dict(left))


if __name__ == "__main__":
    main()
