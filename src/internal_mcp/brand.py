"""Brand library and the deterministic brand QA check.

The model writes copy; template choice, the legal line, the palette and the pass/fail verdict come
from code, so a hard brand rule never depends on a prompt.
"""

from __future__ import annotations

import json
import re
from functools import cache
from importlib.resources import files
from typing import Any

TEMPLATE_ID = re.compile(r"^[a-z0-9-]{1,40}$")


@cache
def library() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        files("internal_mcp").joinpath("data/templates.json").read_text("utf-8")
    )
    return data


def guidelines() -> str:
    return files("internal_mcp").joinpath("data/brand_guidelines.md").read_text("utf-8")


def template(template_id: str) -> dict[str, Any] | None:
    if not TEMPLATE_ID.fullmatch(template_id):
        return None
    return next((t for t in library()["templates"] if t["id"] == template_id), None)


def qa_check(
    template_id: str, headline: str, body: str, cta: str, legal_line: str, colours: list[str]
) -> dict[str, Any]:
    lib = library()
    t = template(template_id)
    if t is None:
        return {"passed": False, "failures": [{"rule": "template", "detail": "unknown template id"}]}
    failures: list[dict[str, str]] = []
    for slot, value in (("headline", headline), ("body", body), ("cta", cta)):
        limit = t["slots"][slot]["max_chars"]
        if len(value) > limit:
            failures.append({"rule": f"{slot}_length", "detail": f"{len(value)} chars, limit {limit}"})
    text = f"{headline} {body} {cta}".lower()
    for word in lib["banned_words"]:
        if re.search(rf"\b{re.escape(word)}\b", text):
            failures.append({"rule": "banned_word", "detail": word})
    if cta not in lib["approved_ctas"]:
        failures.append({"rule": "cta", "detail": f"'{cta[:40]}' is not an approved CTA"})
    if legal_line.strip() != lib["legal_line"]:
        failures.append({"rule": "legal_line", "detail": "must match the approved legal line exactly"})
    allowed = {v.lower() for v in lib["palette"].values()}
    for c in colours:
        if c.lower() not in allowed:
            failures.append({"rule": "colour", "detail": f"{c[:12]} is not in the palette"})
    return {"passed": not failures, "failures": failures}
