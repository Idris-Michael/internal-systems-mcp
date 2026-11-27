"""A small read-only CRM for the fictional customer, in SQLite.

Every query is parameterised and the connection is opened read-only (``mode=ro``), so even a query
bug can't write. Inputs are validated before they reach SQL.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

ACCOUNT_ID = re.compile(r"^ACC-\d{4}$")
MAX_QUERY = 60

_SEED = [
    ("ACC-1001", "Brightwater Spa", "Health & beauty", "growth", "Northern"),
    ("ACC-1002", "Halden Outdoor", "Retail", "scale", "Northern"),
    ("ACC-1003", "Kestrel Legal", "Professional services", "starter", "London"),
    ("ACC-1004", "Morrow Bikes", "Retail", "growth", "Midlands"),
    ("ACC-1005", "Pellam Recruitment", "Professional services", "scale", "London"),
    ("ACC-1006", "Tarn Valley Cycles", "Retail", "starter", "Northern"),
]
_CAMPAIGNS = [
    ("CMP-01", "ACC-1002", "Winter boots", "meta", "live"),
    ("CMP-02", "ACC-1002", "Shopping always-on", "google", "live"),
    ("CMP-03", "ACC-1004", "Spring service", "google", "paused"),
    ("CMP-04", "ACC-1001", "Gift vouchers", "meta", "draft"),
]


def seed(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(
            """
            DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS campaigns;
            CREATE TABLE accounts (id TEXT PRIMARY KEY, name TEXT, sector TEXT, plan TEXT, region TEXT);
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY, account_id TEXT, name TEXT, channel TEXT, status TEXT
            );
            """
        )
        db.executemany("INSERT INTO accounts VALUES (?,?,?,?,?)", _SEED)
        db.executemany("INSERT INTO campaigns VALUES (?,?,?,?,?)", _CAMPAIGNS)


class Crm:
    def __init__(self, path: Path) -> None:
        if not path.exists():
            seed(path)
        self._uri = f"file:{path.as_posix()}?mode=ro"

    def _q(self, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self._uri, uri=True)) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(sql, params).fetchall()]

    def find_accounts(self, query: str) -> list[dict[str, Any]]:
        q = query.strip()
        if not q or len(q) > MAX_QUERY:
            raise ValueError(f"query must be 1-{MAX_QUERY} characters")
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return self._q("SELECT * FROM accounts WHERE name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 10", (like,))

    def account_exists(self, account_id: str) -> bool:
        if not ACCOUNT_ID.fullmatch(account_id):
            raise ValueError("account_id must look like ACC-1234")
        return bool(self._q("SELECT id FROM accounts WHERE id = ?", (account_id,)))

    def campaigns(self, account_id: str) -> list[dict[str, Any]]:
        if not ACCOUNT_ID.fullmatch(account_id):
            raise ValueError("account_id must look like ACC-1234")
        return self._q("SELECT * FROM campaigns WHERE account_id = ? ORDER BY id", (account_id,))
