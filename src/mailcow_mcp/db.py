"""SQLite database with versioned migrations.

Migrations are the numbered ``migrations/NNNN_*.sql`` files, applied in order and
tracked with ``PRAGMA user_version``. They run automatically on start.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

DB_FILENAME = "mailcow-mcp.sqlite3"
_MIGRATION_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class Database:
    """A single SQLite connection in autocommit mode; use ``transaction()`` for writes."""

    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")

    @classmethod
    def in_data_dir(cls, data_dir: Path) -> Database:
        return cls(data_dir / DB_FILENAME)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def execute(
        self, sql: str, params: tuple[object, ...] | dict[str, object] = ()
    ) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def one(
        self, sql: str, params: tuple[object, ...] | dict[str, object] = ()
    ) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute(sql, params).fetchone()
        return row

    def all(
        self, sql: str, params: tuple[object, ...] | dict[str, object] = ()
    ) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    @property
    def version(self) -> int:
        row = self.conn.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    def migrate(self) -> list[str]:
        """Apply pending migrations; return the names of those applied."""
        applied: list[str] = []
        for number, name, sql in available_migrations():
            if number <= self.version:
                continue
            # executescript() commits first, so the transaction is part of the script.
            try:
                self.conn.executescript(
                    f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {number};\nCOMMIT;"
                )
            except sqlite3.Error:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                raise
            applied.append(name)
        return applied


def available_migrations() -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for entry in resources.files("mailcow_mcp.migrations").iterdir():
        match = _MIGRATION_RE.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry.name, entry.read_text(encoding="utf-8")))
    found.sort()
    numbers = [number for number, _, _ in found]
    if numbers != list(range(1, len(numbers) + 1)):
        raise RuntimeError(f"migrations must be numbered 0001, 0002, … without gaps: {numbers}")
    return found
