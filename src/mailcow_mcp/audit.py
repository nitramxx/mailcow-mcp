"""Audit log: one JSON object per line, to stdout and to DATA_DIR/audit.log.

The file is rotated at 10 MB, keeping five old files (audit.log.1 … .5).

Never pass message bodies, attachment contents, passwords or tokens.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any

AUDIT_FILENAME = "audit.log"
MAX_FILE_BYTES = 10 * 1024 * 1024
KEEP_FILES = 5  # audit.log.1 … audit.log.5


class AuditLog:
    def __init__(self, path: Path | None, *, stream: IO[str] | None = None) -> None:
        self._path = path
        self._stream = stream if stream is not None else sys.stdout
        self._lock = threading.Lock()

    @classmethod
    def in_data_dir(cls, data_dir: Path) -> AuditLog:
        return cls(data_dir / AUDIT_FILENAME)

    def __call__(
        self,
        event: str,
        *,
        result: str = "ok",
        mailbox: str | None = None,
        client: str | None = None,
        **fields: Any,
    ) -> None:
        record: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "audit": event,
            "result": result,
        }
        if mailbox is not None:
            record["mailbox"] = mailbox
        if client is not None:
            record["client"] = client
        record.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            print(line, file=self._stream, flush=True)
            if self._path is not None:
                self._rotate_if_full()
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")

    def _rotate_if_full(self) -> None:
        assert self._path is not None  # noqa: S101 - checked by the caller
        try:
            if self._path.stat().st_size < MAX_FILE_BYTES:
                return
        except FileNotFoundError:
            return
        for index in range(KEEP_FILES - 1, 0, -1):
            older = self._path.with_name(f"{self._path.name}.{index}")
            if older.exists():
                older.replace(self._path.with_name(f"{self._path.name}.{index + 1}"))
        self._path.replace(self._path.with_name(f"{self._path.name}.1"))
