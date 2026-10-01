"""Audit log: one JSON object per line, to stdout and to DATA_DIR/audit.log.

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
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
