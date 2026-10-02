"""Logging setup. Access logs never contain query strings.

Query strings carry secrets on this server: sign-in request ids (/login?request=…)
and mailcow's OAuth code and state (/oauth/mailcow/callback?code=…).
"""

from __future__ import annotations

import logging


class StripQueryString(logging.Filter):
    """For uvicorn.access records: args are (client, method, path, http_version, status)."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            path, _, query = args[2].partition("?")
            record.args = (args[0], args[1], path + ("?…" if query else ""), args[3], args[4])
        return True


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("uvicorn.access").addFilter(StripQueryString())
    # httpx logs every request URL at INFO, e.g. mailcow API paths naming a mailbox.
    logging.getLogger("httpx").setLevel(logging.WARNING)
