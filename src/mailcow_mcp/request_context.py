"""State of the HTTP request being handled, for code that has no request object."""

from __future__ import annotations

import contextvars

# The client IP (resolved from TRUSTED_PROXIES by uvicorn), set by the app's middleware.
client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("client_ip", default=None)
