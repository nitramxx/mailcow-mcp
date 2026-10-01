"""HTTP applications. Phase 0 serves only the health endpoint."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mailcow_mcp import __version__


def create_app(role: str) -> Starlette:
    """The ASGI app for ``role`` ("app" or "broker")."""

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "role": role, "version": __version__})

    return Starlette(routes=[Route("/healthz", healthz, methods=["GET"])])
