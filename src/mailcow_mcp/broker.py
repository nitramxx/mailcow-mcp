"""The internal broker. Phases 0-3: only the health endpoint."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mailcow_mcp import __version__


def create_broker_app() -> Starlette:
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "role": "broker", "version": __version__})

    return Starlette(routes=[Route("/healthz", healthz, methods=["GET"])])
