"""The app's client for the broker (mailcow mode)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mailcow_mcp.broker_protocol import SECRET_HEADER
from mailcow_mcp.errors import MailError, NotFound, ServerUnavailable
from mailcow_mcp.limits import BROKER_TIMEOUT

log = logging.getLogger(__name__)


class BrokerRefused(MailError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CapabilityRejected(BrokerRefused):
    """The broker refused this connection's capability: invalid, or its app password is gone."""


class BrokerClient:
    def __init__(
        self, url: str, shared_secret: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=url,
            headers={SECRET_HEADER: shared_secret},
            timeout=BROKER_TIMEOUT,
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def reachable(self) -> bool:
        """Whether the broker answers its health check (no secret needed)."""
        try:
            response = await self._http.get("/healthz", timeout=3)
        except httpx.HTTPError:
            return False
        return response.status_code == 200

    async def call(self, operation: str, **body: Any) -> dict[str, Any]:
        try:
            response = await self._http.post(f"/v1/{operation}", json=body)
        except httpx.HTTPError as exc:
            log.warning("broker %s failed: %s", operation, exc)
            raise ServerUnavailable("The mailcow connector (broker)") from exc
        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code == 200 and isinstance(data, dict):
            return data
        code = str(data.get("error", "error")) if isinstance(data, dict) else "error"
        message = str(data.get("message", code)) if isinstance(data, dict) else code
        log.warning(
            "broker %s refused: HTTP %s %s: %s", operation, response.status_code, code, message
        )
        if response.status_code == 401:
            log.error("the broker refused BROKER_SHARED_SECRET; check both containers' settings")
            raise ServerUnavailable("The mailcow connector (broker)")
        if code in ("invalid_capability", "revoked_capability"):
            raise CapabilityRejected(code, message)
        if response.status_code == 404:
            raise NotFound(message)
        if response.status_code in (502, 503):
            raise ServerUnavailable("mailcow")
        raise BrokerRefused(code, message)

    async def provision(self, mailcow_oauth_token: str, client_name: str | None) -> dict[str, Any]:
        return await self.call(
            "provision", mailcow_oauth_token=mailcow_oauth_token, client_name=client_name
        )

    async def deprovision(self, capability: str) -> dict[str, Any]:
        return await self.call("deprovision", capability=capability)

    async def reconcile(self, capabilities: list[str]) -> dict[str, Any]:
        return await self.call("reconcile", capabilities=capabilities)
