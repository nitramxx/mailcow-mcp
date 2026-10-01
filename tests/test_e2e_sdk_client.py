"""End to end with the MCP SDK's own OAuth client against a real uvicorn server.

Covers what a third-party client does: 401 → resource metadata → server
metadata → dynamic registration → PKCE authorization (here the "browser" signs
in on our page) → token exchange with `iss` check → MCP session.
"""

from __future__ import annotations

import io
import socket
import threading
import time
from collections.abc import Iterator

import anyio
import httpx2
import pytest
import uvicorn
from mcp.client import Client
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)

from mailcow_mcp.app import create_app
from mailcow_mcp.audit import AuditLog
from mailcow_mcp.db import Database

from conftest import EMAIL, PASSWORD, FakeVerifier, app_config, form_value, query_of

REDIRECT = "http://127.0.0.1:1/callback"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@pytest.fixture
def server_url() -> Iterator[str]:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = create_app(
        app_config(PUBLIC_URL=base),
        db=Database(":memory:"),
        audit=AuditLog(None, stream=io.StringIO()),
        verifier=FakeVerifier(),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("server did not start")
        time.sleep(0.02)
    yield base
    server.should_exit = True
    thread.join(timeout=10)


class MemoryStorage:
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client = client_info


def test_sdk_client_connects_and_lists_no_tools(server_url: str) -> None:
    storage = MemoryStorage()
    result: dict[str, AuthorizationCodeResult] = {}

    async def browser(authorization_url: str) -> None:
        """Plays the user: opens the sign-in page and submits the password."""
        async with httpx2.AsyncClient() as http:
            authorize = await http.get(authorization_url)
            assert authorize.status_code == 302
            page = await http.get(authorize.headers["location"])
            assert page.status_code == 200
            assert "SDK test client" in page.text
            signed_in = await http.post(
                f"{server_url}/login",
                data={
                    "request": form_value(page.text, "request"),
                    "csrf": form_value(page.text, "csrf"),
                    "action": "login",
                    "email": EMAIL,
                    "password": PASSWORD,
                },
            )
            assert signed_in.status_code == 303
            location = signed_in.headers["location"]
            assert location.startswith(REDIRECT)
            params = query_of(location)
            result["code"] = AuthorizationCodeResult(
                code=params["code"], state=params["state"], iss=params["iss"]
            )

    async def callback() -> AuthorizationCodeResult:
        return result["code"]

    auth = OAuthClientProvider(
        server_url=f"{server_url}/mcp",
        client_metadata=OAuthClientMetadata.model_validate(
            {
                "client_name": "SDK test client",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }
        ),
        storage=storage,
        redirect_handler=browser,
        callback_handler=callback,
    )

    async def run() -> list[str]:
        async with (
            httpx2.AsyncClient(auth=auth, timeout=10) as http,
            Client(streamable_http_client(f"{server_url}/mcp", http_client=http)) as client,
        ):
            tools = await client.list_tools()
            return [tool.name for tool in tools.tools]

    assert anyio.run(run) == []
    assert storage.tokens is not None
    assert storage.tokens.access_token.startswith("mcp_at_")
    assert storage.client is not None
    assert storage.client.client_id
