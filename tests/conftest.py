from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from mailcow_mcp.app import create_app
from mailcow_mcp.audit import AuditLog
from mailcow_mcp.config import AppConfig, generate_key, load_app_config
from mailcow_mcp.db import Database
from mailcow_mcp.imap import LoginResult
from mailcow_mcp.oauth import Provider

from mailserver_fixture import mailserver  # noqa: F401 - pytest fixture

BASE_URL = "http://localhost:8090"
REDIRECT_URI = "http://127.0.0.1:3333/callback"
EMAIL = "user@example.org"
PASSWORD = "correct horse battery staple"


def app_config(**overrides: str) -> AppConfig:
    env = {
        "MODE": "generic",
        "PUBLIC_URL": BASE_URL,
        "IMAP_HOST": "imap.example.org",
        "ENC_KEY": generate_key(),
        "TRUSTED_PROXIES": "127.0.0.1",
    }
    env.update(overrides)
    return load_app_config(env)


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeVerifier:
    """Accepts EMAIL/PASSWORD; records every call."""

    result: LoginResult | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def __call__(self, username: str, password: str) -> LoginResult:
        self.calls.append((username, password))
        if self.result is not None:
            return self.result
        ok = username == EMAIL and password == PASSWORD
        return LoginResult.OK if ok else LoginResult.INVALID


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def form_value(html: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]*)"', html)
    assert match, f"no {name} field"
    return match.group(1)


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


@dataclass
class Harness:
    client: TestClient
    provider: Provider
    db: Database
    clock: Clock
    verifier: FakeVerifier
    audit_stream: io.StringIO

    def audit_lines(self) -> list[str]:
        return self.audit_stream.getvalue().splitlines()

    def register(self, **metadata: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "client_name": "Test Client",
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        body.update(metadata)
        response = self.client.post("/register", json=body)
        assert response.status_code == 201, response.text
        result: dict[str, Any] = response.json()
        return result

    def authorize(self, client_id: str, challenge: str, **params: str) -> str:
        """Run /authorize; returns the sign-in page URL."""
        query = {
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "state-123",
            "resource": f"{BASE_URL}/mcp",
        }
        query.update(params)
        response = self.client.get("/authorize", params=query, follow_redirects=False)
        assert response.status_code == 302, response.text
        location: str = response.headers["location"]
        return location

    def open_login(self, login_url: str) -> tuple[str, str]:
        """GET the sign-in page; returns (request id, csrf token)."""
        page = self.client.get(login_url)
        assert page.status_code == 200, page.text
        return form_value(page.text, "request"), form_value(page.text, "csrf")

    def submit_login(
        self,
        request_id: str,
        csrf: str,
        *,
        email: str = EMAIL,
        password: str = PASSWORD,
        **extra: str,
    ) -> Any:
        data = {
            "request": request_id,
            "csrf": csrf,
            "action": "login",
            "email": email,
            "password": password,
        }
        data.update(extra)
        return self.client.post("/login", data=data, follow_redirects=False)

    def sign_in(
        self, client_id: str, email: str = EMAIL, password: str = PASSWORD
    ) -> tuple[str, str]:
        """Full sign-in; returns (authorization code, PKCE verifier)."""
        verifier, challenge = pkce_pair()
        request_id, csrf = self.open_login(self.authorize(client_id, challenge))
        response = self.submit_login(request_id, csrf, email=email, password=password)
        assert response.status_code == 303, response.text
        params = query_of(response.headers["location"])
        assert params["state"] == "state-123"
        return params["code"], verifier

    def exchange(self, client_id: str, code: str, verifier: str) -> Any:
        return self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )

    def tokens(
        self, client_id: str | None = None, email: str = EMAIL, password: str = PASSWORD
    ) -> tuple[str, dict[str, Any]]:
        """Register (unless given), sign in and exchange; returns (client id, token response)."""
        client_id = client_id or self.register()["client_id"]
        code, verifier = self.sign_in(client_id, email, password)
        response = self.exchange(client_id, code, verifier)
        assert response.status_code == 200, response.text
        return client_id, response.json()

    def refresh(self, client_id: str, refresh_token: str) -> Any:
        return self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
        )

    def mcp(self, access_token: str | None, method: str = "initialize") -> Any:
        headers = {"Accept": "application/json, text/event-stream"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }
        return self.client.post("/mcp", headers=headers, json=body)

    def session(self, email: str = EMAIL, password: str = PASSWORD) -> McpSession:
        """Sign in and open an MCP session."""
        _, tokens = self.tokens(email=email, password=password)
        return McpSession(self.client, tokens["access_token"])


class ToolFailed(Exception):
    pass


class McpSession:
    """A minimal Streamable HTTP client for tool calls in tests."""

    def __init__(self, client: TestClient, access_token: str) -> None:
        self.client = client
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        }
        self._id = 0
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        assert "serverInfo" in result
        self.client.post(
            "/mcp",
            headers=self.headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        response = self.client.post(
            "/mcp",
            headers=self.headers,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
        )
        if response.status_code != 200:
            raise ToolFailed(f"HTTP {response.status_code}: {response.text}")
        if session_id := response.headers.get("mcp-session-id"):
            self.headers["mcp-session-id"] = session_id
        for line in response.text.splitlines():
            if line.startswith("data: "):
                message = json.loads(line[6:])
                if message.get("id") == self._id:
                    if "error" in message:
                        raise ToolFailed(json.dumps(message["error"]))
                    result: dict[str, Any] = message["result"]
                    return result
        raise AssertionError(f"no response in {response.text!r}")

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        """Call a tool; returns its structured result or raises ToolFailed with its message."""
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise ToolFailed(result["content"][0]["text"])
        structured: dict[str, Any] = result["structuredContent"]
        return structured


def make_harness(
    config: AppConfig,
    verifier: FakeVerifier | None = None,
    db: Database | None = None,
    *,
    real_login: bool = False,
) -> Iterator[Harness]:
    """real_login: check passwords with the configured IMAP server instead of a fake."""
    db = db or Database(":memory:")
    clock = Clock()
    stream = io.StringIO()
    fake = None if real_login else (verifier or FakeVerifier())
    app = create_app(config, db=db, audit=AuditLog(None, stream=stream), verifier=fake, clock=clock)
    with TestClient(app, base_url=BASE_URL) as client:
        yield Harness(client, app.provider, db, clock, fake or FakeVerifier(), stream)


@pytest.fixture
def harness() -> Iterator[Harness]:
    yield from make_harness(app_config())
