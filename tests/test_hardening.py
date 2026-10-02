"""Negative and hardening tests (phase 6)."""

from __future__ import annotations

import base64
import io
import json
import logging
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer
from aiosmtpd.smtp import Envelope, Session

from mailcow_mcp.app import AUTHORIZATIONS_PER_IP_HOUR, create_app
from mailcow_mcp.audit import AuditLog
from mailcow_mcp.cli import app_server_options
from mailcow_mcp.db import Database
from mailcow_mcp.errors import MailError
from mailcow_mcp.logs import StripQueryString
from mailcow_mcp.smtp import SmtpSender

from conftest import BASE_URL, Harness, McpSession, ToolFailed, app_config


class Recorder:
    def __init__(self) -> None:
        self.messages: list[Envelope] = []

    async def handle_DATA(self, server: SMTPServer, session: Session, envelope: Envelope) -> str:
        self.messages.append(envelope)
        return "250 OK"


@pytest.fixture
def smtp_server(certs: Path) -> Iterator[tuple[Controller, Recorder]]:
    """A STARTTLS-capable SMTP server that offers no AUTH (like a trusting relay)."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certs / "server.crt", certs / "server.key")
    recorder = Recorder()
    controller = Controller(
        recorder,
        hostname="127.0.0.1",
        port=_free_port(),
        tls_context=context,
        require_starttls=True,
        auth_exclude_mechanism=["LOGIN", "PLAIN"],  # so AUTH isn't offered at all
    )
    controller.start()
    try:
        yield controller, recorder
    finally:
        controller.stop()


class TestSmtpNeverUnauthenticated:
    async def test_server_without_auth_gets_nothing(
        self, smtp_server: tuple[Controller, Recorder], certs: Path
    ) -> None:
        controller, recorder = smtp_server
        config = app_config(
            SMTP_HOST="127.0.0.1",
            SMTP_PORT=str(controller.port),
            SMTP_SECURITY="starttls",
            TLS_SERVER_NAME="mail.test",
            TLS_CA_FILE=str(certs / "ca.crt"),
        )
        with pytest.raises(MailError, match="nothing was sent"):
            await SmtpSender(config).send(
                "user@example.org",
                "pw",
                envelope_from="user@example.org",
                recipients=["x@example.org"],
                message=b"Subject: x\r\n\r\nx\r\n",
            )
        assert recorder.messages == []

    async def test_plaintext_server_is_refused(self) -> None:
        recorder = Recorder()
        controller = Controller(recorder, hostname="127.0.0.1", port=_free_port())  # no TLS at all
        controller.start()
        try:
            config = app_config(
                SMTP_HOST="127.0.0.1",
                SMTP_PORT=str(controller.port),
                SMTP_SECURITY="starttls",
            )
            with pytest.raises(MailError):
                await SmtpSender(config).send(
                    "u@example.org",
                    "pw",
                    envelope_from="u@example.org",
                    recipients=["x@example.org"],
                    message=b"x",
                )
            assert recorder.messages == []
        finally:
            controller.stop()

    async def test_certificate_name_is_verified(
        self, smtp_server: tuple[Controller, Recorder], certs: Path
    ) -> None:
        controller, recorder = smtp_server
        config = app_config(
            SMTP_HOST="127.0.0.1",
            SMTP_PORT=str(controller.port),
            TLS_SERVER_NAME="other.test",
            TLS_CA_FILE=str(certs / "ca.crt"),
        )
        with pytest.raises(MailError, match="can't be reached"):
            await SmtpSender(config).send(
                "u@example.org",
                "pw",
                envelope_from="u@example.org",
                recipients=["x@example.org"],
                message=b"x",
            )
        assert recorder.messages == []


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


pytestmark = pytest.mark.anyio


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _serve(trusted: str) -> Iterator[tuple[str, io.StringIO]]:
    port = _free_port()
    config = app_config(
        PUBLIC_URL=f"http://127.0.0.1:{port}", TRUSTED_PROXIES=trusted, PORT=str(port)
    )
    audit = io.StringIO()
    app = create_app(config, db=Database(":memory:"), audit=AuditLog(None, stream=audit))
    options = app_server_options(config) | {"host": "127.0.0.1", "log_level": "warning"}
    server = uvicorn.Server(uvicorn.Config(app, **options))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}", audit
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _register_ip(base: str, audit: io.StringIO) -> str:
    response = httpx.post(
        f"{base}/register",
        json={"redirect_uris": ["http://127.0.0.1:1/cb"], "token_endpoint_auth_method": "none"},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert response.status_code == 201, response.text
    event = json.loads(audit.getvalue().splitlines()[-1])
    return str(event["ip"])


class TestClientIp:
    async def test_forwarded_for_from_trusted_proxy(self) -> None:
        for base, audit in _serve("127.0.0.1"):
            assert _register_ip(base, audit) == "203.0.113.9"

    async def test_forwarded_for_from_anyone_else_is_ignored(self) -> None:
        for base, audit in _serve("10.0.0.0/8"):
            assert _register_ip(base, audit) == "127.0.0.1"


def test_access_log_has_no_query_strings() -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4:5", "GET", "/oauth/mailcow/callback?code=SECRET&state=S", "1.1", 303),
        None,
    )
    assert StripQueryString().filter(record)
    message = record.getMessage()
    assert "SECRET" not in message and "/oauth/mailcow/callback?…" in message


class TestIsolation:
    def test_token_for_another_resource_is_refused(self, harness: Harness) -> None:
        _, tokens = harness.tokens()
        harness.db.execute("UPDATE grants SET resource = 'https://other.example/mcp'")
        assert harness.mcp(tokens["access_token"]).status_code == 401

    def test_session_belongs_to_its_user(self, harness: Harness) -> None:
        alice = harness.session()
        _, other = harness.tokens()
        hijack = harness.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {other['access_token']}",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-11-25",
                "mcp-session-id": alice.headers["mcp-session-id"],
            },
            json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
        )
        assert hijack.status_code in (403, 404)

    def test_registration_body_limit(self, harness: Harness) -> None:
        response = harness.client.post(
            "/register",
            json={"redirect_uris": ["https://x.example/cb"], "client_name": "x" * 70_000},
        )
        assert response.status_code == 413

    def test_chunked_registration_body_limit(self, harness: Harness) -> None:
        def chunks() -> Iterator[bytes]:
            yield b'{"redirect_uris": ["https://x.example/cb"], "client_name": "'
            for _ in range(20):
                yield b"x" * 4096
            yield b'"}'

        response = harness.client.post(
            "/register", content=chunks(), headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 413

    def test_authorize_is_rate_limited(self, harness: Harness) -> None:
        for _ in range(AUTHORIZATIONS_PER_IP_HOUR):
            harness.client.get("/authorize", params={"client_id": "x"})
        response = harness.client.get("/authorize", params={"client_id": "x"})
        assert response.status_code == 429

    def test_login_form_body_limit(self, harness: Harness) -> None:
        response = harness.client.post("/login", data={"request": "x", "password": "x" * 20_000})
        assert response.status_code == 413

    def test_large_attachments_fit_the_mcp_body_limit(self, harness: Harness) -> None:
        session: McpSession = harness.session()
        attachment = base64.b64encode(b"x" * 6 * 1024 * 1024).decode()
        # No mail server in this test: the call gets past the HTTP body limit and fails later.
        with pytest.raises(ToolFailed) as failure:
            session.call(
                "send_email",
                to=["b@example.org"],
                subject="big",
                body_text="x",
                attachments=[
                    {
                        "filename": "a.bin",
                        "content_base64": attachment,
                        "mime_type": "application/octet-stream",
                    }
                ],
            )
        assert "413" not in str(failure.value)
        assert "can't be reached" in str(failure.value)


def test_untrusted_host_header_does_not_change_metadata(harness: Harness) -> None:
    data = harness.client.get(
        "/.well-known/oauth-authorization-server",
        headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example"},
    ).json()
    assert data["issuer"] == BASE_URL
    assert all("evil" not in str(v) for v in data.values())


def test_no_secrets_in_audit_or_errors_on_failures(harness: Harness) -> None:
    client_id = harness.register()["client_id"]
    harness.client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "mcp_rt_guess",
            "client_id": client_id,
        },
    )
    log: Any = harness.audit_stream.getvalue()
    assert "mcp_rt_guess" not in log
