"""Fixtures for mailcow mode: mock mailcow over TLS, an in-process broker, the app."""

from __future__ import annotations

import io
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from mock_mailcow import API_KEY, CLIENT_ID, CLIENT_SECRET, MockMailcow, RunningMailcow, run_mailcow
from starlette.applications import Starlette

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.broker import Broker, create_broker_app
from mailcow_mcp.broker_client import BrokerClient
from mailcow_mcp.config import BrokerConfig, generate_key, load_broker_config
from mailcow_mcp.db import Database
from mailcow_mcp.imap import LoginResult
from mailcow_mcp.mailcow_login import MailcowOAuth
from mailcow_mcp.tls import client_context

from conftest import BASE_URL, FakeVerifier, Harness, app_config, make_harness
from mailserver_fixture import SERVER_NAME, make_certificates

SHARED_SECRET = generate_key()


@pytest.fixture(scope="session")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("mailcow-certs")
    make_certificates(directory)
    return directory


@pytest.fixture(scope="session")
def running_mailcow(certs: Path) -> Iterator[RunningMailcow]:
    yield from run_mailcow(certs)


@pytest.fixture
def mailcow(running_mailcow: RunningMailcow) -> Iterator[MockMailcow]:
    mock = running_mailcow.mock
    fresh = MockMailcow()
    for name in fresh.__dataclass_fields__:
        setattr(mock, name, getattr(fresh, name))
    mock.redirect_uri = f"{BASE_URL}/oauth/mailcow/callback"
    yield mock


@dataclass
class BrokerSetup:
    config: BrokerConfig
    app: Starlette
    broker: Broker
    audit: io.StringIO
    client: BrokerClient

    async def call(
        self, operation: str, secret: str | None = SHARED_SECRET, **body: Any
    ) -> httpx.Response:
        headers = {"X-Broker-Secret": secret} if secret is not None else {}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://broker"
        ) as http:
            return await http.post(f"/v1/{operation}", json=body, headers=headers)


def make_broker(
    running: RunningMailcow, certs: Path, tmp_path: Path, **overrides: str
) -> BrokerSetup:
    env = {
        "MAILCOW_API_URL": running.url,
        "TLS_SERVER_NAME": SERVER_NAME,
        "TLS_CA_FILE": str(certs / "ca.crt"),
        "MAILCOW_API_KEY": API_KEY,
        "BROKER_SHARED_SECRET": SHARED_SECRET,
        "BROKER_SIGNING_KEY": generate_key(),
        "DATA_DIR": str(tmp_path),
    }
    env.update(overrides)
    config = load_broker_config(env)
    stream = io.StringIO()
    app = create_broker_app(config, db=Database(":memory:"), audit=AuditLog(None, stream=stream))
    client = BrokerClient("http://broker", SHARED_SECRET, transport=httpx.ASGITransport(app=app))
    return BrokerSetup(config, app, app.state.broker, stream, client)


@pytest.fixture
def broker(
    running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, tmp_path: Path
) -> BrokerSetup:
    return make_broker(running_mailcow, certs, tmp_path)


def mailcow_app_env(running: RunningMailcow, certs: Path, **overrides: str) -> dict[str, str]:
    env = {
        "MODE": "mailcow",
        "MAILCOW_URL": running.url,
        "MAILCOW_OAUTH_CLIENT_ID": CLIENT_ID,
        "MAILCOW_OAUTH_CLIENT_SECRET": CLIENT_SECRET,
        "BROKER_SHARED_SECRET": SHARED_SECRET,
        "TLS_SERVER_NAME": SERVER_NAME,
        "TLS_CA_FILE": str(certs / "ca.crt"),
    }
    env.update(overrides)
    return env


def make_mailcow_harness(
    running: RunningMailcow,
    certs: Path,
    broker: BrokerSetup,
    *,
    verifier: FakeVerifier | None = None,
    real_login: bool = False,
    env: dict[str, str] | None = None,
    **overrides: str,
) -> Iterator[Harness]:
    config = app_config(**mailcow_app_env(running, certs, **(env or {}), **overrides))
    oauth = MailcowOAuth(
        config, verify=client_context(server_name=SERVER_NAME, ca_file=certs / "ca.crt")
    )
    yield from make_harness(
        config,
        verifier or FakeVerifier(result=LoginResult.OK),
        real_login=real_login,
        broker=broker.client,
        mailcow_oauth=oauth,
    )
