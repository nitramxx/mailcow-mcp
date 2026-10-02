from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from mailcow_mcp import __version__, cli
from mailcow_mcp.broker import create_broker_app


def test_generate_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["generate-key"]) == 0
    key = capsys.readouterr().out.strip()
    Fernet(key)


def test_serve_refuses_to_start_on_invalid_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("PUBLIC_URL", "ENC_KEY", "TRUSTED_PROXIES", "MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    assert cli.main(["serve"]) == cli.EXIT_CONFIG
    err = capsys.readouterr().err
    assert err.startswith("mailcow-mcp: invalid app configuration")
    assert "PUBLIC_URL: required" in err


def test_broker_refuses_to_start_on_invalid_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MAILCOW_API_KEY", raising=False)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    assert cli.main(["broker"]) == cli.EXIT_CONFIG
    assert "MAILCOW_API_KEY: required" in capsys.readouterr().err


def test_serve_refuses_missing_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = {
        "MODE": "generic",
        "PUBLIC_URL": "https://mcp.example.org",
        "ENC_KEY": Fernet.generate_key().decode(),
        "TRUSTED_PROXIES": "127.0.0.1",
        "DATA_DIR": str(tmp_path / "missing"),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    assert cli.main(["serve"]) == cli.EXIT_CONFIG
    assert "does not exist" in capsys.readouterr().err


def test_serve_starts_with_valid_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env = {
        "MODE": "generic",
        "PUBLIC_URL": "https://mcp.example.org",
        "ENC_KEY": Fernet.generate_key().decode(),
        "TRUSTED_PROXIES": "172.22.1.0/24",
        "DATA_DIR": str(tmp_path),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: calls.append(kwargs))
    assert cli.main(["serve"]) == 0
    assert calls[0]["port"] == 8090
    assert calls[0]["forwarded_allow_ips"] == ["172.22.1.0/24"]


def test_healthcheck_fails_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PORT", raising=False)
    assert cli.main(["healthcheck", "--port", "1"]) == 1


def test_broker_healthz(tmp_path: Path) -> None:
    from mailcow_mcp.config import load_broker_config

    config = load_broker_config(
        {
            "MAILCOW_API_URL": "https://nginx-mailcow",
            "TLS_SERVER_NAME": "mail.example.com",
            "MAILCOW_API_KEY": "key",
            "BROKER_SHARED_SECRET": Fernet.generate_key().decode(),
            "BROKER_SIGNING_KEY": Fernet.generate_key().decode(),
            "DATA_DIR": str(tmp_path),
        }
    )
    response = TestClient(create_broker_app(config)).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "role": "broker", "version": __version__}


def _data_env(monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> None:
    for name, value in {
        "MODE": "generic",
        "PUBLIC_URL": "http://localhost:8090",
        "ENC_KEY": Fernet.generate_key().decode(),
        "TRUSTED_PROXIES": "127.0.0.1",
        "DATA_DIR": str(data_dir),
    }.items():
        monkeypatch.setenv(name, value)


def test_migrate_users_clients_revoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from mailcow_mcp.db import Database

    from conftest import EMAIL, app_config, make_harness

    _data_env(monkeypatch, tmp_path)
    assert cli.main(["migrate"]) == 0
    assert "applied: 0001_oauth.sql" in capsys.readouterr().out
    assert cli.main(["migrate"]) == 0
    assert "up to date" in capsys.readouterr().out

    # Connect a mailbox through the real flow, on the same database file.
    for harness in make_harness(app_config(), db=Database.in_data_dir(tmp_path)):
        harness.tokens()

    assert cli.main(["users"]) == 0
    out = capsys.readouterr().out
    assert EMAIL in out and "Test Client" in out

    assert cli.main(["clients"]) == 0
    assert "Test Client" in capsys.readouterr().out

    assert cli.main(["revoke", EMAIL.upper()]) == 0
    assert f"disconnected {EMAIL} from 1 connection(s)" in capsys.readouterr().out
    db = Database.in_data_dir(tmp_path)
    assert db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]
    assert '"audit":"grant_revoke"' in (tmp_path / "audit.log").read_text()

    assert cli.main(["revoke", "not-an-address"]) == cli.EXIT_CONFIG
    assert cli.main(["revoke"]) == cli.EXIT_CONFIG
    assert cli.main(["revoke", "--all"]) == 0
    assert "disconnected 0 mailbox(es)" in capsys.readouterr().out
