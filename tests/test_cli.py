from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from mailcow_mcp import cli
from mailcow_mcp.web import create_app


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


@pytest.mark.parametrize("role", ["app", "broker"])
def test_healthz(role: str) -> None:
    response = TestClient(create_app(role)).get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["role"] == role
