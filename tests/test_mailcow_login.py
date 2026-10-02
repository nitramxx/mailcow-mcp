"""Sign in with mailcow: consent page → mailcow → broker → client, and the revocation lifecycle."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from mailcow_mcp.imap import LoginResult
from mailcow_mcp.lifecycle import drain_deprovision_queue, reconcile
from mailcow_mcp.ratelimit import RateLimiter

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    FakeVerifier,
    Harness,
    McpSession,
    ToolFailed,
    form_value,
    pkce_pair,
    query_of,
)
from mailcow_fixtures import (
    BrokerSetup,
    at_mailcow,
    connect,
    in_app,
    make_mailcow_harness,
    sign_in,
    start,
    state_cookies,
)
from mock_mailcow import MockMailcow, RunningMailcow


@pytest.fixture
def app(running_mailcow: RunningMailcow, certs: Path, broker: BrokerSetup) -> Iterator[Harness]:
    yield from make_mailcow_harness(running_mailcow, certs, broker)


def test_healthz_reports_the_broker(app: Harness) -> None:
    assert app.client.get("/healthz").json()["broker"] == "ok"


def test_consent_page_offers_mailcow(app: Harness, running_mailcow: RunningMailcow) -> None:
    client_id = app.register()["client_id"]
    _, challenge = pkce_pair()
    page = app.client.get(app.authorize(client_id, challenge))
    assert "Sign in with mailcow" in page.text
    assert "never sees your password" in page.text
    assert 'type="password"' not in page.text
    assert running_mailcow.url in page.headers["content-security-policy"]


def test_internal_url_for_the_token_exchange(
    running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, broker: BrokerSetup
) -> None:
    # The browser uses the public URL; the app talks to nginx directly (no hairpin NAT).
    public = "https://mail.example.test"
    for app in make_mailcow_harness(
        running_mailcow, certs, broker, MAILCOW_URL=public, MAILCOW_INTERNAL_URL=running_mailcow.url
    ):
        _, url, _ = start(app)
        assert url.startswith(f"{public}/oauth/authorize?")
        back = at_mailcow(running_mailcow.url + url.removeprefix(public), certs)
        response = app.client.get(
            back.headers["location"].removeprefix(BASE_URL), follow_redirects=False
        )
        assert response.status_code == 303, response.text
    assert mailcow.app_passwords


def test_redirect_to_mailcow(app: Harness, running_mailcow: RunningMailcow) -> None:
    _, url, _ = start(app)
    assert url.startswith(f"{running_mailcow.url}/oauth/authorize?")
    params = query_of(url)
    assert params["client_id"] == "0123456789ab"
    assert params["redirect_uri"] == f"{BASE_URL}/oauth/mailcow/callback"
    assert params["scope"] == "profile"
    assert params["state"] in state_cookies(app).values()


def test_full_sign_in(app: Harness, mailcow: MockMailcow, certs: Path) -> None:
    client_id, response, verifier = sign_in(app, certs)
    assert response.status_code == 303
    assert response.headers["location"].startswith(REDIRECT_URI + "?code=")
    assert state_cookies(app) == {}  # state cookie cleared
    (password,) = mailcow.passwords_of("alice@example.test")
    assert password["name"].startswith("MCP: Claude (")
    grant = app.db.one(
        "SELECT login_method, app_password_id, capability_enc, credential_enc FROM grant_mailboxes"
    )
    assert grant is not None
    assert grant["login_method"] == "mailcow"
    assert grant["app_password_id"] == password["id"]
    assert grant["capability_enc"] and "cap1." not in grant["capability_enc"]  # stored encrypted
    # The app password was checked with the mail server before the client got a code.
    username, app_password = app.verifier.calls[-1]
    assert username == "alice@example.test" and len(app_password) >= 32
    assert mailcow.tokens  # the mailcow token went to the broker...
    dump = "\n".join(app.db.conn.iterdump())
    for token in mailcow.tokens:
        assert token not in dump  # ...and was not stored
    params = query_of(response.headers["location"])
    tokens = app.exchange(client_id, params["code"], verifier).json()
    assert app.mcp(tokens["access_token"]).status_code == 200


def test_state_must_match_the_cookie(app: Harness, certs: Path) -> None:
    _, url, _ = start(app)
    back = at_mailcow(url, certs)
    callback = back.headers["location"].removeprefix(BASE_URL)
    (name,) = state_cookies(app)
    app.client.cookies.set(name, "attacker-state")
    assert app.client.get(callback).status_code == 400
    app.client.cookies.clear()
    assert app.client.get(callback).status_code == 400


def test_declined_at_mailcow(app: Harness, mailcow: MockMailcow, certs: Path) -> None:
    mailcow.deny = True
    response = sign_in(app, certs).response
    assert response.status_code == 400
    assert "cancelled" in response.text
    assert mailcow.app_passwords == []


def test_retry_after_a_failed_callback(app: Harness, mailcow: MockMailcow, certs: Path) -> None:
    mailcow.deny = True
    response = sign_in(app, certs).response
    assert response.status_code == 400
    # The error page offers "Sign in with mailcow" again, and it works.
    mailcow.deny = False
    retry = app.client.post(
        "/login",
        data={
            "request": form_value(response.text, "request"),
            "resume": form_value(response.text, "resume"),
            "csrf": form_value(response.text, "csrf"),
            "action": "mailcow",
        },
        follow_redirects=False,
    )
    assert retry.status_code == 303, retry.text
    back = at_mailcow(retry.headers["location"], certs)
    done = app.client.get(back.headers["location"].removeprefix(BASE_URL), follow_redirects=False)
    assert done.status_code == 303
    assert done.headers["location"].startswith(REDIRECT_URI + "?code=")


def test_allowed_domains_apply(
    running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, broker: BrokerSetup
) -> None:
    for app in make_mailcow_harness(running_mailcow, certs, broker, ALLOWED_DOMAINS="other.test"):
        response = sign_in(app, certs).response
        assert response.status_code == 403
        assert mailcow.app_passwords == []  # created, then deleted again
        assert app.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]


def test_app_password_that_does_not_work_is_removed(
    running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, broker: BrokerSetup
) -> None:
    verifier = FakeVerifier(result=LoginResult.INVALID)
    for app in make_mailcow_harness(running_mailcow, certs, broker, verifier=verifier):
        response = sign_in(app, certs).response
        assert response.status_code == 502
        # It was created and checked, then deleted again (not: never created).
        assert [user for user, _ in verifier.calls] == ["alice@example.test"]
        assert ("POST", "/api/v1/add/app-passwd") in mailcow.requests
        assert ("POST", "/api/v1/delete/app-passwd") in mailcow.requests
        assert mailcow.app_passwords == []


def test_revoking_deletes_the_app_password(
    app: Harness, mailcow: MockMailcow, broker: BrokerSetup, certs: Path
) -> None:
    client_id, tokens = connect(app, certs)
    assert len(mailcow.app_passwords) == 1
    app.client.post("/revoke", data={"token": tokens["refresh_token"], "client_id": client_id})
    assert app.db.one("SELECT count(*) AS n FROM deprovision_queue")["n"] == 1  # type: ignore[index]
    assert in_app(app, drain_deprovision_queue, broker) == 1
    assert mailcow.app_passwords == []
    assert app.db.one("SELECT count(*) AS n FROM deprovision_queue")["n"] == 0  # type: ignore[index]


def test_expired_connection_deletes_the_app_password(
    app: Harness, mailcow: MockMailcow, broker: BrokerSetup, certs: Path
) -> None:
    connect(app, certs)
    app.clock.advance(31 * 86400)
    app.provider.purge_expired()
    in_app(app, drain_deprovision_queue, broker)
    assert mailcow.app_passwords == []


def test_reconcile_from_the_app(
    app: Harness, mailcow: MockMailcow, broker: BrokerSetup, certs: Path
) -> None:
    connect(app, certs)
    mailcow.add_existing_app_password("alice@example.test", "MCP: Lost (2026-01-01, 0000)")
    mailcow.add_existing_app_password("alice@example.test", "Phone")
    assert in_app(app, reconcile, broker) == 1
    assert sorted(p["name"][:9] for p in mailcow.app_passwords) == ["MCP: Clau", "Phone"]


def test_audit_never_contains_secrets(
    app: Harness, broker: BrokerSetup, mailcow: MockMailcow, certs: Path
) -> None:
    connect(app, certs)
    logs = app.audit_stream.getvalue() + broker.audit.getvalue()
    for token in mailcow.tokens:
        assert token not in logs
    assert "cap1." not in logs
    events = [json.loads(line) for line in logs.splitlines()]
    assert {"provision", "login"} <= {e["audit"] for e in events}


def test_cli_revoke_deprovisions(
    app: Harness, mailcow: MockMailcow, broker: BrokerSetup, certs: Path
) -> None:
    connect(app, certs)
    assert app.provider.revoke_mailbox("alice@example.test") == 1
    in_app(app, drain_deprovision_queue, broker)
    assert mailcow.app_passwords == []


def test_tools_fail_cleanly_when_the_mail_server_is_unreachable(
    app: Harness, certs: Path, broker: BrokerSetup
) -> None:
    _, tokens = connect(app, certs)
    session = McpSession(app.client, tokens["access_token"])
    assert session.request("tools/list", {})["tools"]
    with pytest.raises(ToolFailed, match="can't be reached"):
        session.call("read_message", folder="INBOX", uid=1)  # no IMAP server in this test


def _callback(app: Harness, **query: str) -> Any:
    """mailcow's redirect back, with this browser's state."""
    _, mailcow_url, _ = start(app)
    state = query_of(mailcow_url)["state"]
    return app.client.get(
        "/oauth/mailcow/callback", params={"state": state, **query}, follow_redirects=False
    )


@pytest.mark.parametrize("code", ["", "x" * 1025])
def test_callback_without_a_usable_code(app: Harness, mailcow: MockMailcow, code: str) -> None:
    response = _callback(app, code=code)
    assert response.status_code == 400
    assert "Signing in with mailcow didn" in response.text
    assert mailcow.app_passwords == []


def test_callback_with_a_code_mailcow_refuses(app: Harness, mailcow: MockMailcow) -> None:
    response = _callback(app, code="not-issued-by-mailcow")
    assert response.status_code == 502
    assert mailcow.app_passwords == []
    assert '"result":"mailcow_failed"' in app.audit_stream.getvalue()


def test_callback_replay(app: Harness, mailcow: MockMailcow, certs: Path) -> None:
    _, mailcow_url, _ = start(app)
    back = at_mailcow(mailcow_url, certs)
    callback = back.headers["location"].removeprefix(BASE_URL)
    assert app.client.get(callback, follow_redirects=False).status_code == 303
    again = app.client.get(callback, follow_redirects=False)
    assert again.status_code == 400  # the state cookie is gone, and so is the sign-in
    assert len(mailcow.app_passwords) == 1


def test_broker_refusal_during_sign_in(
    app: Harness, mailcow: MockMailcow, certs: Path, broker: BrokerSetup
) -> None:
    broker.broker.provision_limit = RateLimiter(0, 3600)
    response = sign_in(app, certs).response
    assert response.status_code == 502
    assert "Signing in with mailcow didn" in response.text
    assert mailcow.app_passwords == []


def test_broker_unreachable_during_sign_in(
    app: Harness,
    mailcow: MockMailcow,
    certs: Path,
    broker: BrokerSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unreachable(*args: object, **kwargs: object) -> None:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(broker.client._http, "post", unreachable)
    response = sign_in(app, certs).response
    assert response.status_code == 503
    assert "mailcow can" in response.text


def test_two_tabs_can_sign_in_at_once(app: Harness, mailcow: MockMailcow, certs: Path) -> None:
    _, first_url, _ = start(app)
    _, second_url, _ = start(app)  # another tab, before the first returns from mailcow
    for url in (first_url, second_url):
        back = at_mailcow(url, certs)
        done = app.client.get(
            back.headers["location"].removeprefix(BASE_URL), follow_redirects=False
        )
        assert done.status_code == 303, done.text
    assert len(mailcow.app_passwords) == 2
