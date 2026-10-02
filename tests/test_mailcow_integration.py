"""mailcow mode end to end: mailcow sign-in → app password → real Dovecot/Postfix."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import Harness, McpSession, ToolFailed, query_of
from mailcow_fixtures import BrokerSetup, make_mailcow_harness
from mailserver_fixture import MailServer
from mock_mailcow import MockMailcow, RunningMailcow
from test_mailcow_login import sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
def app(
    running_mailcow: RunningMailcow,
    certs: Path,
    broker: BrokerSetup,
    mailserver: MailServer,
    mailcow: MockMailcow,
) -> Iterator[Harness]:
    mailcow.on_app_password = mailserver.set_app_password
    yield from make_mailcow_harness(
        running_mailcow, certs, broker, real_login=True, env=mailserver.env()
    )


def connect(app: Harness, certs: Path) -> McpSession:
    client_id, response = sign_in(app, certs)
    assert response.status_code == 303, response.text
    code = query_of(response.headers["location"])["code"]
    tokens = app.exchange(client_id, code, app.verifier_value).json()  # type: ignore[attr-defined]
    return McpSession(app.client, tokens["access_token"])


def test_app_password_works_and_deleting_it_disconnects(
    app: Harness, mailcow: MockMailcow, certs: Path
) -> None:
    session = connect(app, certs)
    folders = {f["name"] for f in session.call("list_folders")["folders"]}
    assert {"INBOX", "Sent", "Junk"} <= folders
    sent = session.call(
        "send_email", to=["bob@example.test"], subject="via app password", body_text="hi"
    )
    assert sent["accepted"] == ["bob@example.test"]

    # The user deletes the app password in mailcow.
    assert len(mailcow.passwords_of("alice@example.test")) == 1
    mailcow.app_passwords.clear()
    assert mailcow.on_app_password is not None
    mailcow.on_app_password("alice@example.test", None)
    with pytest.raises(ToolFailed, match="reconnect the app"):
        session.call("list_folders")
    assert app.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]
    assert app.db.one("SELECT count(*) AS n FROM deprovision_queue")["n"] == 1  # type: ignore[index]
    with pytest.raises(ToolFailed, match="HTTP 401"):
        session.call("list_folders")
