"""Several mailboxes in one connection: add_mailbox links, choosing, removing, migrating."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from mailcow_mcp.config import generate_key
from mailcow_mcp.crypto import Box, hash_secret
from mailcow_mcp.db import Database, available_migrations
from mailcow_mcp.imap import LoginResult
from mailcow_mcp.lifecycle import drain_deprovision_queue
from mailcow_mcp.oauth import MAX_MAILBOXES_PER_GRANT

from conftest import (
    BASE_URL,
    EMAIL,
    FakeVerifier,
    Harness,
    McpSession,
    ToolFailed,
    app_config,
    form_value,
    make_harness,
)
from mailcow_fixtures import BrokerSetup, at_mailcow, connect, in_app, make_mailcow_harness
from mailserver_fixture import ALICE, BOB, MailServer, wait_for
from mock_mailcow import MockMailcow, RunningMailcow

OTHER = "other@example.org"


@pytest.fixture
def anyone() -> Iterator[Harness]:
    """Password sign-in that accepts any mailbox (the fake verifier says yes)."""
    yield from make_harness(app_config(), FakeVerifier(result=LoginResult.OK))


def add(harness: Harness, session: McpSession, email: str = OTHER, password: str = "secret") -> Any:
    """Ask for a link, open it, sign in with ``email``: the response to that."""
    link = session.call("add_mailbox")["url"]
    page = harness.client.get(link)
    assert page.status_code == 200, page.text
    return harness.client.post(
        "/connect",
        data={
            "code": form_value(page.text, "code"),
            "csrf": form_value(page.text, "csrf"),
            "action": "login",
            "email": email,
            "password": password,
        },
        follow_redirects=False,
    )


def addresses(session: McpSession) -> list[str]:
    return [m["address"] for m in session.call("list_mailboxes")["mailboxes"]]


def test_one_mailbox_needs_no_parameter(anyone: Harness) -> None:
    session = anyone.session()
    assert addresses(session) == [EMAIL]
    tools = {t["name"]: t for t in session.request("tools/list", {})["tools"]}
    assert "mailbox" in tools["list_messages"]["inputSchema"]["properties"]
    assert "mailbox" not in tools["list_messages"]["inputSchema"].get("required", [])


def test_add_a_mailbox_with_the_link(anyone: Harness) -> None:
    session = anyone.session()
    done = add(anyone, session)
    assert done.status_code == 200
    assert "Mailbox added" in done.text and OTHER in done.text
    assert addresses(session) == [EMAIL, OTHER]  # the same connection, nothing to reconnect


def test_the_page_names_the_connection(anyone: Harness) -> None:
    session = anyone.session()
    page = anyone.client.get(session.call("add_mailbox")["url"])
    assert "Test Client" in page.text and EMAIL in page.text


def test_with_several_mailboxes_tools_must_say_which(anyone: Harness) -> None:
    session = anyone.session()
    add(anyone, session)
    with pytest.raises(ToolFailed, match=r"2 mailboxes \(user@example.org, other@example.org\)"):
        session.call("list_folders")
    with pytest.raises(ToolFailed, match="isn't connected"):
        session.call("list_folders", mailbox="nobody@example.org")


def test_links_work_once_and_expire(anyone: Harness) -> None:
    session = anyone.session()
    link = session.call("add_mailbox")["url"]
    page = anyone.client.get(link)
    form = {"code": form_value(page.text, "code"), "csrf": form_value(page.text, "csrf")}
    login = {"action": "login", "email": OTHER, "password": "x"}
    assert anyone.client.post("/connect", data={**form, **login}).status_code == 200
    again = anyone.client.post("/connect", data={**form, **login, "email": "third@example.org"})
    assert again.status_code == 400 and "expired" in again.text
    late = session.call("add_mailbox")["url"]
    anyone.clock.advance(16 * 60)
    assert "expired" in anyone.client.get(late).text


def test_the_form_only_works_in_the_browser_that_opened_it(anyone: Harness) -> None:
    session = anyone.session()
    page = anyone.client.get(session.call("add_mailbox")["url"])
    anyone.client.cookies.clear()
    response = anyone.client.post(
        "/connect",
        data={
            "code": form_value(page.text, "code"),
            "csrf": form_value(page.text, "csrf"),
            "action": "login",
            "email": OTHER,
            "password": "x",
        },
    )
    assert response.status_code == 400
    assert addresses(session) == [EMAIL]


def test_cancel_and_already_connected(anyone: Harness) -> None:
    session = anyone.session()
    page = anyone.client.get(session.call("add_mailbox")["url"])
    cancelled = anyone.client.post(
        "/connect",
        data={
            "code": form_value(page.text, "code"),
            "csrf": form_value(page.text, "csrf"),
            "action": "deny",
        },
    )
    assert "Nothing was added" in cancelled.text
    again = add(anyone, session, email=EMAIL)
    assert again.status_code == 409 and "already connected" in again.text
    assert addresses(session) == [EMAIL]


def test_the_number_of_mailboxes_is_limited(anyone: Harness) -> None:
    session = anyone.session()
    for i in range(MAX_MAILBOXES_PER_GRANT - 1):
        add(anyone, session, email=f"m{i}@example.org")
    with pytest.raises(ToolFailed, match="already has"):
        session.call("add_mailbox")


def test_remove_a_mailbox(anyone: Harness) -> None:
    session = anyone.session()
    add(anyone, session)
    removed = session.call("remove_mailbox", mailbox=OTHER)
    assert removed == {"removed": OTHER, "remaining": [EMAIL]}
    assert addresses(session) == [EMAIL]
    with pytest.raises(ToolFailed, match="only mailbox"):
        session.call("remove_mailbox", mailbox=EMAIL)


def test_revoking_a_mailbox_keeps_the_connection(anyone: Harness) -> None:
    session = anyone.session()
    add(anyone, session)
    assert anyone.provider.revoke_mailbox(OTHER) == 1  # e.g. the CLI's revoke
    assert addresses(session) == [EMAIL]


def test_ending_the_connection_ends_all(anyone: Harness) -> None:
    client_id, tokens = anyone.tokens()
    session = McpSession(anyone.client, tokens["access_token"])
    add(anyone, session)
    anyone.client.post("/revoke", data={"token": tokens["refresh_token"], "client_id": client_id})
    assert anyone.db.one("SELECT count(*) AS n FROM grant_mailboxes")["n"] == 0  # type: ignore[index]


def test_link_points_at_this_server(anyone: Harness) -> None:
    url = anyone.session().call("add_mailbox")["url"]
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}" == "http://localhost:8090"
    assert parts.path == "/connect"


def test_migration_keeps_existing_connections(tmp_path: Path) -> None:
    db = Database.in_data_dir(tmp_path)
    for number, _, sql in available_migrations()[:3]:
        db.conn.executescript(sql)
        db.conn.execute(f"PRAGMA user_version = {number}")
    box = Box(generate_key())
    db.execute("INSERT INTO mailboxes VALUES (1, 'a@example.org', 1, 1)")
    db.execute("INSERT INTO clients VALUES ('c', 'Claude', '{}', NULL, NULL, 1, 1)")
    db.execute(
        "INSERT INTO grants (id, client_id, mailbox_id, login_method, credential_enc, scopes,"
        " resource, created_at, last_used_at, app_password_id, capability_enc)"
        " VALUES (7, 'c', 1, 'mailcow', ?, '', 'https://x/mcp', 5, 6, 42, ?)",
        (box.encrypt("app-password"), box.encrypt("cap1.x.y")),
    )
    db.execute("INSERT INTO tokens VALUES (?, 7, 'refresh', 99, NULL)", (hash_secret("mcp_rt_x"),))
    db.migrate()
    row = db.one("SELECT * FROM grant_mailboxes")
    assert row is not None
    assert (row["grant_id"], row["mailbox_id"], row["app_password_id"]) == (7, 1, 42)
    assert box.decrypt(row["capability_enc"]) == "cap1.x.y"
    assert db.one("SELECT count(*) AS n FROM tokens")["n"] == 1  # type: ignore[index]
    grant = db.one("SELECT * FROM grants")
    assert grant is not None and grant["id"] == 7 and "credential_enc" not in list(grant.keys())
    assert db.one("PRAGMA foreign_keys")[0] == 1  # type: ignore[index]


# --- with a real mail server ---------------------------------------------------


@pytest.mark.integration
def test_two_real_mailboxes(mailserver: MailServer) -> None:
    for harness in make_harness(app_config(**mailserver.env()), real_login=True):
        session = harness.session(*ALICE)
        done = add(harness, session, email=BOB[0], password=BOB[1])
        assert done.status_code == 200, done.text
        alice = session.call("list_folders", mailbox=ALICE[0])
        bob = session.call("list_folders", mailbox=BOB[0])
        assert alice["mailbox"] == ALICE[0] and bob["mailbox"] == BOB[0]
        sent = session.call(
            "send_email",
            mailbox=BOB[0],
            to=[ALICE[0]],
            subject="from bob's mailbox",
            body_text="hi",
        )
        assert sent["mailbox"] == BOB[0]
        received = wait_for(mailserver, ALICE, sent["message_id"])
        assert received["From"] == BOB[0]
        # Bob's password stops working: only Bob's mailbox leaves the connection.
        harness.db.execute(
            "UPDATE grant_mailboxes SET credential_enc = ? WHERE mailbox_id ="
            " (SELECT id FROM mailboxes WHERE username = ?)",
            (harness.provider.box.encrypt("wrong"), BOB[0]),
        )
        with pytest.raises(ToolFailed, match="disconnected"):
            session.call("list_folders", mailbox=BOB[0])
        assert addresses(session) == [ALICE[0]]
        assert session.call("list_folders")["mailbox"] == ALICE[0]  # one left: no parameter


@pytest.mark.integration
def test_wrong_password_on_the_connect_page(mailserver: MailServer) -> None:
    for harness in make_harness(app_config(**mailserver.env()), real_login=True):
        session = harness.session(*ALICE)
        wrong = add(harness, session, email=BOB[0], password="nope")
        assert wrong.status_code == 401 and "Wrong email address or password" in wrong.text
        assert addresses(session) == [ALICE[0]]


# --- mailcow mode ----------------------------------------------------------------


def test_add_with_mailcow(
    running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, broker: BrokerSetup
) -> None:
    mailcow.names = {"alice@example.test": "Alice", "bob@example.test": "Bob"}
    mailcow.aliases = [
        {"id": 1, "address": "sales@example.test", "goto": "bob@example.test", "active": "1"}
    ]
    for app in make_mailcow_harness(running_mailcow, certs, broker):
        client_id, tokens = connect(app, certs)
        session = McpSession(app.client, tokens["access_token"])
        page = app.client.get(session.call("add_mailbox")["url"])
        assert "private window" in page.text
        mailcow.login_as = "bob@example.test"  # the user signs in at mailcow as Bob
        start = app.client.post(
            "/connect",
            data={
                "code": form_value(page.text, "code"),
                "csrf": form_value(page.text, "csrf"),
                "action": "mailcow",
            },
            follow_redirects=False,
        )
        assert start.status_code == 303
        back = at_mailcow(start.headers["location"], certs)
        done = app.client.get(back.headers["location"].removeprefix(BASE_URL))
        assert done.status_code == 200 and "Mailbox added" in done.text, done.text
        listed = session.call("list_mailboxes")["mailboxes"]
        assert listed == [
            {"address": "alice@example.test", "name": "Alice", "aliases": [], "sign_in": "mailcow"},
            {
                "address": "bob@example.test",
                "name": "Bob",
                "aliases": ["sales@example.test"],
                "sign_in": "mailcow",
            },
        ]
        assert len(mailcow.app_passwords) == 2  # one per mailbox
        # The same mailbox again: its new app password is deleted at once.
        page = app.client.get(session.call("add_mailbox")["url"])
        start = app.client.post(
            "/connect",
            data={
                "code": form_value(page.text, "code"),
                "csrf": form_value(page.text, "csrf"),
                "action": "mailcow",
            },
            follow_redirects=False,
        )
        back = at_mailcow(start.headers["location"], certs)
        again = app.client.get(back.headers["location"].removeprefix(BASE_URL))
        assert again.status_code == 409
        assert len(mailcow.app_passwords) == 2
        # Disconnecting the app deletes both app passwords.
        app.client.post("/revoke", data={"token": tokens["refresh_token"], "client_id": client_id})
        assert in_app(app, drain_deprovision_queue, broker) == 2
        assert mailcow.app_passwords == []


def test_a_new_link_replaces_the_previous_one(anyone: Harness) -> None:
    session = anyone.session()
    first = session.call("add_mailbox")["url"]
    session.call("add_mailbox")
    assert "expired" in anyone.client.get(first).text
