"""mailcow extras: quarantine, delivery status, own addresses, contacts."""

from __future__ import annotations

import imaplib
import time
from collections.abc import Iterator
from email.message import EmailMessage
from email.policy import default as default_policy
from pathlib import Path

import httpx
import pytest
import radicale.config
from a2wsgi import WSGIMiddleware
from mailcow_fixtures import BrokerSetup, make_mailcow_harness
from mock_mailcow import MockMailcow, RunningMailcow
from radicale.app import Application
from test_mailcow_login import in_app, sign_in

from mailcow_mcp.config import generate_key, load_app_config
from mailcow_mcp.contacts import CardDav, parse_vcards
from mailcow_mcp.errors import MailError

from conftest import Harness, McpSession, ToolFailed, app_config, make_harness, query_of
from mailserver_fixture import ALICE, MailServer

CONTACTS = [
    "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:1\r\nFN:Jan Novák\r\nN:Novák;Jan;;;\r\nEMAIL;TYPE=work:jan@firma.cz\r\nORG:Firma s.r.o.\r\nTEL:+420 777 000 000\r\nEND:VCARD\r\n",
    "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:2\r\nFN:Eva Svobodová\r\nEMAIL:eva@example.org\r\nEMAIL:eva.s@firma.cz\r\nEND:VCARD\r\n",
    "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:3\r\nFN:Bob\r\nEMAIL:bob@example.test\r\nEND:VCARD\r\n",
]


def radicale_transport(tmp_path: Path, user: str, password: str) -> httpx.ASGITransport:
    """A Radicale CardDAV server with one address book of CONTACTS for ``user``."""
    htpasswd = tmp_path / "htpasswd"
    htpasswd.write_text(f"{user}:{password}\n")
    configuration = radicale.config.load()
    configuration.update(
        {
            "storage": {"filesystem_folder": str(tmp_path / "collections")},
            "auth": {
                "type": "htpasswd",
                "htpasswd_filename": str(htpasswd),
                "htpasswd_encryption": "plain",
            },
            "rights": {"type": "owner_only"},
        },
        "test",
        privileged=True,
    )
    application = Application(configuration)
    transport = httpx.ASGITransport(app=WSGIMiddleware(application))  # type: ignore[arg-type]
    with httpx.Client(
        transport=httpx.WSGITransport(app=application),
        auth=(user, password),
        base_url="https://contacts.test",
    ) as http:
        book = f"/{user}/contacts/"
        response = http.request(
            "MKCOL",
            book,
            content=(
                '<?xml version="1.0"?><mkcol xmlns="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">'
                "<set><prop><resourcetype><collection/><CR:addressbook/></resourcetype>"
                "<displayname>Contacts</displayname></prop></set></mkcol>"
            ),
        )
        assert response.status_code == 201, response.text
        for index, card in enumerate(CONTACTS):
            put = http.put(
                f"{book}{index}.vcf", content=card, headers={"Content-Type": "text/vcard"}
            )
            assert put.status_code == 201, put.text
    return transport


def test_vcard_parsing() -> None:
    folded = "BEGIN:VCARD\r\nFN:Very Long\r\n  Name\r\nitem1.EMAIL;TYPE=INTERNET:a@b.c\r\nORG:A\\, B;Sales\r\nEND:VCARD\r\nBEGIN:VCARD\r\nN:Doe;John;;;\r\nEND:VCARD\r\n"
    first, second = parse_vcards(folded)
    assert first.name == "Very Long Name"
    assert first.emails == ["a@b.c"]
    assert first.organisation == "A, B, Sales"
    assert second.name == "John Doe"


def test_vcard_escapes_and_empty_name_parts() -> None:
    (card,) = parse_vcards("BEGIN:VCARD\r\nN:;Jan;Karel;;\r\nORG:C:\\\\new\r\nEND:VCARD\r\n")
    assert card.name == "Jan"
    assert card.organisation == "C:\\new"


def test_carddav_via_internal_url() -> None:
    config = load_app_config(
        {
            "PUBLIC_URL": "https://mcp.mail.example.com",
            "MAILCOW_URL": "https://mail.example.com",
            "MAILCOW_INTERNAL_URL": "https://nginx-mailcow",
            "MAILCOW_OAUTH_CLIENT_ID": "client-id",
            "MAILCOW_OAUTH_CLIENT_SECRET": "client-secret-value",
            "BROKER_SHARED_SECRET": "s" * 32,
            "TLS_SERVER_NAME": "mail.example.com",
            "ENC_KEY": generate_key(),
            "TRUSTED_PROXIES": "172.22.1.0/24",
        }
    )
    carddav = CardDav.from_config(config)
    assert carddav.url == "https://nginx-mailcow/SOGo/dav/"
    assert carddav.headers == {"Host": "mail.example.com"}
    assert getattr(carddav.verify, "fixed_server_name", None) == "mail.example.com"


def _dav_server(principal: str, seen: list[str]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        href = principal if len(seen) == 1 else "/SOGo/dav/u/Contacts/"
        body = (
            '<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
            "<d:response><d:propstat><d:prop><d:current-user-principal>"
            f"<d:href>{href}</d:href></d:current-user-principal></d:prop></d:propstat>"
            "</d:response></d:multistatus>"
        )
        return httpx.Response(207, text=body)

    return httpx.MockTransport(handle)


@pytest.mark.anyio
async def test_carddav_maps_public_hrefs_to_the_internal_url() -> None:
    seen: list[str] = []
    transport = _dav_server("https://mail.example.com/SOGo/dav/u/", seen)
    carddav = CardDav(
        "https://nginx-mailcow/SOGo/dav/", host_header="mail.example.com", transport=transport
    )
    assert await carddav.search("u", "pw", "jan") == []
    assert seen[1] == "https://nginx-mailcow/SOGo/dav/u/"
    assert all(url.startswith("https://nginx-mailcow/") for url in seen)


@pytest.mark.anyio
async def test_carddav_never_sends_credentials_elsewhere() -> None:
    seen: list[str] = []
    transport = _dav_server("https://evil.example/collect/", seen)
    carddav = CardDav("https://contacts.test/dav/", transport=transport)
    with pytest.raises(MailError, match="another server"):
        await carddav.search("u", "pw", "jan")
    assert all(url.startswith("https://contacts.test/") for url in seen)


class TestContactsGeneric:
    @pytest.fixture
    def app(self, tmp_path: Path) -> Iterator[Harness]:
        transport = radicale_transport(tmp_path, "user@example.org", "correct horse battery staple")
        config = app_config(CARDDAV_URL="https://contacts.test/")
        yield from make_harness(
            config, carddav=CardDav(config.carddav_url or "", transport=transport)
        )

    def test_find_contacts(self, app: Harness) -> None:
        session = app.session()
        by_name = session.call("find_contacts", query="novák")
        assert by_name["contacts"] == [
            {
                "name": "Jan Novák",
                "emails": ["jan@firma.cz"],
                "organisation": "Firma s.r.o.",
                "phones": ["+420 777 000 000"],
            }
        ]
        by_domain = session.call("find_contacts", query="firma.cz")
        assert sorted(c["name"] for c in by_domain["contacts"]) == ["Eva Svobodová", "Jan Novák"]
        assert session.call("find_contacts", query="nobody")["contacts"] == []
        assert "untrusted" in by_name["notice"]

    def test_wrong_credentials_dont_sign_out_in_generic_mode(self, tmp_path: Path) -> None:
        transport = radicale_transport(tmp_path, "someone-else@example.org", "x")
        config = app_config(CARDDAV_URL="https://contacts.test/")
        for app in make_harness(
            config, carddav=CardDav(config.carddav_url or "", transport=transport)
        ):
            session = app.session()
            with pytest.raises(ToolFailed, match="didn't accept"):
                session.call("find_contacts", query="jan")
            assert app.db.one("SELECT count(*) AS n FROM grants")["n"] == 1  # type: ignore[index]

    def test_no_contacts_tool_without_carddav(self, harness: Harness) -> None:
        tools = {t["name"] for t in harness.session().request("tools/list", {})["tools"]}
        assert "find_contacts" not in tools
        assert "delivery_status" not in tools and "release_from_quarantine" not in tools


def connect(app: Harness, certs: Path) -> McpSession:
    client_id, response = sign_in(app, certs)
    assert response.status_code == 303, response.text
    code = query_of(response.headers["location"])["code"]
    tokens = app.exchange(client_id, code, app.verifier_value).json()  # type: ignore[attr-defined]
    return McpSession(app.client, tokens["access_token"])


class TestMailcowTools:
    @pytest.fixture
    def app(
        self, running_mailcow: RunningMailcow, certs: Path, broker: BrokerSetup
    ) -> Iterator[Harness]:
        yield from make_mailcow_harness(running_mailcow, certs, broker)

    def test_tool_list(self, app: Harness, certs: Path) -> None:
        session = connect(app, certs)
        tools = {t["name"]: t for t in session.request("tools/list", {})["tools"]}
        for name in (
            "release_from_quarantine",
            "delete_from_quarantine",
            "delivery_status",
            "my_addresses",
            "find_contacts",
        ):
            assert name in tools
        assert tools["release_from_quarantine"]["annotations"]["destructiveHint"] is True
        assert tools["delete_from_quarantine"]["annotations"]["destructiveHint"] is True
        assert tools["delivery_status"]["annotations"]["readOnlyHint"] is True

    def test_my_addresses(self, app: Harness, mailcow: MockMailcow, certs: Path) -> None:
        mailcow.aliases = [
            {"id": 1, "address": "sales@example.test", "goto": "alice@example.test", "active": "1"}
        ]
        result = connect(app, certs).call("my_addresses")
        assert result["mailbox"] == "alice@example.test" and result["aliases"] == [
            "sales@example.test"
        ]

    def test_delivery_status(self, app: Harness, mailcow: MockMailcow, certs: Path) -> None:
        mailcow.logs = [
            {"time": "100", "message": "ABCDEF1234: message-id=<x1@example.test>"},
            {"time": "101", "message": "ABCDEF1234: from=<alice@example.test>, size=1, nrcpt=1"},
            {
                "time": "102",
                "message": "ABCDEF1234: to=<bob@remote.example>, relay=mx[1.1.1.1]:25, dsn=5.1.1, status=bounced (550 5.1.1 No such user)",
            },
        ]
        session = connect(app, certs)
        result = session.call("delivery_status", message_id="x1@example.test")
        assert result["recipients"][0]["status"] == "bounced"
        assert result["recipients"][0]["response"] == "550 5.1.1 No such user"
        empty = session.call("delivery_status", message_id="<unknown@example.test>")
        assert empty["recipients"] == [] and "log" in empty["note"]

    def test_quarantine_release_and_delete(
        self, app: Harness, mailcow: MockMailcow, certs: Path
    ) -> None:
        mailcow.quarantine = [
            {
                "id": 7,
                "qid": "Q",
                "subject": "Hi",
                "score": 12,
                "rcpt": "alice@example.test",
                "sender": "bob@x",
                "action": "reject",
                "created": 1790000000,
                "virus_flag": 0,
            },
            {
                "id": 8,
                "qid": "R",
                "subject": "Other",
                "score": 12,
                "rcpt": "carol@example.test",
                "sender": "bob@x",
                "action": "reject",
                "created": 1790000000,
                "virus_flag": 0,
            },
        ]
        session = connect(app, certs)
        with pytest.raises(ToolFailed, match="no such quarantine item"):
            session.call("release_from_quarantine", id=8)
        released = session.call("release_from_quarantine", id=7)
        assert released["released"] == 7 and "INBOX" in released["note"]
        assert mailcow.released == [7]
        with pytest.raises(ToolFailed, match="no such quarantine item"):
            session.call("delete_from_quarantine", id=8)
        assert [q["id"] for q in mailcow.quarantine] == [8]

    def test_my_addresses_include_display_names(
        self,
        running_mailcow: RunningMailcow,
        mailcow: MockMailcow,
        certs: Path,
        broker: BrokerSetup,
    ) -> None:
        mailcow.aliases = [
            {"id": 1, "address": "sales@example.test", "goto": "alice@example.test", "active": "1"}
        ]
        for app in make_mailcow_harness(
            running_mailcow,
            certs,
            broker,
            FROM_NAMES="alice@example.test=Alice Nováková; sales@example.test=Sales",
        ):
            result = connect(app, certs).call("my_addresses")
            assert result["display_names"] == {
                "alice@example.test": "Alice Nováková",
                "sales@example.test": "Sales",
            }

    def test_password_connections_cant_use_mailcow_tools(
        self, running_mailcow: RunningMailcow, certs: Path, broker: BrokerSetup
    ) -> None:
        for app in make_mailcow_harness(
            running_mailcow, certs, broker, ALLOW_PASSWORD_LOGIN="true"
        ):
            session = app.session()  # password sign-in
            with pytest.raises(ToolFailed, match="Sign in with mailcow"):
                session.call("my_addresses")

    def test_removed_app_password_signs_out(
        self, app: Harness, broker: BrokerSetup, certs: Path
    ) -> None:
        session = connect(app, certs)
        capability = app.provider.capability_of(1)
        assert capability is not None
        in_app(app, lambda provider, client: client.deprovision(capability), broker)
        with pytest.raises(ToolFailed, match="signed out"):
            session.call("my_addresses")
        assert app.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]


def _append(server: MailServer, folder: str, message: EmailMessage) -> None:
    conn = server.imap(ALICE)
    try:
        conn.append(f'"{folder}"', "", imaplib.Time2Internaldate(time.time()), message.as_bytes())
    finally:
        conn.logout()


@pytest.mark.integration
class TestMailcowWithMailServer:
    @pytest.fixture
    def app(
        self,
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

    def test_spam_and_replies_include_quarantine(
        self, app: Harness, mailcow: MockMailcow, mailserver: MailServer, certs: Path
    ) -> None:
        session = connect(app, certs)
        sent = session.call(
            "send_email", to=["partner@example.net"], subject="Proposal", body_text="See you?"
        )
        now = int(time.time())
        mailcow.quarantine = [
            {
                "id": 21,
                "qid": "A",
                "subject": "Re: Proposal",
                "score": 16,
                "rcpt": "alice@example.test",
                "sender": "partner@example.net",
                "action": "reject",
                "created": now + 60,
                "virus_flag": 0,
            },
            {
                "id": 22,
                "qid": "B",
                "subject": "Old",
                "score": 16,
                "rcpt": "alice@example.test",
                "sender": "partner@example.net",
                "action": "reject",
                "created": now - 86400,
                "virus_flag": 0,
            },
            {
                "id": 23,
                "qid": "C",
                "subject": "Win!",
                "score": 30,
                "rcpt": "alice@example.test",
                "sender": "spammer@example.org",
                "action": "reject",
                "created": now + 60,
                "virus_flag": 0,
            },
        ]
        junk = EmailMessage(policy=default_policy)
        junk["From"] = "partner@example.net"
        junk["To"] = "alice@example.test"
        junk["Subject"] = "Re: Proposal (2)"
        junk["Message-ID"] = "<junk-reply@example.net>"
        junk["In-Reply-To"] = sent["message_id"]
        junk.set_content("yes")
        _append(mailserver, "Junk", junk)

        replies = session.call("find_replies", message_id=sent["message_id"])
        where = {(r["found_in"], r["possible_reply"]): r for r in replies["replies"]}
        assert set(where) == {("junk", False), ("quarantine", True)}
        assert where[("quarantine", True)]["quarantine_id"] == 21
        assert "quarantine" in replies["searched"]

        spam = session.call("list_spam", limit=50)
        locations = {(i["location"], i.get("quarantine_id")) for i in spam["items"]}
        assert {("quarantine", 21), ("quarantine", 22), ("quarantine", 23)} <= locations
        assert any(i["location"] == "junk" for i in spam["items"])

        released = session.call("release_from_quarantine", id=21)
        assert released["released"] == 21
        moved = session.call(
            "rescue_from_junk",
            uids=[
                next(
                    i["uid"]
                    for i in spam["items"]
                    if i["location"] == "junk" and i["subject"] == "Re: Proposal (2)"
                )
            ],
        )
        assert "rspamd" in moved["note"]  # mailcow mode says what it teaches
