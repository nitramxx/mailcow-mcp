"""Sending, drafts and attachments against a real Dovecot + Postfix server."""

from __future__ import annotations

import base64
import imaplib
import time
from collections.abc import Iterator
from email.message import EmailMessage
from email.policy import default as default_policy

import pytest

from mailcow_mcp.mime import parse_message, walk_parts

from conftest import Harness, McpSession, ToolFailed, app_config, make_harness
from mailserver_fixture import ALICE, ALICE_ALIAS, BOB, MailServer

pytestmark = pytest.mark.integration

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


@pytest.fixture
def server(mailserver: MailServer) -> Iterator[Harness]:
    yield from make_harness(app_config(**mailserver.env()), real_login=True)


@pytest.fixture
def alice(server: Harness) -> McpSession:
    return server.session(*ALICE)


def wait_for(
    mailserver: MailServer, user: tuple[str, str], message_id: str, folder: str = "INBOX"
) -> EmailMessage:
    deadline = time.monotonic() + 20
    while True:
        conn = mailserver.imap(user)
        try:
            conn.select(f'"{folder}"', readonly=True)
            _, data = conn.uid("SEARCH", "HEADER", "Message-ID", message_id)
            uids = data[0].split()
            if uids:
                _, fetched = conn.uid("FETCH", uids[-1], "(BODY.PEEK[])")
                raw = next(part[1] for part in fetched if isinstance(part, tuple))
                return parse_message(raw)
        finally:
            conn.logout()
        if time.monotonic() > deadline:
            raise AssertionError(f"{message_id} did not arrive in {user[0]}'s {folder}")
        time.sleep(0.3)


def flags_of(mailserver: MailServer, user: tuple[str, str], folder: str, message_id: str) -> bytes:
    conn = mailserver.imap(user)
    try:
        conn.select(f'"{folder}"', readonly=True)
        _, data = conn.uid("SEARCH", "HEADER", "Message-ID", message_id)
        uid = data[0].split()[-1]
        _, fetched = conn.uid("FETCH", uid, "(FLAGS)")
        return fetched[0] if isinstance(fetched[0], bytes) else b""
    finally:
        conn.logout()


def append(
    mailserver: MailServer, user: tuple[str, str], message: EmailMessage, folder: str = "INBOX"
) -> int:
    conn = mailserver.imap(user)
    try:
        typ, data = conn.append(
            f'"{folder}"', "", imaplib.Time2Internaldate(time.time()), message.as_bytes()
        )
        assert typ == "OK"
        text = data[0].decode() if data and isinstance(data[0], bytes) else ""
        return int(text.split("APPENDUID ")[1].split()[1].rstrip("]"))
    finally:
        conn.logout()


def test_send_markdown_with_bcc(alice: McpSession, mailserver: MailServer) -> None:
    result = alice.call(
        "send_email",
        to=["Bob <bob@example.test>"],
        bcc=["sales@example.test"],
        subject="Ahoj Bobe \u2013 test",
        body_markdown="# Hello\n\n**Bold** and <script>alert(1)</script> [link](https://example.com)",
    )
    assert result["accepted"] == ["bob@example.test", "sales@example.test"]
    assert result["saved_to_sent"] is True
    assert result["sent_folder"] == "Sent"

    received = wait_for(mailserver, BOB, result["message_id"])
    assert received["Subject"] == "Ahoj Bobe \u2013 test"
    assert received["From"] == "alice@example.test"
    assert "Bcc" not in received
    assert received.get_content_type() == "multipart/alternative"
    html = received.get_body(("html",))
    assert html is not None
    content = html.get_content()
    assert "<strong>Bold</strong>" in content
    assert "<script>" not in content
    assert 'href="https://example.com"' in content
    text = received.get_body(("plain",))
    assert text is not None and "**Bold**" in text.get_content()

    # the alias delivers to Alice, so Alice gets it too (as Bcc)
    wait_for(mailserver, ALICE, result["message_id"])
    sent = wait_for(mailserver, ALICE, result["message_id"], folder="Sent")
    assert sent["Bcc"] == "sales@example.test"
    assert b"\\Seen" in flags_of(mailserver, ALICE, "Sent", result["message_id"])


def test_send_plain_text_from_alias(alice: McpSession, mailserver: MailServer) -> None:
    result = alice.call(
        "send_email",
        to=["bob@example.test"],
        subject="From sales",
        body_text="Plain text\nsecond line",
        from_address=ALICE_ALIAS,
        from_name="Alice from Sales",
    )
    received = wait_for(mailserver, BOB, result["message_id"])
    assert received["From"] == "Alice from Sales <sales@example.test>"
    assert received.get_content_type() == "text/plain"
    assert received.get_content().replace("\r\n", "\n").strip() == "Plain text\nsecond line"


def test_sender_acl_rejection_is_reported(alice: McpSession) -> None:
    with pytest.raises(ToolFailed, match=r"refused to send from bob@example\.test"):
        alice.call(
            "send_email",
            to=["bob@example.test"],
            subject="x",
            body_text="x",
            from_address="bob@example.test",
        )


def test_attachments_from_all_three_sources(alice: McpSession, mailserver: MailServer) -> None:
    original = EmailMessage(policy=default_policy)
    original["From"] = "bob@example.test"
    original["To"] = "alice@example.test"
    original["Subject"] = "Invoice"
    original["Message-ID"] = "<invoice-1@example.test>"
    original.set_content("See attached.")
    original.add_attachment(
        b"col1,col2\n1,2\n", maintype="text", subtype="csv", filename="data.csv"
    )
    uid = append(mailserver, ALICE, original)
    part_id = next(n for n, p in walk_parts(original) if p.get_filename() == "data.csv")

    result = alice.call(
        "send_email",
        to=["bob@example.test"],
        subject="Three attachments",
        body_text="Attached.",
        attachments=[
            {
                "filename": "pixel.png",
                "content_base64": base64.b64encode(PNG).decode(),
                "mime_type": "image/png",
            },
            {"from_message": {"folder": "INBOX", "uid": uid, "part_id": part_id}},
            {
                "render_pdf": {
                    "filename": "Zpráva",
                    "markdown": "# Příliš žluťoučký kůň\n\n| a | b |\n|---|---|\n| 1 | 2 |",
                    "title": "Zpráva",
                }
            },
        ],
    )
    received = wait_for(mailserver, BOB, result["message_id"])
    files = {p.get_filename(): p for p in received.iter_attachments()}
    assert set(files) == {"pixel.png", "data.csv", "Zpráva.pdf"}
    assert files["pixel.png"].get_content() == PNG
    assert files["data.csv"].get_content_type() == "text/csv"
    assert files["data.csv"].get_content().replace("\r\n", "\n") == "col1,col2\n1,2\n"
    pdf = files["Zpráva.pdf"].get_content()
    assert pdf.startswith(b"%PDF-")


def test_reply_threads_with_references(alice: McpSession, mailserver: MailServer) -> None:
    original = EmailMessage(policy=default_policy)
    original["From"] = "bob@example.test"
    original["To"] = "alice@example.test"
    original["Subject"] = "Question"
    original["Message-ID"] = "<q-2@example.test>"
    original["References"] = "<q-1@example.test>"
    original.set_content("Can you?")
    append(mailserver, ALICE, original)

    result = alice.call(
        "send_email",
        to=["bob@example.test"],
        subject="Re: Question",
        body_text="Yes.",
        in_reply_to="q-2@example.test",
    )
    received = wait_for(mailserver, BOB, result["message_id"])
    assert received["In-Reply-To"] == "<q-2@example.test>"
    assert received["References"] == "<q-1@example.test> <q-2@example.test>"


def test_draft_lifecycle(alice: McpSession, mailserver: MailServer) -> None:
    draft = alice.call(
        "save_draft",
        to=["bob@example.test"],
        bcc=["sales@example.test"],
        subject="Draft",
        body_markdown="*draft*",
    )
    assert draft["folder"] == "Drafts"
    assert draft["uid"] > 0
    flags = flags_of(mailserver, ALICE, "Drafts", draft["message_id"])
    assert b"\\Draft" in flags

    sent = alice.call("send_draft", uid=draft["uid"])
    assert sent["message_id"] == draft["message_id"]
    assert sent["accepted"] == ["bob@example.test", "sales@example.test"]
    received = wait_for(mailserver, BOB, draft["message_id"])
    assert "Bcc" not in received
    copy = wait_for(mailserver, ALICE, draft["message_id"], folder="Sent")
    assert copy["Bcc"] == "sales@example.test"
    assert b"\\Draft" not in flags_of(mailserver, ALICE, "Sent", draft["message_id"])
    with pytest.raises(ToolFailed, match="No message with UID"):
        alice.call("send_draft", uid=draft["uid"])


def test_delete_draft(alice: McpSession, mailserver: MailServer) -> None:
    draft = alice.call("save_draft", to=["bob@example.test"], subject="Delete me", body_text="x")
    assert alice.call("delete_draft", uid=draft["uid"]) == {"deleted": True, "folder": "Drafts"}
    conn = mailserver.imap(ALICE)
    conn.select('"Drafts"', readonly=True)
    _, data = conn.uid("SEARCH", "HEADER", "Message-ID", draft["message_id"])
    conn.logout()
    assert data[0] == b""
    with pytest.raises(ToolFailed, match="No message with UID"):
        alice.call("delete_draft", uid=draft["uid"])


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"subject": "a\r\nBcc: evil@example.net"}, "line breaks"),
        ({"to": ["bob@example.test\r\nBcc: evil@example.net"]}, "line breaks"),
        ({"to": ["not-an-address"]}, "not a valid email address"),
        ({"to": [f"user{i}@example.test" for i in range(51)]}, "At most 50 recipients"),
        ({"body_markdown": "x"}, "exactly one of body_markdown or body_text"),
        ({"from_name": "A\nB"}, "line breaks"),
        ({"in_reply_to": "no spaces allowed@x y"}, "is not a Message-ID"),
        (
            {
                "attachments": [
                    {
                        "filename": "run.exe",
                        "content_base64": "TVo=",
                        "mime_type": "application/octet-stream",
                    }
                ]
            },
            r"\.exe can't be sent",
        ),
        (
            {
                "attachments": [
                    {
                        "filename": "a.pdf",
                        "content_base64": base64.b64encode(PNG).decode(),
                        "mime_type": "application/pdf",
                    }
                ]
            },
            "declared as application/pdf, but its content is image/png",
        ),
        (
            {
                "attachments": [
                    {
                        "filename": "a.bin",
                        "content_base64": "not base64!",
                        "mime_type": "application/octet-stream",
                    }
                ]
            },
            "not valid base64",
        ),
        (
            {
                "attachments": [
                    {
                        "filename": "big.bin",
                        "content_base64": base64.b64encode(b"x" * (2 * 1024 * 1024)).decode(),
                        "mime_type": "application/octet-stream",
                    }
                ]
            },
            "larger than",
        ),
    ],
)
def test_invalid_input_is_refused(
    mailserver: MailServer, arguments: dict[str, object], message: str
) -> None:
    for harness in make_harness(app_config(**mailserver.env(MAX_MESSAGE_MB="1")), real_login=True):
        session = harness.session(*ALICE)
        call: dict[str, object] = {"to": ["bob@example.test"], "subject": "x", "body_text": "x"}
        call.update(arguments)
        with pytest.raises(ToolFailed, match=message):
            session.call("send_email", **call)


def test_send_limit(mailserver: MailServer) -> None:
    for harness in make_harness(
        app_config(**mailserver.env(SEND_LIMIT_HOUR="2", SEND_LIMIT_DAY="5")), real_login=True
    ):
        session = harness.session(*ALICE)
        for _ in range(2):
            session.call("send_email", to=["bob@example.test"], subject="limit", body_text="x")
        with pytest.raises(ToolFailed, match="2 messages per hour"):
            session.call("send_email", to=["bob@example.test"], subject="limit", body_text="x")


def test_implicit_tls_submission(mailserver: MailServer) -> None:
    env = mailserver.env(
        SMTP_PORT=str(mailserver.submissions_port), SMTP_SECURITY="ssl", SAVE_SENT="never"
    )
    for harness in make_harness(app_config(**env), real_login=True):
        result = harness.session(*ALICE).call(
            "send_email", to=["bob@example.test"], subject="465", body_text="x"
        )
        assert result["saved_to_sent"] is False
        wait_for(mailserver, BOB, result["message_id"])


def test_rejected_credentials_sign_the_connection_out(server: Harness) -> None:
    session = server.session(*ALICE)
    # The password changes on the server: simulate by corrupting the stored credential.
    server.db.execute(
        "UPDATE grants SET credential_enc = ?", (server.provider.box.encrypt("wrong"),)
    )
    with pytest.raises(ToolFailed, match="reconnect the app"):
        session.call("save_draft", to=["bob@example.test"], subject="x", body_text="x")
    assert server.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]
    with pytest.raises(ToolFailed, match="HTTP 401"):
        session.call("save_draft", to=["bob@example.test"], subject="x", body_text="x")


def test_send_draft_reencodes_8bit_drafts(alice: McpSession, mailserver: MailServer) -> None:
    """A draft written by another client as raw 8bit goes out 7-bit clean."""
    draft = EmailMessage(policy=default_policy)
    draft["From"] = "alice@example.test"
    draft["To"] = "bob@example.test"
    draft["Subject"] = "8bit draft"
    draft["Message-ID"] = "<draft-8bit@example.test>"
    draft.set_content("Příliš žluťoučký kůň", cte="8bit")
    uid = append(mailserver, ALICE, draft, folder="Drafts")
    alice.call("send_draft", uid=uid)
    conn = mailserver.imap(BOB)
    try:
        deadline = time.monotonic() + 20
        while True:
            conn.select("INBOX", readonly=True)
            _, data = conn.uid("SEARCH", "HEADER", "Message-ID", "<draft-8bit@example.test>")
            if data[0] or time.monotonic() > deadline:
                break
            time.sleep(0.3)
        _, fetched = conn.uid("FETCH", data[0].split()[-1], "(BODY.PEEK[])")
        raw = next(part[1] for part in fetched if isinstance(part, tuple))
    finally:
        conn.logout()
    body = raw.split(b"\r\n\r\n", 1)[1]
    assert body.isascii()
    assert parse_message(raw).get_content().strip() == "Příliš žluťoučký kůň"
