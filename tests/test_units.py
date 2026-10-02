from __future__ import annotations

import imaplib
import json
import socket
import ssl
from pathlib import Path

import aiosmtplib
import pytest
from imapclient.exceptions import LoginError

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.db import Database, available_migrations
from mailcow_mcp.errors import CredentialsRejected, ServerUnavailable
from mailcow_mcp.i18n import Translator, messages, pick_language
from mailcow_mcp.imap import login_rejected
from mailcow_mcp.login import normalize_email
from mailcow_mcp.messages import summarize
from mailcow_mcp.mime import parse_message
from mailcow_mcp.ratelimit import RateLimiter
from mailcow_mcp.smtp import auth_error
from mailcow_mcp.tls import client_context


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_rate_limiter_sliding_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(2, 10, clock=clock)
    assert limiter.hit("a") and limiter.hit("a")
    assert not limiter.hit("a")
    assert limiter.hit("b")
    clock.now = 10.5
    assert limiter.allowed("a")
    assert limiter.hit("a")
    limiter.reset("a")
    assert limiter.hit("a") and limiter.hit("a")


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, "en"),
        ("", "en"),
        ("cs", "cs"),
        ("cs-CZ,cs;q=0.9,en;q=0.8", "cs"),
        ("de-DE,de;q=0.9,cs;q=0.5,en;q=0.7", "en"),
        ("de, fr", "en"),
        ("en;q=0.1, cs;q=0.9", "cs"),
        ("cs;q=bad, en", "en"),
    ],
)
def test_pick_language(header: str | None, expected: str) -> None:
    assert pick_language(header, "en") == expected


def test_translations_are_complete() -> None:
    assert messages("en").keys() == messages("cs").keys()
    assert (
        Translator("cs")("error_domain", domain="x.cz")
        == "Tento server nepřijímá přihlášení pro doménu x.cz."
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("User@Example.ORG", "user@example.org"),
        (" a.b+c@sub.example.org ", "a.b+c@sub.example.org"),
        ("jan@příklad.cz", "jan@xn--pklad-zsa96e.cz"),
        ("no-at-sign", None),
        ("two@@example.org", None),
        ("a b@example.org", None),
        ("a@localhost", None),
        ("a@-bad.example", None),
        ("a\r\nBcc: x@example.org", None),
        ("x" * 65 + "@example.org", None),
    ],
)
def test_normalize_email(value: str, expected: str | None) -> None:
    assert normalize_email(value) == expected


def test_tls_context_verifies_against_fixed_name() -> None:
    context = client_context(server_name="mail.example.com")
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    a, b = socket.socketpair()
    with a, b:
        wrapped = context.wrap_socket(
            a, server_hostname="dovecot-mailcow", do_handshake_on_connect=False
        )
        assert wrapped.server_hostname == "mail.example.com"
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    bio = context.wrap_bio(incoming, outgoing, server_hostname="postfix-mailcow")
    assert bio.server_hostname == "mail.example.com"
    # asyncio/httpcore pass server_hostname positionally
    bio = context.wrap_bio(incoming, outgoing, False, "nginx-mailcow")
    assert bio.server_hostname == "mail.example.com"


def test_tls_context_without_verification() -> None:
    context = client_context(server_name=None, verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert not context.check_hostname


def test_migrations(tmp_path: Path) -> None:
    db = Database.in_data_dir(tmp_path)
    assert db.version == 0
    applied = db.migrate()
    assert applied == [name for _, name, _ in available_migrations()]
    assert db.version == len(applied)
    assert db.migrate() == []
    tables = {r["name"] for r in db.all("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"mailboxes", "clients", "auth_requests", "grants", "auth_codes", "tokens"} <= tables
    assert db.one("PRAGMA journal_mode")[0] == "wal"  # type: ignore[index]


def test_transaction_rolls_back(tmp_path: Path) -> None:
    db = Database.in_data_dir(tmp_path)
    db.migrate()
    with pytest.raises(RuntimeError), db.transaction() as conn:
        conn.execute(
            "INSERT INTO mailboxes (username, created_at, last_login_at) VALUES ('a', 1, 1)"
        )
        raise RuntimeError
    assert db.one("SELECT count(*) AS n FROM mailboxes")["n"] == 0  # type: ignore[index]


def test_audit_log_writes_json_lines(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit = AuditLog.in_data_dir(tmp_path)
    audit("login", mailbox="a@example.org", client="Claude", ip=None, attempts=1)
    line = (tmp_path / "audit.log").read_text().strip()
    record = json.loads(line)
    assert record["audit"] == "login"
    assert record["result"] == "ok"
    assert record["mailbox"] == "a@example.org"
    assert record["attempts"] == 1
    assert "ip" not in record
    assert capsys.readouterr().out.strip() == line


def _login_error(message: str, cause: Exception | None = None) -> LoginError:
    """As imapclient raises it: LoginError(str(original)) inside the except block."""
    error = LoginError(message)
    error.__context__ = cause or imaplib.IMAP4.error(message)
    return error


@pytest.mark.parametrize(
    ("error", "rejected"),
    [
        (_login_error("b'[AUTHENTICATIONFAILED] Authentication failed.'"), True),
        (_login_error("b'[EXPIRED] Password expired.'"), True),
        (_login_error("b'LOGIN failed'"), True),  # no response code: taken as refused
        (_login_error("b'[UNAVAILABLE] Temporary authentication failure.'"), False),
        (_login_error("b'Temporary authentication failure, try again'"), False),
        (_login_error("socket error: EOF", imaplib.IMAP4.abort("socket error: EOF")), False),
        (_login_error("timed out", TimeoutError("timed out")), False),
    ],
)
def test_imap_login_rejected(error: LoginError, rejected: bool) -> None:
    assert login_rejected(error) is rejected


@pytest.mark.parametrize(
    ("code", "expected"),
    [(535, CredentialsRejected), (534, CredentialsRejected), (454, ServerUnavailable)],
)
def test_smtp_auth_error(code: int, expected: type[Exception]) -> None:
    error = auth_error(aiosmtplib.SMTPAuthenticationError(code, "x"))
    assert type(error) is expected


def test_smtp_auth_error_other_codes_are_not_a_sign_out() -> None:
    error = auth_error(aiosmtplib.SMTPAuthenticationError(530, "Must issue a STARTTLS first"))
    assert not isinstance(error, (CredentialsRejected, ServerUnavailable))
    assert "530" in str(error)


@pytest.mark.parametrize(
    "broken", [b'To: "', b"Message-ID: <a@[b>", b'From: (%=?=?)"', b'Cc: a@b.c, ,"']
)
def test_summary_of_malformed_headers(broken: bytes) -> None:
    message = parse_message(broken + b"\r\nSubject: =?utf-8?q?ok?=\r\n\r\nbody")
    summary = summarize(1, "INBOX", message, ())
    assert summary.subject == "ok"
