"""The broker against a mock mailcow over TLS."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from mailcow_fixtures import BrokerSetup, make_broker
from mock_mailcow import MockMailcow, RunningMailcow

from mailcow_mcp.broker import (
    RECONCILE_GRACE_SECONDS,
    app_password_name,
    generate_password,
    parse_delivery,
)
from mailcow_mcp.capability import CapabilitySigner, InvalidCapability
from mailcow_mcp.config import generate_key

pytestmark = pytest.mark.anyio


def token_for(mock: MockMailcow, user: str) -> str:
    token = f"token-{user}"
    mock.tokens[token] = user
    return token


async def provision(
    broker: BrokerSetup, mock: MockMailcow, user: str = "alice@example.test", client: str = "Claude"
) -> dict:  # type: ignore[type-arg]
    response = await broker.call(
        "provision", mailcow_oauth_token=token_for(mock, user), client_name=client
    )
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


class TestHelpers:
    def test_name(self) -> None:
        assert app_password_name("Claude", "2026-10-01", "a1b2") == "MCP: Claude (2026-10-01, a1b2)"
        assert (
            app_password_name('<b>Evil & "co"</b>\n', "2026-10-01", "x")
            == "MCP: bEvil cob (2026-10-01, x)"
        )
        assert app_password_name(None, "2026-10-01", "x") == "MCP: MCP client (2026-10-01, x)"

    def test_password_meets_policy(self) -> None:
        for _ in range(20):
            password = generate_password({"length": 40, "special_chars": 1})
            assert len(password) == 40
            assert re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
            assert re.search(r"\d", password) and re.search(r"[-_]", password)

    def test_capabilities(self) -> None:
        signer = CapabilitySigner(generate_key())
        token = signer.issue("a@example.org", 7)
        assert signer.verify(token).mailbox == "a@example.org"
        other = CapabilitySigner(generate_key())
        with pytest.raises(InvalidCapability):
            other.verify(token)
        prefix, payload, signature = token.split(".")
        forged = signer.issue("b@example.org", 7).split(".")[1]
        for bad in [
            f"{prefix}.{forged}.{signature}",
            f"{prefix}.{payload}.",
            "cap2.x.y",
            "garbage",
            "a" * 5000,
        ]:
            with pytest.raises(InvalidCapability):
                signer.verify(bad)

    def test_delivery_parsing(self) -> None:
        mid = "<m1@example.test>"
        logs = [
            {"time": "100", "message": f"4A1B2C3D: message-id={mid}"},
            {
                "time": "101",
                "message": "4A1B2C3D: from=<Alice@example.test>, size=900, nrcpt=2 (queue active)",
            },
            {
                "time": "102",
                "message": "4A1B2C3D: to=<bob@remote.example>, relay=mx.remote.example[1.2.3.4]:25, delay=1, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as XYZ)",
            },
            {
                "time": "103",
                "message": "4A1B2C3D: to=<carol@remote.example>, relay=none, delay=5, dsn=4.4.1, status=deferred (connect to mx.remote.example[1.2.3.4]:25: Connection refused)",
            },
            {
                "time": "200",
                "message": "4A1B2C3D: to=<carol@remote.example>, relay=mx.remote.example[1.2.3.4]:25, dsn=5.1.1, status=bounced (host said: 550 5.1.1 User unknown)",
            },
            # Someone else's message with the same Message-ID is not reported.
            {"time": "150", "message": f"5B5B5B5B5B: message-id={mid}"},
            {"time": "151", "message": "5B5B5B5B5B: from=<mallory@example.test>, size=1, nrcpt=1"},
            {
                "time": "152",
                "message": "5B5B5B5B5B: to=<victim@remote.example>, relay=x, dsn=2.0.0, status=sent (250 ok)",
            },
        ]
        result = parse_delivery(logs, mid, {"alice@example.test", "sales@example.test"})
        assert [(r["recipient"], r["status"], r["dsn"]) for r in result] == [
            ("bob@remote.example", "sent", "2.0.0"),
            ("carol@remote.example", "bounced", "5.1.1"),
        ]
        assert result[1]["response"] == "host said: 550 5.1.1 User unknown"
        assert parse_delivery(logs, "<other@x>", {"alice@example.test"}) == []


class TestTransport:
    async def test_shared_secret_required(self, broker: BrokerSetup) -> None:
        assert (await broker.call("aliases", secret=None, capability="x")).status_code == 401
        assert (await broker.call("aliases", secret="wrong", capability="x")).status_code == 401
        assert '"result":"bad_secret"' in broker.audit.getvalue()

    async def test_unknown_operation_and_bad_bodies(self, broker: BrokerSetup) -> None:
        assert (await broker.call("delete_everything")).status_code == 404
        assert (await broker.call("provision")).status_code == 400

    async def test_tls_name_is_verified(
        self, running_mailcow: RunningMailcow, mailcow: MockMailcow, certs: Path, tmp_path: Path
    ) -> None:
        wrong = make_broker(running_mailcow, certs, tmp_path, TLS_SERVER_NAME="other.test")
        response = await wrong.call(
            "provision", mailcow_oauth_token=token_for(mailcow, "alice@example.test")
        )
        assert response.status_code == 503


class TestProvisioning:
    async def test_provision(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        result = await provision(broker, mailcow, "Alice@Example.test")
        assert result["username"] == "alice@example.test"
        (created,) = mailcow.passwords_of("Alice@Example.test") or mailcow.passwords_of(
            "alice@example.test"
        )
        assert created["id"] == result["app_password_id"]
        assert re.fullmatch(r"MCP: Claude \(\d{4}-\d{2}-\d{2}, [0-9a-f]{4}\)", created["name"])
        assert created["protocols"] == ["imap_access", "smtp_access", "dav_access"]
        assert len(result["app_password"]) >= 32
        assert broker.broker.signer.verify(result["capability"]).mailbox == "alice@example.test"
        assert result["app_password"] not in broker.audit.getvalue()

    async def test_username_comes_from_mailcow_not_the_caller(
        self, broker: BrokerSetup, mailcow: MockMailcow
    ) -> None:
        response = await broker.call(
            "provision",
            mailcow_oauth_token=token_for(mailcow, "alice@example.test"),
            username="admin@example.test",
        )
        assert response.json()["username"] == "alice@example.test"

    async def test_bad_token(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        response = await broker.call("provision", mailcow_oauth_token="not-a-token")
        assert response.status_code == 403
        assert response.json()["error"] == "token_rejected"
        assert mailcow.app_passwords == []

    async def test_rate_limited_per_mailbox(
        self, broker: BrokerSetup, mailcow: MockMailcow
    ) -> None:
        for _ in range(10):
            await provision(broker, mailcow)
        response = await broker.call(
            "provision", mailcow_oauth_token=token_for(mailcow, "alice@example.test")
        )
        assert response.status_code == 429
        await provision(broker, mailcow, "bob@example.test")

    async def test_deprovision(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        result = await provision(broker, mailcow)
        own = mailcow.add_existing_app_password("alice@example.test", "Thunderbird")
        response = await broker.call("deprovision", capability=result["capability"])
        assert response.json() == {"deleted": True}
        assert [p["id"] for p in mailcow.passwords_of("alice@example.test")] == [own]
        again = await broker.call("deprovision", capability=result["capability"])
        assert again.status_code == 403 and again.json()["error"] == "revoked_capability"
        assert (await broker.call("aliases", capability=result["capability"])).status_code == 403

    async def test_never_deletes_other_app_passwords(
        self, broker: BrokerSetup, mailcow: MockMailcow
    ) -> None:
        result = await provision(broker, mailcow)
        # The user renamed it: it's no longer ours to delete.
        mailcow.passwords_of("alice@example.test")[0]["name"] = "My phone"
        assert (
            await broker.call("deprovision", capability=result["capability"])
        ).status_code == 200
        assert len(mailcow.passwords_of("alice@example.test")) == 1

    async def test_forged_capability(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        await provision(broker, mailcow)
        forged = CapabilitySigner(generate_key()).issue(
            "alice@example.test", mailcow.app_passwords[0]["id"]
        )
        response = await broker.call("aliases", capability=forged)
        assert response.status_code == 403 and response.json()["error"] == "invalid_capability"
        # A genuine capability for one mailbox, edited to name another, fails too.
        bob = await provision(broker, mailcow, "bob@example.test")
        relabelled = broker.broker.signer.issue("alice@example.test", bob["app_password_id"])
        assert (await broker.call("aliases", capability=relabelled)).status_code == 403


class TestReconcile:
    async def test_reconcile(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        keep = await provision(broker, mailcow)
        drop = await provision(broker, mailcow)
        recent = await provision(broker, mailcow)
        orphan = mailcow.add_existing_app_password(
            "alice@example.test", "MCP: Old (2025-01-01, ffff)"
        )
        user_own = mailcow.add_existing_app_password("alice@example.test", "Thunderbird")
        broker.broker.db.execute(
            "UPDATE app_passwords SET created_at = created_at - ? WHERE app_password_id IN (?, ?)",
            (RECONCILE_GRACE_SECONDS + 1, keep["app_password_id"], drop["app_password_id"]),
        )
        response = await broker.call("reconcile", capabilities=[keep["capability"], "junk"])
        assert response.json() == {"deleted": 2}
        remaining = {p["id"] for p in mailcow.passwords_of("alice@example.test")}
        assert remaining == {keep["app_password_id"], recent["app_password_id"], user_own}
        assert orphan not in remaining


class TestMailboxScopedOperations:
    async def test_aliases(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        mailcow.aliases = [
            {
                "id": 1,
                "address": "sales@example.test",
                "goto": "alice@example.test,bob@example.test",
                "active": "1",
            },
            {"id": 2, "address": "info@example.test", "goto": "bob@example.test", "active": "1"},
            {"id": 3, "address": "old@example.test", "goto": "alice@example.test", "active": "0"},
            {"id": 4, "address": "@example.test", "goto": "alice@example.test", "active": "1"},
            {
                "id": 5,
                "address": "malice@example.test",
                "goto": "malice@example.test",
                "active": "1",
            },
        ]
        result = await provision(broker, mailcow)
        response = await broker.call("aliases", capability=result["capability"])
        assert response.json() == {
            "mailbox": "alice@example.test",
            "aliases": ["sales@example.test"],
        }

    async def test_quarantine_is_scoped(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        mailcow.aliases = [
            {"id": 1, "address": "sales@example.test", "goto": "alice@example.test", "active": "1"}
        ]
        mailcow.quarantine = [
            {
                "id": 1,
                "qid": "A",
                "subject": "Mine",
                "score": "15.5",
                "rcpt": "alice@example.test",
                "sender": "x@y",
                "action": "reject",
                "created": 1790000000,
                "virus_flag": 0,
                "msg": "raw",
            },
            {
                "id": 2,
                "qid": "B",
                "subject": "Alias",
                "score": 9,
                "rcpt": "sales@example.test",
                "sender": "x@y",
                "action": "add header",
                "created": 1790000100,
                "virus_flag": 0,
                "msg": "raw",
            },
            {
                "id": 3,
                "qid": "C",
                "subject": "Bob's",
                "score": 20,
                "rcpt": "bob@example.test",
                "sender": "x@y",
                "action": "reject",
                "created": 1790000200,
                "virus_flag": 0,
                "msg": "raw",
            },
        ]
        result = await provision(broker, mailcow)
        cap = result["capability"]
        items = (await broker.call("quarantine_list", capability=cap)).json()["items"]
        assert [i["id"] for i in items] == [2, 1]
        assert items[1] == {
            "id": 1,
            "sender": "x@y",
            "recipient": "alice@example.test",
            "subject": "Mine",
            "score": 15.5,
            "action": "reject",
            "virus": False,
            "created": "2026-09-21T14:13:20+00:00",
        }
        for operation in ("quarantine_release", "quarantine_delete"):
            response = await broker.call(operation, capability=cap, id=3)
            assert response.status_code == 404  # Bob's item
            assert (await broker.call(operation, capability=cap, id="1")).status_code == 400
        assert (await broker.call("quarantine_release", capability=cap, id=1)).json() == {
            "released": 1
        }
        assert mailcow.released == [1]
        assert (await broker.call("quarantine_delete", capability=cap, id=2)).json() == {
            "deleted": 2
        }
        assert [q["id"] for q in mailcow.quarantine] == [3]

    async def test_delivery_status(self, broker: BrokerSetup, mailcow: MockMailcow) -> None:
        result = await provision(broker, mailcow)
        mailcow.logs = [
            {
                "time": "100",
                "priority": "info",
                "program": "postfix/cleanup",
                "message": "ABCDEF123: message-id=<m@example.test>",
            },
            {
                "time": "101",
                "priority": "info",
                "program": "postfix/qmgr",
                "message": "ABCDEF123: from=<alice@example.test>, size=1, nrcpt=1",
            },
            {
                "time": "102",
                "priority": "info",
                "program": "postfix/smtp",
                "message": "ABCDEF123: to=<bob@remote.example>, relay=mx[1.2.3.4]:25, dsn=2.0.0, status=sent (250 ok)",
            },
        ]
        response = await broker.call(
            "delivery_status", capability=result["capability"], message_id="<m@example.test>"
        )
        recipients = response.json()["recipients"]
        assert [(r["recipient"], r["status"]) for r in recipients] == [
            ("bob@remote.example", "sent")
        ]
        bad = await broker.call(
            "delivery_status", capability=result["capability"], message_id="no brackets"
        )
        assert bad.status_code == 400
