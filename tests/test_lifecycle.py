"""Deprovisioning queue: retries, giving up, and an unreachable broker."""

from __future__ import annotations

from typing import Any

import pytest

from mailcow_mcp.broker_client import BrokerRefused, CapabilityRejected
from mailcow_mcp.errors import ServerUnavailable
from mailcow_mcp.lifecycle import MAX_ATTEMPTS, drain_deprovision_queue, reconcile
from mailcow_mcp.oauth import Provider

from conftest import Harness

pytestmark = pytest.mark.anyio


class FakeBroker:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[str] = []

    async def deprovision(self, capability: str) -> dict[str, Any]:
        self.calls.append(capability)
        if self.error is not None:
            raise self.error
        return {"deleted": True}

    async def reconcile(self, capabilities: list[str]) -> dict[str, Any]:
        self.calls += capabilities
        return {"deleted": 0}


def queue(provider: Provider, *capabilities: str) -> None:
    for capability in capabilities:
        provider.db.execute(
            "INSERT INTO deprovision_queue (mailbox, capability_enc, queued_at) VALUES (?, ?, 0)",
            ("a@example.org", provider.box.encrypt(capability)),
        )


def queued(provider: Provider) -> int:
    return int(provider.db.one("SELECT count(*) AS n FROM deprovision_queue")["n"])  # type: ignore[index]


async def test_done_and_already_gone_leave_the_queue(harness: Harness) -> None:
    queue(harness.provider, "cap-a", "cap-b")
    assert await drain_deprovision_queue(harness.provider, FakeBroker()) == 2  # type: ignore[arg-type]
    queue(harness.provider, "cap-c")
    gone = FakeBroker(CapabilityRejected("revoked_capability", "gone"))
    assert await drain_deprovision_queue(harness.provider, gone) == 1  # type: ignore[arg-type]
    assert queued(harness.provider) == 0


async def test_failures_are_retried_then_given_up(harness: Harness) -> None:
    queue(harness.provider, "cap-a")
    failing = FakeBroker(BrokerRefused("mailcow_error", "nope"))
    for _ in range(MAX_ATTEMPTS - 1):
        await drain_deprovision_queue(harness.provider, failing)  # type: ignore[arg-type]
    assert queued(harness.provider) == 1
    await drain_deprovision_queue(harness.provider, failing)  # type: ignore[arg-type]
    assert queued(harness.provider) == 0


async def test_unreachable_broker_stops_the_drain(harness: Harness) -> None:
    queue(harness.provider, "cap-a", "cap-b", "cap-c")
    down = FakeBroker(ServerUnavailable())
    await drain_deprovision_queue(harness.provider, down)  # type: ignore[arg-type]
    assert down.calls == ["cap-a"]
    row = harness.provider.db.one("SELECT max(attempts) AS n FROM deprovision_queue")
    assert row is not None and row["n"] == 0  # not counted against the items
    assert queued(harness.provider) == 3


async def test_unreadable_items_dont_block_the_queue(harness: Harness) -> None:
    harness.provider.db.execute(
        "INSERT INTO deprovision_queue (mailbox, capability_enc, queued_at) VALUES (?, ?, 0)",
        ("a@example.org", "not-fernet"),
    )
    queue(harness.provider, "cap-a")
    broker = FakeBroker()
    assert await drain_deprovision_queue(harness.provider, broker) == 1  # type: ignore[arg-type]
    assert broker.calls == ["cap-a"]
    assert queued(harness.provider) == 0


async def test_reconcile_skips_unreadable_capabilities(harness: Harness) -> None:
    broker = FakeBroker()
    assert await reconcile(harness.provider, broker) == 0  # type: ignore[arg-type]
    assert broker.calls == []
