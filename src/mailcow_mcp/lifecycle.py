"""App password lifecycle in mailcow mode (deprovisioning and reconciling)."""

from __future__ import annotations

import logging

from mailcow_mcp.broker_client import BrokerClient, RevokedCapability
from mailcow_mcp.errors import MailError
from mailcow_mcp.oauth import Provider

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 50  # then reconcile cleans up


async def drain_deprovision_queue(provider: Provider, broker: BrokerClient) -> int:
    """Ask the broker to delete app passwords of ended grants; returns how many were done."""
    done = 0
    for queue_id, mailbox, capability in provider.pending_deprovisions():
        try:
            await broker.deprovision(capability)
        except RevokedCapability:
            pass  # already gone in the broker's records
        except MailError as exc:
            provider.deprovision_failed(queue_id, str(exc))
            row = provider.db.one(
                "SELECT attempts FROM deprovision_queue WHERE id = ?", (queue_id,)
            )
            if row is not None and row["attempts"] >= MAX_ATTEMPTS:
                log.warning("giving up deprovisioning an app password of %s", mailbox)
                provider.deprovisioned(queue_id)
            continue
        provider.deprovisioned(queue_id)
        done += 1
    return done


async def reconcile(provider: Provider, broker: BrokerClient) -> int:
    """Tell the broker which app passwords are still in use; it deletes the rest."""
    result = await broker.reconcile(provider.live_capabilities())
    return int(result.get("deleted", 0))
