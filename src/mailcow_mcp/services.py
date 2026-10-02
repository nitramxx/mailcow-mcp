"""What tools need: the signed-in mailbox, mail connections, limits, audit."""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import anyio
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.broker_client import BrokerClient, CapabilityRejected
from mailcow_mcp.config import AppConfig
from mailcow_mcp.contacts import CardDav
from mailcow_mcp.crypto import Box
from mailcow_mcp.db import Database
from mailcow_mcp.errors import CredentialsRejected, LimitExceeded, MailError
from mailcow_mcp.imap import ImapConnector, ImapSession
from mailcow_mcp.limits import DAY, HOUR
from mailcow_mcp.oauth import MailboxAccessToken, Provider
from mailcow_mcp.smtp import SmtpSender

log = logging.getLogger(__name__)

SIGNED_OUT = "This connection has been signed out. Reconnect the app to sign in again."


@dataclass(frozen=True)
class Mailbox:
    """A mailbox the current request can act as."""

    grant_id: int
    username: str
    password: str = ""
    client_name: str | None = None
    login_method: str = "password"
    capability: str | None = None  # the broker's token (mailcow sign-in only)

    def __repr__(self) -> str:
        return f"Mailbox({self.username!r}, grant={self.grant_id})"


@dataclass(frozen=True)
class Connection:
    """The current request's connection (grant) and its mailboxes."""

    grant_id: int
    client_name: str | None
    mailboxes: list[Mailbox]

    def select(self, wanted: str | None) -> Mailbox:
        """The mailbox a tool call names; it may leave it out only if there is one."""
        names = ", ".join(m.username for m in self.mailboxes)
        if wanted is None or not wanted.strip():
            if len(self.mailboxes) == 1:
                return self.mailboxes[0]
            raise ToolError(
                f"This connection has {len(self.mailboxes)} mailboxes ({names}): "
                "say which one with the mailbox parameter."
            )
        key = wanted.strip().lower()
        for mailbox in self.mailboxes:
            if mailbox.username == key:
                return mailbox
        raise ToolError(f"{wanted!r} isn't connected. Connected mailboxes: {names}.")


class SendLimits:
    def __init__(
        self, db: Database, per_hour: int, per_day: int, clock: Callable[[], float] = time.time
    ) -> None:
        self.db = db
        self.per_hour = per_hour
        self.per_day = per_day
        self._clock = clock

    def _check(self, conn: sqlite3.Connection, username: str, now: int) -> None:
        row = conn.execute(
            "SELECT count(*) AS day, coalesce(sum(sent_at > ?), 0) AS hour FROM sent_log"
            " WHERE mailbox = ? AND sent_at > ?",
            (now - HOUR, username, now - DAY),
        ).fetchone()
        day, hour = (row["day"], row["hour"]) if row else (0, 0)
        if hour >= self.per_hour:
            raise LimitExceeded(
                f"Send limit reached: {self.per_hour} messages per hour. Try again later."
            )
        if day >= self.per_day:
            raise LimitExceeded(f"Send limit reached: {self.per_day} messages per day.")

    def check(self, username: str) -> None:
        """Raises LimitExceeded if the mailbox can't send now (an early check)."""
        self._check(self.db.conn, username, int(self._clock()))

    def reserve(self, username: str) -> int:
        """Count a message about to be sent; raises LimitExceeded if over a limit.

        Counted before sending, so parallel calls can't all slip through; ``release``
        it if nothing was sent.
        """
        now = int(self._clock())
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM sent_log WHERE sent_at <= ?", (now - DAY,))
            self._check(conn, username, now)
            cursor = conn.execute(
                "INSERT INTO sent_log (mailbox, sent_at, recipients) VALUES (?, ?, 0)",
                (username, now),
            )
        return int(cursor.lastrowid or 0)

    def settle(self, reservation: int, recipients: int) -> None:
        self.db.execute(
            "UPDATE sent_log SET recipients = ? WHERE id = ?", (recipients, reservation)
        )

    def release(self, reservation: int) -> None:
        self.db.execute("DELETE FROM sent_log WHERE id = ?", (reservation,))


class Services:
    def __init__(
        self,
        config: AppConfig,
        db: Database,
        box: Box,
        provider: Provider,
        audit: AuditLog,
        *,
        imap: ImapConnector | None = None,
        smtp: SmtpSender | None = None,
        broker: BrokerClient | None = None,
        carddav: CardDav | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.db = db
        self.box = box
        self.provider = provider
        self.audit = audit
        self.imap = imap or ImapConnector(config)
        self.smtp = smtp or SmtpSender(config)
        self.broker = broker
        self.carddav = carddav
        self.send_limits = SendLimits(db, config.send_limit_hour, config.send_limit_day, clock)
        self.max_message_bytes = config.max_message_mb * 1024 * 1024

    def _token(self, ctx: Context[Any, Any] | None) -> MailboxAccessToken | None:
        token = None
        if ctx is not None:
            request = ctx.request_context.request
            user = getattr(request, "scope", {}).get("user") if request is not None else None
            if isinstance(user, AuthenticatedUser):
                token = user.access_token
        token = token or get_access_token()
        return token if isinstance(token, MailboxAccessToken) else None

    def connection_for(self, ctx: Context[Any, Any] | None) -> Connection:
        token = self._token(ctx)
        if token is None:
            raise ToolError(SIGNED_OUT)
        connected = self.provider.connected(token.grant_id)
        if not connected:
            raise ToolError(SIGNED_OUT)
        client_name = self.provider.client_name_of(token.grant_id)
        return Connection(
            grant_id=token.grant_id,
            client_name=client_name,
            mailboxes=[
                Mailbox(
                    grant_id=token.grant_id,
                    username=m.username,
                    password=m.credential,
                    client_name=client_name,
                    login_method=m.login_method,
                    capability=m.capability,
                )
                for m in connected
            ],
        )

    async def run_imap[T](self, mailbox: Mailbox, work: Callable[[ImapSession], T]) -> T:
        """Run ``work`` in a worker thread with an IMAP session, logged out afterwards."""

        def run() -> T:
            with self.imap.connect(mailbox.username, mailbox.password) as session:
                return work(session)

        return await anyio.to_thread.run_sync(run)

    async def display_name(self, mailbox: Mailbox) -> str:
        """The mailbox's name in mailcow, for From when the client gives none ("" if unknown)."""
        if self.broker is None or mailbox.capability is None:
            return ""  # generic mode, or a password sign-in
        try:
            profile = await self.broker_call(mailbox, "aliases")
        except CapabilityRejected:
            raise
        except MailError as exc:
            log.warning("mailbox name unavailable, sending without one: %s", exc)
            return ""
        name = profile.get("name")
        return name if isinstance(name, str) else ""

    async def broker_call(self, mailbox: Mailbox, operation: str, **body: Any) -> dict[str, Any]:
        """A broker operation for this mailbox (mailcow sign-in connections only)."""
        if self.broker is None or mailbox.capability is None:
            raise MailError(
                f"This needs a mailbox connected with 'Sign in with mailcow' ({mailbox.username} "
                "signed in with a password)."
            )
        return await self.broker.call(operation, capability=mailbox.capability, **body)

    @asynccontextmanager
    async def tool(
        self, ctx: Context[Any, Any] | None, name: str, mailbox: str | None = None
    ) -> AsyncIterator[Mailbox]:
        """Resolve the mailbox the call names; turn mail errors into tool errors, audited.

        A mailbox whose credentials are rejected leaves the connection (the last one ends
        it, so the client is asked to sign in again).
        """
        connection = self.connection_for(ctx)
        selected = connection.select(mailbox)
        try:
            yield selected
        except (CredentialsRejected, CapabilityRejected) as exc:
            raise self._disconnected(connection, selected, name, exc) from exc
        except MailError as exc:
            result = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).lower()
            self.audit(name, result=result, mailbox=selected.username, client=selected.client_name)
            raise ToolError(str(exc)) from exc

    @asynccontextmanager
    async def connection_tool(
        self, ctx: Context[Any, Any] | None, name: str
    ) -> AsyncIterator[Connection]:
        """For tools about the connection itself (its list of mailboxes)."""
        connection = self.connection_for(ctx)
        try:
            yield connection
        except MailError as exc:
            self.audit(name, result="error", client=connection.client_name)
            raise ToolError(str(exc)) from exc

    def _disconnected(
        self, connection: Connection, mailbox: Mailbox, name: str, exc: MailError
    ) -> ToolError:
        """The mailbox's password or app password is gone: take it out of the connection."""
        revoked = isinstance(exc, CapabilityRejected)
        reason = "revoked_capability" if revoked else "credentials_rejected"
        self.provider.remove_mailbox(connection.grant_id, mailbox.username, reason=reason)
        self.audit(name, result=reason, mailbox=mailbox.username, client=mailbox.client_name)
        if len(connection.mailboxes) > 1:
            return ToolError(
                f"{mailbox.username} no longer accepts this connection's password (it may have "
                "been changed, or the app password deleted), so it was disconnected. The other "
                "mailboxes are still connected; add_mailbox connects it again."
            )
        return ToolError(SIGNED_OUT if revoked else str(exc))
