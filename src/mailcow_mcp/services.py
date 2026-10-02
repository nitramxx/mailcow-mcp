"""What tools need: the signed-in mailbox, mail connections, limits, audit."""

from __future__ import annotations

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
from mailcow_mcp.broker_client import BrokerClient, RevokedCapability
from mailcow_mcp.config import AppConfig
from mailcow_mcp.contacts import CardDav
from mailcow_mcp.crypto import Box
from mailcow_mcp.db import Database
from mailcow_mcp.errors import CredentialsRejected, LimitExceeded, MailError
from mailcow_mcp.imap import ImapConnector, ImapSession
from mailcow_mcp.oauth import MailboxAccessToken, Provider
from mailcow_mcp.smtp import SmtpSender

SIGNED_OUT = "This connection has been signed out. Reconnect the app to sign in again."


@dataclass(frozen=True)
class Mailbox:
    """The mailbox the current request acts as."""

    grant_id: int
    username: str
    password: str = ""
    client_name: str | None = None

    def __repr__(self) -> str:
        return f"Mailbox({self.username!r}, grant={self.grant_id})"


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
            (now - 3600, username, now - 86400),
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
            conn.execute("DELETE FROM sent_log WHERE sent_at <= ?", (now - 86400,))
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

    def mailbox_for(self, ctx: Context[Any, Any] | None) -> Mailbox:
        token = self._token(ctx)
        if token is None:
            raise ToolError(SIGNED_OUT)
        row = self.db.one(
            "SELECT g.credential_enc, m.username, c.client_name FROM grants g"
            " JOIN mailboxes m ON m.id = g.mailbox_id JOIN clients c ON c.client_id = g.client_id"
            " WHERE g.id = ?",
            (token.grant_id,),
        )
        if row is None:
            raise ToolError(SIGNED_OUT)
        return Mailbox(
            grant_id=token.grant_id,
            username=row["username"],
            password=self.box.decrypt(row["credential_enc"]),
            client_name=row["client_name"],
        )

    async def run_imap[T](self, mailbox: Mailbox, work: Callable[[ImapSession], T]) -> T:
        """Run ``work`` in a worker thread with an IMAP session, logged out afterwards."""

        def run() -> T:
            with self.imap.connect(mailbox.username, mailbox.password) as session:
                return work(session)

        return await anyio.to_thread.run_sync(run)

    async def broker_call(self, mailbox: Mailbox, operation: str, **body: Any) -> dict[str, Any]:
        """A broker operation for this mailbox (mailcow sign-in connections only)."""
        capability = self.provider.capability_of(mailbox.grant_id)
        if self.broker is None or capability is None:
            raise MailError(
                "This needs a connection made with 'Sign in with mailcow' (this one signed in "
                "with a password)."
            )
        return await self.broker.call(operation, capability=capability, **body)

    @asynccontextmanager
    async def tool(self, ctx: Context[Any, Any] | None, name: str) -> AsyncIterator[Mailbox]:
        """Resolve the mailbox; turn mail errors into tool errors, audited.

        Rejected credentials end the grant, so the client is asked to sign in again.
        """
        mailbox = self.mailbox_for(ctx)
        try:
            yield mailbox
        except (CredentialsRejected, RevokedCapability) as exc:
            revoked = isinstance(exc, RevokedCapability)
            reason = "revoked_capability" if revoked else "credentials_rejected"
            self.provider.revoke_grant(mailbox.grant_id, reason=reason)
            self.audit(name, result=reason, mailbox=mailbox.username, client=mailbox.client_name)
            raise ToolError(SIGNED_OUT if revoked else str(exc)) from exc
        except MailError as exc:
            result = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).lower()
            self.audit(name, result=result, mailbox=mailbox.username, client=mailbox.client_name)
            raise ToolError(str(exc)) from exc
