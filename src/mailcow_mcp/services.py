"""What tools need: the signed-in mailbox, mail connections, limits, audit."""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.config import AppConfig
from mailcow_mcp.crypto import Box
from mailcow_mcp.db import Database
from mailcow_mcp.errors import CredentialsRejected, LimitExceeded, MailError
from mailcow_mcp.imap import ImapConnector
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

    def check(self, username: str) -> None:
        now = int(self._clock())
        self.db.execute("DELETE FROM sent_log WHERE sent_at <= ?", (now - 86400,))
        row = self.db.one(
            "SELECT count(*) AS day, coalesce(sum(sent_at > ?), 0) AS hour FROM sent_log"
            " WHERE mailbox = ?",
            (now - 3600, username),
        )
        day, hour = (row["day"], row["hour"]) if row else (0, 0)
        if hour >= self.per_hour:
            raise LimitExceeded(
                f"Send limit reached: {self.per_hour} messages per hour. Try again later."
            )
        if day >= self.per_day:
            raise LimitExceeded(f"Send limit reached: {self.per_day} messages per day.")

    def record(self, username: str, recipients: int) -> None:
        self.db.execute(
            "INSERT INTO sent_log (mailbox, sent_at, recipients) VALUES (?, ?, ?)",
            (username, int(self._clock()), recipients),
        )


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
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.db = db
        self.box = box
        self.provider = provider
        self.audit = audit
        self.imap = imap or ImapConnector(config)
        self.smtp = smtp or SmtpSender(config)
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

    @asynccontextmanager
    async def tool(self, ctx: Context[Any, Any] | None, name: str) -> AsyncIterator[Mailbox]:
        """Resolve the mailbox; turn mail errors into tool errors, audited.

        Rejected credentials end the grant, so the client is asked to sign in again.
        """
        mailbox = self.mailbox_for(ctx)
        try:
            yield mailbox
        except CredentialsRejected as exc:
            self.provider.revoke_grant(mailbox.grant_id, reason="credentials_rejected")
            self.audit(
                name,
                result="credentials_rejected",
                mailbox=mailbox.username,
                client=mailbox.client_name,
            )
            raise ToolError(str(exc)) from exc
        except MailError as exc:
            result = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).lower()
            self.audit(name, result=result, mailbox=mailbox.username, client=mailbox.client_name)
            raise ToolError(str(exc)) from exc
