"""Building blocks shared by the tool modules."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from mailcow_mcp.broker_client import RevokedCapability
from mailcow_mcp.config import Mode
from mailcow_mcp.errors import MailError
from mailcow_mcp.imap import ImapSession
from mailcow_mcp.messages import SUMMARY_HEADERS, MessageSummary, summarize
from mailcow_mcp.mime import parse_message
from mailcow_mcp.services import Mailbox, Services

log = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
CHANGES_FLAGS = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)

MAX_FOLDER_NAME = 500
MAX_UIDS = 100

FolderName = Annotated[
    str,
    Field(
        max_length=MAX_FOLDER_NAME,
        description='Folder name from list_folders, or a role: "inbox", "sent", "drafts", "junk", "trash", "archive".',
    ),
]
Uids = Annotated[
    list[int], Field(min_length=1, max_length=MAX_UIDS, description="Message UIDs in the folder.")
]


class Moved(BaseModel):
    from_folder: str
    to_folder: str
    moved: list[int]
    not_found: list[int]
    note: str | None = None


async def with_session[T](
    services: Services, ctx: Context[Any, Any], name: str, work: Callable[[ImapSession], T]
) -> T:
    """Run ``work`` with an IMAP session of the signed-in mailbox, as tool ``name`` (audited)."""
    async with services.tool(ctx, name) as mailbox:
        result = await services.run_imap(mailbox, work)
        services.audit(name, mailbox=mailbox.username, client=mailbox.client_name)
        return result


def summaries(session: ImapSession, folder: str, uids: list[int]) -> list[MessageSummary]:
    """Summaries of messages, in the order of ``uids`` (missing ones are left out)."""
    fetched = session.summaries(folder, uids, SUMMARY_HEADERS)
    result = []
    for uid in uids:
        if uid not in fetched:
            continue
        raw, flags, size, internal = fetched[uid]
        when = internal if isinstance(internal, datetime) else None
        try:
            summary = summarize(uid, folder, parse_message(raw), flags, size, when)
        except Exception:  # one broken message mustn't hide the others
            log.warning("could not summarize message %d in a folder", uid, exc_info=True)
            summary = summarize(uid, folder, parse_message(b""), flags, size, when)
        result.append(summary)
    return result


def move(
    services: Services, session: ImapSession, source: str, uids: list[int], destination: str
) -> Moved:
    """Move the UIDs that exist; report the rest and what the spam filter learns."""
    present = session.existing(source, uids)
    if present:
        session.move(source, present, destination)
    return Moved(
        from_folder=source,
        to_folder=destination,
        moved=present,
        not_found=sorted(set(uids) - set(present)),
        note=training_note(services, session, source, destination),
    )


def training_note(
    services: Services, session: ImapSession, source: str, destination: str
) -> str | None:
    """What moving in or out of Junk teaches the spam filter."""
    junk = session.folder("junk")
    trash = session.folder("trash")
    mailcow = services.config.mode is Mode.MAILCOW
    if source == junk and destination != trash:
        if mailcow:
            return "mailcow reported these messages to its spam filter (rspamd) as not spam."
        return "Moved out of Junk. Depending on the mail server, this may train its spam filter."
    if destination == junk:
        if mailcow:
            return "mailcow reported these messages to its spam filter (rspamd) as spam."
        return "Moved to Junk. Depending on the mail server, this may train its spam filter."
    return None


async def quarantine(
    services: Services, mailbox: Mailbox
) -> tuple[list[dict[str, Any]], str | None]:
    """The mailbox's quarantine items, or none and why (a revoked connection still signs out)."""
    try:
        items: list[dict[str, Any]] = (await services.broker_call(mailbox, "quarantine_list"))[
            "items"
        ]
    except RevokedCapability:
        raise
    except MailError as exc:
        return [], str(exc)
    return items, None
