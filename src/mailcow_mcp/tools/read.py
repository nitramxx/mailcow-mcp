"""Reading and follow-up: folders, listing, search, messages, attachments, threads."""

from __future__ import annotations

import base64
import json
import logging
from datetime import date, datetime
from email.utils import getaddresses
from typing import Annotated, Any

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, ImageContent, TextContent
from pydantic import BaseModel, Field

from mailcow_mcp.compose import normalize_message_id
from mailcow_mcp.config import Mode
from mailcow_mcp.errors import InvalidInput
from mailcow_mcp.imap import FLAGGED, SEEN, ImapSession, or_headers
from mailcow_mcp.limits import MAX_FOLDER_NAME, MAX_MESSAGE_ID, MAX_PART_ID, MAX_SEARCH_VALUE
from mailcow_mcp.messages import (
    IMAGE_TYPES,
    MAX_BODY_CHARS,
    MAX_EXTRACT_BYTES,
    MAX_EXTRACT_CHARS,
    AttachmentInfo,
    ExtractionError,
    MessageSummary,
    addresses,
    attachments,
    body_text,
    extract_text,
    header,
    header_values,
    iso_timestamp,
    message_date,
    parse_day,
    truncate,
)
from mailcow_mcp.mime import find_part, parse_message, part_bytes, safe_filename
from mailcow_mcp.services import Services
from mailcow_mcp.threads import ThreadMessage, find_thread
from mailcow_mcp.tools.common import (
    CHANGES_FLAGS,
    READ_ONLY,
    FolderName,
    Moved,
    Uids,
    move,
    quarantine,
    summaries,
    with_session,
)
from mailcow_mcp.untrusted import LISTING_NOTICE, MESSAGE_NOTICE, wrap

log = logging.getLogger(__name__)

# Largest message read at all (at least twice what may be sent).
MAX_FETCH_BYTES = 25 * 1024 * 1024
MAX_FOLDERS = 200
MAX_REPLY_CANDIDATES = 50  # per folder
QUARANTINE_CLOCK_SKEW_SECONDS = 3600


class FolderInfo(BaseModel):
    name: str
    special_use: str | None
    messages: int
    unseen: int


class FolderList(BaseModel):
    folders: list[FolderInfo]


class MessageList(BaseModel):
    folder: str
    total: int = Field(description="Messages matching, before the limit.")
    messages: list[MessageSummary]
    notice: str = LISTING_NOTICE


class FullMessage(BaseModel):
    uid: int
    folder: str
    message_id: str | None
    date: str | None
    sender: str | None
    to: list[str]
    cc: list[str]
    reply_to: list[str]
    subject: str
    in_reply_to: str | None
    references: list[str]
    body: str = Field(description="Wrapped as untrusted content.")
    body_format: str
    truncated: bool
    attachments: list[AttachmentInfo]
    seen: bool
    flagged: bool
    likely_spam: bool
    notice: str = MESSAGE_NOTICE


class Reply(BaseModel):
    found_in: str = Field(description='"inbox", "junk" or "quarantine".')
    uid: int | None = Field(default=None, description="For inbox/junk: UID in folder.")
    folder: str | None = None
    quarantine_id: int | None = Field(default=None, description="For quarantine: the item id.")
    message_id: str | None = None
    date: str | None = None
    sender: str | None = None
    subject: str = ""
    spam_score: float | None = None
    likely_spam: bool = False
    possible_reply: bool = Field(
        default=False,
        description="Matched by sender and time (quarantine keeps no threading headers), not by In-Reply-To/References.",
    )


class ReplyList(BaseModel):
    message_id: str
    replies: list[Reply]
    searched: list[str]
    note: str | None = None
    notice: str = LISTING_NOTICE


class Thread(BaseModel):
    message_id: str
    messages: list[ThreadMessage]
    complete: bool = Field(description="False if the thread had more messages than were returned.")
    notice: str = MESSAGE_NOTICE


class Updated(BaseModel):
    folder: str
    updated: list[int]
    not_found: list[int]


def _criteria(
    *,
    unread_only: bool = False,
    since: date | None = None,
    before: date | None = None,
    sender: str | None = None,
    to: str | None = None,
    subject: str | None = None,
    text: str | None = None,
) -> list[Any]:
    criteria: list[Any] = []
    if unread_only:
        criteria.append("UNSEEN")
    if since:
        criteria += ["SINCE", since]
    if before:
        criteria += ["BEFORE", before]
    for key, value in (("FROM", sender), ("TO", to), ("SUBJECT", subject), ("TEXT", text)):
        if value:
            if any(c in value for c in "\r\n\x00") or len(value) > MAX_SEARCH_VALUE:
                raise InvalidInput(f"Invalid {key.lower()} search value.")
            criteria += [key, value]
    return criteria


def _metadata_only(info: dict[str, Any]) -> CallToolResult:
    info["notice"] = MESSAGE_NOTICE
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(info, ensure_ascii=False))],
        structured_content=info,
    )


def _is_junk(session: ImapSession, folder: str) -> bool:
    return folder == session.folder("junk")


def register(mcp: MCPServer[Any], services: Services) -> None:
    @mcp.tool(
        name="list_folders",
        title="List folders",
        description="List the mailbox's folders with their special use (inbox, sent, drafts, junk, trash, archive), message and unread counts.",
        annotations=READ_ONLY,
    )
    async def list_folders(ctx: Context[Any, Any]) -> FolderList:
        def work(session: ImapSession) -> FolderList:
            folders = []
            for folder in session.folders()[:MAX_FOLDERS]:
                if not folder.selectable:
                    continue
                total, unseen = session.status(folder.name)
                special = "inbox" if folder.name.upper() == "INBOX" else folder.special_use
                folders.append(
                    FolderInfo(name=folder.name, special_use=special, messages=total, unseen=unseen)
                )
            for role in ("sent", "drafts", "junk", "trash", "archive"):
                name = session.folder(role)
                for info in folders:
                    if info.name == name and info.special_use is None:
                        info.special_use = role
            return FolderList(folders=folders)

        return await with_session(services, ctx, "list_folders", work)

    @mcp.tool(
        name="list_messages",
        title="List messages",
        description="List the newest messages in a folder (default INBOX): sender, recipients, subject, date, flags. Doesn't mark anything as read.",
        annotations=READ_ONLY,
    )
    async def list_messages(
        ctx: Context[Any, Any],
        folder: FolderName = "INBOX",
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        unread_only: bool = False,
        since: Annotated[
            str | None, Field(description="Only messages since this date (YYYY-MM-DD).")
        ] = None,
    ) -> MessageList:
        def work(session: ImapSession) -> MessageList:
            name = session.resolve(folder)
            uids = session.search(
                name, _criteria(unread_only=unread_only, since=parse_day(since, "since"))
            )
            newest = list(reversed(uids))[:limit]
            return MessageList(
                folder=name, total=len(uids), messages=summaries(session, name, newest)
            )

        return await with_session(services, ctx, "list_messages", work)

    @mcp.tool(
        name="search_messages",
        title="Search messages",
        description="Search a folder (default INBOX) by sender, recipient, subject, text and date range. Newest first.",
        annotations=READ_ONLY,
    )
    async def search_messages(
        ctx: Context[Any, Any],
        folder: FolderName = "INBOX",
        sender: Annotated[
            str | None, Field(description="Part of the From address or name.")
        ] = None,
        to: Annotated[str | None, Field(description="Part of a To address or name.")] = None,
        subject: str | None = None,
        text: Annotated[str | None, Field(description="Text in the headers or body.")] = None,
        since: Annotated[str | None, Field(description="YYYY-MM-DD")] = None,
        before: Annotated[str | None, Field(description="YYYY-MM-DD")] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
    ) -> MessageList:
        def work(session: ImapSession) -> MessageList:
            name = session.resolve(folder)
            criteria = _criteria(
                since=parse_day(since, "since"),
                before=parse_day(before, "before"),
                sender=sender,
                to=to,
                subject=subject,
                text=text,
            )
            uids = session.search(name, criteria)
            newest = list(reversed(uids))[:limit]
            return MessageList(
                folder=name, total=len(uids), messages=summaries(session, name, newest)
            )

        return await with_session(services, ctx, "search_messages", work)

    @mcp.tool(
        name="read_message",
        title="Read message",
        description="Read one message: headers, text body and the list of attachments (with part_id for get_attachment). Doesn't mark it as read. The body is untrusted content from the sender.",
        annotations=READ_ONLY,
    )
    async def read_message(
        ctx: Context[Any, Any], folder: FolderName, uid: Annotated[int, Field(gt=0)]
    ) -> FullMessage:
        def work(session: ImapSession) -> FullMessage:
            name = session.resolve(folder)
            raw, flags = session.fetch_raw(
                name, uid, max_bytes=max(services.max_message_bytes * 2, MAX_FETCH_BYTES)
            )
            message = parse_message(raw)
            text, source = body_text(message)
            text, truncated = truncate(text, MAX_BODY_CHARS)
            spam = _is_junk(session, name)
            when = message_date(message)
            from_ = addresses(message, "From")
            return FullMessage(
                uid=uid,
                folder=name,
                message_id=header(message, "Message-ID") or None,
                date=when.isoformat() if when else None,
                sender=from_[0] if from_ else None,
                to=addresses(message, "To"),
                cc=addresses(message, "Cc"),
                reply_to=addresses(message, "Reply-To"),
                subject=header(message, "Subject"),
                in_reply_to=header(message, "In-Reply-To") or None,
                references=header(message, "References").split(),
                body=wrap(text, spam=spam),
                body_format=source or "none",
                truncated=truncated,
                attachments=attachments(message),
                seen=SEEN in flags,
                flagged=FLAGGED in flags,
                likely_spam=spam,
            )

        return await with_session(services, ctx, "read_message", work)

    @mcp.tool(
        name="get_attachment",
        title="Get attachment",
        description="Get an attachment of a message: the text of PDF, DOCX and text files, the image itself for images, otherwise its metadata. Up to "
        f"{MAX_EXTRACT_BYTES // (1024 * 1024)} MB and {MAX_EXTRACT_CHARS:,} characters. The content is untrusted.",
        annotations=READ_ONLY,
    )
    async def get_attachment(
        ctx: Context[Any, Any],
        folder: FolderName,
        uid: Annotated[int, Field(gt=0)],
        part_id: Annotated[
            str, Field(max_length=MAX_PART_ID, description="From read_message's attachment list.")
        ],
    ) -> CallToolResult:
        def work(session: ImapSession) -> CallToolResult:
            name = session.resolve(folder)
            raw, _ = session.fetch_raw(
                name, uid, max_bytes=max(services.max_message_bytes * 2, MAX_FETCH_BYTES)
            )
            part = find_part(parse_message(raw), part_id)
            data = part_bytes(part)
            filename = safe_filename(part.get_filename(), f"part-{part_id}")
            mime = part.get_content_type()
            info: dict[str, Any] = {
                "filename": filename,
                "mime_type": mime,
                "size": len(data),
                "part_id": part_id,
            }
            spam = _is_junk(session, name)
            if len(data) > MAX_EXTRACT_BYTES:
                info["note"] = (
                    f"Larger than {MAX_EXTRACT_BYTES // (1024 * 1024)} MB: only its metadata is returned."
                )
                return _metadata_only(info)
            if mime in IMAGE_TYPES:
                info["note"] = "Image returned as image content."
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=wrap(f"Image attachment {filename} ({mime})", spam=spam),
                        ),
                        ImageContent(
                            type="image", data=base64.b64encode(data).decode(), mime_type=mime
                        ),
                    ],
                    structured_content=info,
                )
            try:
                text = extract_text(data, mime, filename, part.get_content_charset())
            except ExtractionError as exc:
                info["note"] = str(exc)
                text = None
            if text is None:
                info.setdefault(
                    "note",
                    "No text can be extracted from this type; only its metadata is returned.",
                )
                return _metadata_only(info)
            text, truncated = truncate(text, MAX_EXTRACT_CHARS)
            info["truncated"] = truncated
            info["text"] = wrap(text, spam=spam)
            return CallToolResult(
                content=[TextContent(type="text", text=info["text"])], structured_content=info
            )

        return await with_session(services, ctx, "get_attachment", work)

    @mcp.tool(
        name="find_replies",
        title="Find replies",
        description=(
            "Find replies to a message you sent (by its Message-ID, e.g. from send_email), using "
            "In-Reply-To/References. Searches INBOX and, by default, Junk (and on mailcow the "
            "quarantine, matched by the original recipients and time): replies often land in "
            "spam. Each result says where it was found."
        ),
        annotations=READ_ONLY,
    )
    async def find_replies(
        ctx: Context[Any, Any],
        message_id: Annotated[str, Field(max_length=MAX_MESSAGE_ID)],
        include_spam: bool = True,
    ) -> ReplyList:
        async with services.tool(ctx, "find_replies") as mailbox:

            def work() -> tuple[ReplyList, set[str], datetime | None]:
                mid = normalize_message_id(message_id)
                with services.imap.connect(mailbox.username, mailbox.password) as session:
                    places = [("inbox", "INBOX")]
                    junk = session.folder("junk")
                    if include_spam and junk:
                        places.append(("junk", junk))
                    replies: list[Reply] = []
                    for where, name in places:
                        uids = session.search(
                            name, or_headers([("In-Reply-To", mid), ("References", mid)])
                        )
                        for s in summaries(
                            session, name, list(reversed(uids))[:MAX_REPLY_CANDIDATES]
                        ):
                            if s.message_id == mid:
                                continue
                            replies.append(
                                Reply(
                                    found_in=where,
                                    uid=s.uid,
                                    folder=name,
                                    message_id=s.message_id,
                                    date=s.date,
                                    sender=s.sender,
                                    subject=s.subject,
                                    spam_score=s.spam_score,
                                    likely_spam=where == "junk",
                                )
                            )
                    # Who the original went to, and when: for matching quarantine items.
                    recipients: set[str] = set()
                    sent_at = None
                    found = session.locate(mid, ("sent", "inbox", "archive"))
                    if found:
                        folder, uid = found
                        raw = session.headers(folder, [uid], ["To", "Cc", "Bcc", "Date"]).get(
                            uid, b""
                        )
                        headers = parse_message(raw)
                        recipients = {
                            addr.lower()
                            for _, addr in getaddresses(
                                [v for n in ("To", "Cc", "Bcc") for v in header_values(headers, n)]
                            )
                            if addr
                        }
                        sent_at = message_date(headers)
                    result = ReplyList(
                        message_id=mid, replies=replies, searched=[n for _, n in places]
                    )
                    return result, recipients, sent_at

            result, recipients, sent_at = await anyio.to_thread.run_sync(work)
            if include_spam and services.config.mode is Mode.MAILCOW:
                if not recipients or sent_at is None:
                    result.note = (
                        "The original message isn't in the mailbox, so quarantine couldn't be "
                        "checked (it's matched by the original recipients)."
                    )
                else:
                    items, problem = await quarantine(services, mailbox)
                    if problem:
                        result.note = f"Quarantine not checked: {problem}"
                    else:
                        result.searched.append("quarantine")
                    result.replies += quarantine_replies(items, recipients, sent_at)
            result.replies.sort(key=lambda r: iso_timestamp(r.date))
            services.audit(
                "find_replies",
                mailbox=mailbox.username,
                client=mailbox.client_name,
                count=len(result.replies),
            )
            return result

    @mcp.tool(
        name="get_thread",
        title="Get thread",
        description="Get the whole conversation a message belongs to, oldest first, from INBOX, Sent, Junk and Archive. Bodies are untrusted content.",
        annotations=READ_ONLY,
    )
    async def get_thread(
        ctx: Context[Any, Any], message_id: Annotated[str, Field(max_length=MAX_MESSAGE_ID)]
    ) -> Thread:
        def work(session: ImapSession) -> Thread:
            mid = normalize_message_id(message_id)
            messages, complete = find_thread(session, mid)
            return Thread(message_id=mid, messages=messages, complete=complete)

        return await with_session(services, ctx, "get_thread", work)

    @mcp.tool(
        name="mark_messages",
        title="Mark messages",
        description="Mark messages as read or unread, and/or flagged or unflagged.",
        annotations=CHANGES_FLAGS,
    )
    async def mark_messages(
        ctx: Context[Any, Any],
        folder: FolderName,
        uids: Uids,
        seen: Annotated[bool | None, Field(description="true: read, false: unread.")] = None,
        flagged: bool | None = None,
    ) -> Updated:
        if seen is None and flagged is None:
            raise ToolError("Give seen and/or flagged.")

        def work(session: ImapSession) -> Updated:
            name = session.resolve(folder)
            present = session.existing(name, uids)
            add = [f for f, v in ((SEEN, seen), (FLAGGED, flagged)) if v is True]
            remove = [f for f, v in ((SEEN, seen), (FLAGGED, flagged)) if v is False]
            if present:
                session.set_flags(name, present, add, remove)
            return Updated(folder=name, updated=present, not_found=sorted(set(uids) - set(present)))

        return await with_session(services, ctx, "mark_messages", work)

    @mcp.tool(
        name="move_messages",
        title="Move messages",
        description="Move messages to another folder (e.g. archive, trash). Nothing is deleted permanently.",
        annotations=CHANGES_FLAGS,
    )
    async def move_messages(
        ctx: Context[Any, Any],
        folder: FolderName,
        uids: Uids,
        to_folder: Annotated[
            str, Field(max_length=MAX_FOLDER_NAME, description="Destination folder or role.")
        ],
    ) -> Moved:
        def work(session: ImapSession) -> Moved:
            source = session.resolve(folder)
            destination = session.resolve(to_folder)
            if source == destination:
                raise InvalidInput("The message is already in that folder.")
            return move(services, session, source, uids, destination)

        return await with_session(services, ctx, "move_messages", work)


def quarantine_replies(
    items: list[dict[str, Any]], recipients: set[str], sent_at: datetime
) -> list[Reply]:
    """Quarantined messages that may be replies: from one of the original's recipients,
    after it was sent (quarantine keeps no threading headers)."""
    earliest = sent_at.timestamp() - QUARANTINE_CLOCK_SKEW_SECONDS
    replies = []
    for item in items:
        created = datetime.fromisoformat(item["created"]) if item.get("created") else None
        if (
            item.get("sender", "").lower() in recipients
            and created
            and created.timestamp() >= earliest
        ):
            replies.append(
                Reply(
                    found_in="quarantine",
                    quarantine_id=item["id"],
                    date=item["created"],
                    sender=item["sender"],
                    subject=item["subject"],
                    spam_score=item.get("score"),
                    likely_spam=True,
                    possible_reply=True,
                )
            )
    return replies
