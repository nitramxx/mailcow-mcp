"""Conversations: the messages a Message-ID's thread consists of, across folders."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from mailcow_mcp.imap import ImapSession, or_headers
from mailcow_mcp.limits import MAX_REFERENCES
from mailcow_mcp.messages import addresses, body_text, header, message_date, truncate
from mailcow_mcp.mime import parse_message
from mailcow_mcp.untrusted import wrap

MAX_MESSAGES = 30  # the newest of a longer thread
MAX_CANDIDATES = 500  # per folder
MAX_BYTES = 50 * 1024 * 1024  # all bodies of one thread together
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_THREAD_BODY_CHARS = 10_000  # per message
_ROLES = ("sent", "junk", "archive")


class ThreadMessage(BaseModel):
    uid: int
    folder: str
    message_id: str | None
    date: str | None
    sender: str | None
    to: list[str]
    subject: str
    body: str
    truncated: bool
    likely_spam: bool


def find_thread(session: ImapSession, message_id: str) -> tuple[list[ThreadMessage], bool]:
    """The thread's messages, oldest first, and whether that is all of them.

    Searches INBOX, Sent, Junk and Archive for the message, its replies and its
    ancestors (two rounds of References/In-Reply-To), then reads the newest
    MAX_MESSAGES of them, one per Message-ID.
    """
    folders = ["INBOX"] + [f for f in (session.folder(r) for r in _ROLES) if f]
    junk = session.folder("junk")
    found = _related(session, folders, message_id)

    # Pick by headers first: the newest last, one per Message-ID.
    candidates: dict[str, tuple[float, str, int, int]] = {}
    for folder in folders:
        uids = [u for f, u in found if f == folder][:MAX_CANDIDATES]
        for uid, (raw, _flags, size, internal) in session.summaries(
            folder, uids, ["Message-ID", "Date"]
        ).items():
            headers = parse_message(raw)
            when = message_date(headers, internal if isinstance(internal, datetime) else None)
            key = header(headers, "Message-ID") or f"{folder}/{uid}"
            # The same message in two folders (e.g. sent to yourself): keep one.
            candidates.setdefault(key, (when.timestamp() if when else 0, folder, uid, size))

    messages = []
    budget = MAX_BYTES
    for _, folder, uid, size in sorted(candidates.values())[-MAX_MESSAGES:]:
        if size > min(budget, MAX_MESSAGE_BYTES):
            continue  # too large for a thread view; read_message can try
        budget -= size
        raw, _ = session.fetch_raw(folder, uid, max_bytes=MAX_MESSAGE_BYTES)
        messages.append(_entry(folder, uid, raw, spam=folder == junk))
    return messages, len(messages) == len(candidates)


def _related(
    session: ImapSession, folders: list[str], message_id: str
) -> dict[tuple[str, int], None]:
    """(folder, uid) of messages that are, reply to or are referenced by the thread."""
    ids = {message_id}
    found: dict[tuple[str, int], None] = {}
    for _round in range(2):
        searches = [
            (name, value)
            for value in sorted(ids)[:MAX_REFERENCES]
            for name in ("Message-ID", "References", "In-Reply-To")
        ]
        for folder in folders:
            for uid in session.search(folder, or_headers(searches)):
                found[(folder, uid)] = None
        # Ancestors: what the found messages reference.
        new_ids = set(ids)
        for folder in folders:
            uids = [u for f, u in found if f == folder]
            for raw in session.headers(
                folder, uids, ["Message-ID", "References", "In-Reply-To"]
            ).values():
                headers = parse_message(raw)
                for name in ("Message-ID", "In-Reply-To"):
                    if value := header(headers, name):
                        new_ids.add(value)
                new_ids.update(header(headers, "References").split())
        if new_ids == ids:
            break
        ids = new_ids
    return found


def _entry(folder: str, uid: int, raw: bytes, *, spam: bool) -> ThreadMessage:
    message = parse_message(raw)
    text, _source = body_text(message)
    text, truncated = truncate(text, MAX_THREAD_BODY_CHARS)
    when = message_date(message)
    from_ = addresses(message, "From")
    return ThreadMessage(
        uid=uid,
        folder=folder,
        message_id=header(message, "Message-ID") or None,
        date=when.isoformat() if when else None,
        sender=from_[0] if from_ else None,
        to=addresses(message, "To"),
        subject=header(message, "Subject"),
        body=wrap(text, spam=spam),
        truncated=truncated,
        likely_spam=spam,
    )
