"""IMAP access.

imapclient is synchronous: a session is opened per tool call and used from a
worker thread (``anyio.to_thread``). Reads use BODY.PEEK so they never set \\Seen.
"""

from __future__ import annotations

import enum
import logging
import re
import ssl
from collections.abc import Iterable, Sequence
from types import TracebackType
from typing import Any, Protocol

import anyio
import imapclient
from imapclient.exceptions import IMAPClientError, LoginError

from mailcow_mcp.config import AppConfig, Security
from mailcow_mcp.errors import CredentialsRejected, MailError, NotFound, ServerUnavailable
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 30

SPECIAL_USE_FLAGS = {
    "sent": b"\\Sent",
    "drafts": b"\\Drafts",
    "junk": b"\\Junk",
    "trash": b"\\Trash",
    "archive": b"\\Archive",
}
COMMON_NAMES = {
    "sent": ["Sent", "Sent Items", "Sent Messages", "Sent Mail", "Odeslané", "Odeslaná pošta"],
    "drafts": ["Drafts", "Draft", "Koncepty", "Rozepsané"],
    "junk": ["Junk", "Spam", "Junk E-mail", "Junk Email", "Bulk Mail", "Nevyžádaná pošta"],
    "trash": ["Trash", "Deleted Items", "Deleted Messages", "Bin", "Koš"],
    "archive": ["Archive", "Archives", "Archiv"],
}
_APPENDUID_RE = re.compile(rb"\[APPENDUID \d+ (\d+)\]", re.IGNORECASE)

SEEN = imapclient.SEEN
DRAFT = imapclient.DRAFT
FLAGGED = imapclient.FLAGGED
DELETED = imapclient.DELETED


class LoginResult(enum.Enum):
    OK = "ok"
    INVALID = "invalid_credentials"
    UNAVAILABLE = "server_unavailable"


class PasswordVerifier(Protocol):
    async def __call__(self, username: str, password: str) -> LoginResult: ...


class Folder:
    def __init__(self, name: str, flags: Sequence[bytes], delimiter: str | None) -> None:
        self.name = name
        self.flags = tuple(flags)
        self.delimiter = delimiter

    @property
    def leaf(self) -> str:
        if self.delimiter and self.delimiter in self.name:
            return self.name.rsplit(self.delimiter, 1)[1]
        return self.name

    @property
    def selectable(self) -> bool:
        return b"\\Noselect" not in self.flags and b"\\NonExistent" not in self.flags

    @property
    def special_use(self) -> str | None:
        for role, flag in SPECIAL_USE_FLAGS.items():
            if flag in self.flags:
                return role
        return None


class ImapSession:
    """One logged-in IMAP connection. Use as a context manager."""

    def __init__(self, client: imapclient.IMAPClient, folder_names: dict[str, str]) -> None:
        self.client = client
        self._folder_names = folder_names
        self._folders: list[Folder] | None = None
        self._selected: tuple[str, bool] | None = None

    def __enter__(self) -> ImapSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.client.logout()
        except (OSError, IMAPClientError):
            self.client.shutdown()

    # --- folders -------------------------------------------------------------

    def folders(self) -> list[Folder]:
        if self._folders is None:
            listed = self.client.list_folders()
            self._folders = [
                Folder(
                    name,
                    flags,
                    delimiter.decode() if isinstance(delimiter, bytes) else delimiter,
                )
                for flags, delimiter, name in listed
            ]
        return self._folders

    def folder(self, role: str) -> str | None:
        """The folder for a role (sent, drafts, junk, trash, archive), or None."""
        folders = [f for f in self.folders() if f.selectable]
        for f in folders:
            if f.special_use == role:
                return f.name
        names = [n for n in [self._folder_names.get(role)] if n] + COMMON_NAMES[role]
        for wanted in names:
            for f in folders:
                if f.name.casefold() == wanted.casefold():
                    return f.name
            for f in folders:
                if f.leaf.casefold() == wanted.casefold():
                    return f.name
        return None

    def require_folder(self, role: str) -> str:
        name = self.folder(role)
        if name is None:
            raise NotFound(f"This mailbox has no {role} folder.")
        return name

    def resolve(self, folder: str) -> str:
        """A folder name given by the client, matched exactly or case-insensitively."""
        names = [f.name for f in self.folders() if f.selectable]
        if folder in names:
            return folder
        if folder.upper() == "INBOX":
            return "INBOX"
        for name in names:
            if name.casefold() == folder.casefold():
                return name
        role = folder.casefold()
        if role in SPECIAL_USE_FLAGS and (found := self.folder(role)):
            return found
        raise NotFound(f"No folder named {folder!r}. Use list_folders to see the folders.")

    def select(self, folder: str, *, readonly: bool = True) -> dict[bytes, Any]:
        if self._selected == (folder, readonly):
            return {}
        result: dict[bytes, Any] = self.client.select_folder(folder, readonly=readonly)
        self._selected = (folder, readonly)
        return result

    def status(self, folder: str) -> tuple[int, int]:
        """(messages, unseen) without selecting the folder."""
        data = self.client.folder_status(folder, [b"MESSAGES", b"UNSEEN"])
        return int(data.get(b"MESSAGES", 0)), int(data.get(b"UNSEEN", 0))

    # --- messages ------------------------------------------------------------

    def search(self, folder: str, criteria: list[Any]) -> list[int]:
        self.select(folder)
        uids: list[int] = self.client.search(criteria or ["ALL"], charset="UTF-8")
        return sorted(uids)

    def summaries(
        self, folder: str, uids: Sequence[int], header_names: Sequence[str]
    ) -> dict[int, tuple[bytes, tuple[bytes, ...], int, Any]]:
        """Headers, flags, size and internal date of messages (without setting \\Seen)."""
        if not uids:
            return {}
        self.select(folder)
        item = f"BODY.PEEK[HEADER.FIELDS ({' '.join(n.upper() for n in header_names)})]".encode()
        data = self.client.fetch(list(uids), [item, b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE"])
        result = {}
        for uid, fields in data.items():
            headers = next(
                (
                    v
                    for k, v in fields.items()
                    if isinstance(k, bytes) and k.startswith(b"BODY[HEADER")
                ),
                b"",
            )
            result[uid] = (
                headers or b"",
                tuple(fields.get(b"FLAGS", ())),
                int(fields.get(b"RFC822.SIZE", 0)),
                fields.get(b"INTERNALDATE"),
            )
        return result

    def existing(self, folder: str, uids: Sequence[int]) -> list[int]:
        self.select(folder)
        found = self.client.fetch(list(uids), [b"UID"]) if uids else {}
        return sorted(uid for uid in uids if uid in found)

    def set_flags(
        self, folder: str, uids: Sequence[int], add: list[bytes], remove: list[bytes]
    ) -> None:
        self.select(folder, readonly=False)
        if add:
            self.client.add_flags(list(uids), add, silent=True)
        if remove:
            self.client.remove_flags(list(uids), remove, silent=True)

    def move(self, folder: str, uids: Sequence[int], destination: str) -> None:
        """Move messages (MOVE, or COPY + expunge of exactly those UIDs)."""
        self.select(folder, readonly=False)
        if self.client.has_capability("MOVE"):
            self.client.move(list(uids), destination)
            return
        self.client.copy(list(uids), destination)
        self.client.add_flags(list(uids), [DELETED], silent=True)
        if self.client.has_capability("UIDPLUS"):
            self.client.uid_expunge(list(uids))
        else:
            self.client.expunge()

    def append(self, folder: str, message: bytes, flags: Iterable[bytes]) -> int | None:
        """Store a message; returns its UID when the server reports it (UIDPLUS)."""
        response = self.client.append(folder, message, flags=tuple(flags))
        match = _APPENDUID_RE.search(response if isinstance(response, bytes) else b"")
        return int(match.group(1)) if match else None

    def find_message_id(self, folder: str, message_id: str) -> list[int]:
        self.select(folder)
        uids: list[int] = self.client.search(["HEADER", "Message-ID", message_id])
        return uids

    def headers(self, folder: str, uids: Sequence[int], names: Sequence[str]) -> dict[int, bytes]:
        """Selected header fields (raw bytes) of messages, without setting \\Seen."""
        if not uids:
            return {}
        self.select(folder)
        item = f"BODY.PEEK[HEADER.FIELDS ({' '.join(n.upper() for n in names)})]".encode()
        data = self.client.fetch(list(uids), [item])
        result: dict[int, bytes] = {}
        for uid, fields in data.items():
            for key, value in fields.items():
                if isinstance(key, bytes) and key.startswith(b"BODY[HEADER"):
                    result[uid] = value or b""
        return result

    def locate(
        self, message_id: str, roles: Sequence[str] = ("inbox", "sent", "archive")
    ) -> tuple[str, int] | None:
        """Find a message by Message-ID in INBOX and the given special folders."""
        for role in roles:
            folder = "INBOX" if role == "inbox" else self.folder(role)
            if folder is None:
                continue
            uids = self.find_message_id(folder, message_id)
            if uids:
                return folder, max(uids)
        return None

    def size(self, folder: str, uid: int) -> int:
        self.select(folder)
        data = self.client.fetch([uid], [b"RFC822.SIZE"])
        if uid not in data:
            raise NotFound(f"No message with UID {uid} in {folder}.")
        return int(data[uid][b"RFC822.SIZE"])

    def fetch_raw(
        self, folder: str, uid: int, *, max_bytes: int
    ) -> tuple[bytes, tuple[bytes, ...]]:
        """The full message (without setting \\Seen) and its flags."""
        if self.size(folder, uid) > max_bytes:
            raise MailError(f"The message is larger than {max_bytes // (1024 * 1024)} MB.")
        data = self.client.fetch([uid], [b"BODY.PEEK[]", b"FLAGS"])
        if uid not in data:
            raise NotFound(f"No message with UID {uid} in {folder}.")
        return data[uid][b"BODY[]"], tuple(data[uid][b"FLAGS"])

    def delete(self, folder: str, uid: int) -> None:
        """Permanently remove one message (used for drafts only)."""
        self.select(folder, readonly=False)
        self.client.add_flags([uid], [DELETED], silent=True)
        if self.client.has_capability("UIDPLUS"):
            self.client.uid_expunge([uid])
        else:
            self.client.expunge()

    def gmail(self) -> bool:
        """Gmail files sent mail itself (SAVE_SENT=auto)."""
        return bool(self.client.has_capability("X-GM-EXT-1"))


class ImapConnector:
    def __init__(self, config: AppConfig) -> None:
        self.host = config.imap_host
        self.port = config.imap_port
        self.security = config.imap_security
        self.folder_names = config.folder_names
        self.context = client_context(
            server_name=config.tls_server_name, verify=config.tls_verify, ca_file=config.tls_ca_file
        )

    def connect(self, username: str, password: str) -> ImapSession:
        """Log in (synchronous). Raises CredentialsRejected or ServerUnavailable."""
        try:
            client = imapclient.IMAPClient(
                self.host,
                port=self.port,
                ssl=self.security is Security.SSL,
                ssl_context=self.context,
                timeout=TIMEOUT_SECONDS,
            )
        except (OSError, ssl.SSLError, IMAPClientError) as exc:
            log.warning("IMAP connection to %s:%d failed: %s", self.host, self.port, exc)
            raise ServerUnavailable() from exc
        try:
            if self.security is Security.STARTTLS:
                client.starttls(self.context)
            client.plain_login(username, password)
        except LoginError as exc:
            _close(client)
            raise CredentialsRejected() from exc
        except (OSError, ssl.SSLError, IMAPClientError) as exc:
            _close(client)
            log.warning("IMAP login on %s:%d failed: %s", self.host, self.port, exc)
            raise ServerUnavailable() from exc
        return ImapSession(client, self.folder_names)


def _close(client: imapclient.IMAPClient) -> None:
    try:
        client.logout()
    except (OSError, IMAPClientError):
        client.shutdown()


class ImapPasswordVerifier:
    """Checks credentials with an IMAP login (AUTHENTICATE PLAIN, UTF-8 safe)."""

    def __init__(self, config: AppConfig) -> None:
        self.connector = ImapConnector(config)

    async def __call__(self, username: str, password: str) -> LoginResult:
        return await anyio.to_thread.run_sync(self._verify, username, password)

    def _verify(self, username: str, password: str) -> LoginResult:
        try:
            with self.connector.connect(username, password):
                return LoginResult.OK
        except CredentialsRejected:
            return LoginResult.INVALID
        except ServerUnavailable:
            return LoginResult.UNAVAILABLE
