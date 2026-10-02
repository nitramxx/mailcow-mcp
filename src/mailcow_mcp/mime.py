"""MIME helpers shared by sending and reading: part numbering, sniffing, filenames."""

from __future__ import annotations

import re
import unicodedata
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.policy import default as default_policy

from mailcow_mcp.errors import InvalidInput, NotFound

MAX_FILENAME_LENGTH = 150
MAX_PART_DEPTH = 20  # deeper multiparts are treated as one opaque part

_MIME_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_UNSAFE_FILENAME_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')

# Executable or script types that mail servers commonly reject and that are risky to send.
BLOCKED_EXTENSIONS = frozenset(
    [
        "exe",
        "com",
        "bat",
        "cmd",
        "scr",
        "pif",
        "msi",
        "msp",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "ps1",
        "psm1",
        "jar",
        "lnk",
        "hta",
        "cpl",
        "reg",
        "dll",
    ]
)

_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"%PDF-", 0, "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"PK\x03\x04", 0, "application/zip"),
    (b"MZ", 0, "application/x-msdownload"),
    (b"\x7fELF", 0, "application/x-executable"),
]
# Types we can recognise: declared and actual content must agree on these.
_RECOGNISED = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp"}
_EXECUTABLE = {"application/x-msdownload", "application/x-executable"}


def sniff(data: bytes) -> str | None:
    """The MIME type recognised from the first bytes, or None."""
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    for signature, offset, mime in _SIGNATURES:
        if data[offset : offset + len(signature)] == signature:
            return mime
    return None


def safe_filename(name: str | None, default: str = "attachment") -> str:
    """A filename without paths, control or reserved characters, at most 150 characters."""
    if not name:
        return default
    name = unicodedata.normalize("NFC", name)
    name = re.split(r"[/\\]", name)[-1]
    name = _UNSAFE_FILENAME_CHARS.sub("", name)
    name = " ".join(name.split()).strip(" .")
    if not name:
        return default
    if len(name) > MAX_FILENAME_LENGTH:
        stem, dot, ext = name.rpartition(".")
        if dot and 0 < len(ext) <= 10:
            name = stem[: MAX_FILENAME_LENGTH - len(ext) - 1] + "." + ext
        else:
            name = name[:MAX_FILENAME_LENGTH]
    return name


def extension(filename: str) -> str:
    return filename.rpartition(".")[2].lower() if "." in filename else ""


def check_attachment(filename: str | None, data: bytes, declared: str | None) -> tuple[str, str]:
    """Validate an outgoing attachment; returns (safe filename, MIME type)."""
    name = safe_filename(filename)
    if extension(name) in BLOCKED_EXTENSIONS:
        raise InvalidInput(f"Attachments of type .{extension(name)} can't be sent.")
    sniffed = sniff(data)
    if sniffed in _EXECUTABLE:
        raise InvalidInput(f"{name} is an executable program; it can't be sent.")
    mime = (declared or "").strip().lower() or sniffed or "application/octet-stream"
    if not _MIME_TYPE_RE.match(mime):
        raise InvalidInput(f"{mime!r} is not a valid MIME type.")
    if mime.startswith(("multipart/", "message/")):
        # Containers can't be base64-encoded (RFC 2046); an attached email goes as a file.
        mime = "application/octet-stream"
    if mime in _RECOGNISED and sniffed != mime:
        found = f"is {sniffed}" if sniffed else "isn't recognisable"
        raise InvalidInput(f"{name} is declared as {mime}, but its content {found}.")
    if sniffed in _RECOGNISED and mime not in (sniffed, "application/octet-stream"):
        raise InvalidInput(f"{name} is declared as {mime}, but its content is {sniffed}.")
    return name, mime


def parse_message(raw: bytes) -> EmailMessage:
    try:
        message = BytesParser(policy=default_policy).parsebytes(raw)
    except RecursionError as exc:  # thousands of nested multiparts
        raise InvalidInput("The message is nested too deeply to read.") from exc
    assert isinstance(message, EmailMessage)  # noqa: S101 - the default policy guarantees it
    return message


def walk_parts(message: Message) -> list[tuple[str, Message]]:
    """Leaf parts with IMAP-style section numbers ("1", "2", "2.1", …).

    message/rfc822 parts are leaves (an attached email is one attachment).
    """
    result: list[tuple[str, Message]] = []

    def visit(part: Message, number: str) -> None:
        if part.get_content_maintype() == "multipart" and number.count(".") < MAX_PART_DEPTH:
            payload = part.get_payload()
            if isinstance(payload, list):
                for index, child in enumerate(payload, 1):
                    visit(child, f"{number}.{index}" if number else str(index))
            return
        result.append((number or "1", part))

    visit(message, "")
    return result


def is_attachment(part: Message) -> bool:
    disposition = part.get_content_disposition()
    if disposition == "attachment":
        return True
    if part.get_filename():
        return True
    return part.get_content_maintype() not in ("text", "multipart") and disposition != "inline"


def part_bytes(part: Message) -> bytes:
    """The decoded content of a leaf part."""
    if part.get_content_type() == "message/rfc822":
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) else payload
        if isinstance(inner, Message):
            return inner.as_bytes()
    data = part.get_payload(decode=True)
    return data if isinstance(data, bytes) else b""


def find_part(message: Message, part_id: str) -> Message:
    for number, part in walk_parts(message):
        if number == part_id:
            return part
    raise NotFound(f"The message has no part {part_id!r}. Use read_message to list attachments.")
