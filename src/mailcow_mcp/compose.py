"""Building outgoing messages from tool input."""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, getaddresses, localtime

import nh3
from markdown_it import MarkdownIt
from pydantic import BaseModel, ConfigDict, Field

from mailcow_mcp.errors import InvalidInput, LimitExceeded
from mailcow_mcp.mime import check_attachment, safe_filename

MAX_RECIPIENTS = 50
MAX_ATTACHMENTS = 10
MAX_BODY_CHARS = 1_000_000
MAX_SUBJECT_LENGTH = 500
MAX_NAME_LENGTH = 100

# Building: content is encoded here, so quoted-printable wraps at 76 (RFC 2045) and nothing is
# left as 8bit.
BUILD_POLICY = SMTP.clone(max_line_length=76, cte_type="7bit")
# Sending: long header lines aren't refolded (folding at 78 would RFC 2047-encode long Message-IDs
# in In-Reply-To/References and split long filenames into RFC 2231 pieces), and any 8bit part of a
# stored draft is re-encoded for 7-bit transport.
POLICY = SMTP.clone(max_line_length=998, cte_type="7bit")

_FORBIDDEN_IN_HEADERS = re.compile(r"[\r\n\x00]")
_LOCAL_PART_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_MESSAGE_ID_RE = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")


# --- tool input models -------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InlineAttachment(_Strict):
    """File content supplied directly."""

    filename: str = Field(max_length=255)
    content_base64: str = Field(description="The file content, base64-encoded.")
    mime_type: str = Field(max_length=255, description="e.g. application/pdf, image/png")


class MessagePart(_Strict):
    folder: str = Field(max_length=500)
    uid: int = Field(gt=0)
    part_id: str = Field(max_length=50, description="From read_message's attachment list.")


class ForwardedAttachment(_Strict):
    """An attachment of a message already in the mailbox."""

    from_message: MessagePart


class PdfSpec(_Strict):
    filename: str = Field(max_length=255)
    markdown: str = Field(max_length=MAX_BODY_CHARS, description="Document content in Markdown.")
    title: str | None = Field(default=None, max_length=MAX_SUBJECT_LENGTH)


class RenderedPdf(_Strict):
    """A PDF rendered on the server from Markdown."""

    render_pdf: PdfSpec


Attachment = InlineAttachment | ForwardedAttachment | RenderedPdf


@dataclass(frozen=True)
class FileAttachment:
    filename: str
    mime_type: str
    data: bytes


@dataclass
class Outgoing:
    to: Sequence[str]
    subject: str
    cc: Sequence[str] = ()
    bcc: Sequence[str] = ()
    body_markdown: str | None = None
    body_text: str | None = None
    from_name: str | None = None
    from_address: str | None = None
    in_reply_to: str | None = None
    references: Sequence[str] = ()
    attachments: list[FileAttachment] = field(default_factory=list)


@dataclass(frozen=True)
class Composed:
    message: EmailMessage  # as transmitted: no Bcc header
    message_id: str
    envelope_from: str
    recipients: list[str]  # To + Cc + Bcc
    copy_with_bcc: bytes  # for Sent and Drafts

    def as_bytes(self) -> bytes:
        return self.message.as_bytes(policy=POLICY)


# --- validation --------------------------------------------------------------


def header_text(value: str | None, name: str, max_length: int) -> str:
    value = value or ""
    if _FORBIDDEN_IN_HEADERS.search(value):
        raise InvalidInput(f"{name} must not contain line breaks.")
    if len(value) > max_length:
        raise InvalidInput(f"{name} is longer than {max_length} characters.")
    return value.strip()


def normalize_address(addr: str) -> str | None:
    """local@domain with an IDNA, lowercased domain; None if it isn't one."""
    local, at, domain = addr.strip().rpartition("@")
    if not at or not _LOCAL_PART_RE.match(local) or local.startswith(".") or ".." in local:
        return None
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        return None
    return f"{local}@{domain}"


def parse_address(value: str, field_name: str) -> Address:
    """One address, optionally with a display name: ``Jan Novák <jan@example.cz>``."""
    header_text(value, field_name, 400)
    parsed = getaddresses([value], strict=True)
    if len(parsed) != 1 or not parsed[0][1]:
        raise InvalidInput(f"{field_name}: {value!r} is not one email address.")
    name, addr = parsed[0]
    normalized = normalize_address(addr)
    if normalized is None:
        raise InvalidInput(f"{field_name}: {addr!r} is not a valid email address.")
    name = header_text(name, f"{field_name} name", MAX_NAME_LENGTH)
    return Address(display_name=name, addr_spec=normalized)


def parse_addresses(values: Sequence[str], field_name: str) -> list[Address]:
    return [parse_address(v, field_name) for v in values]


def normalize_message_id(value: str) -> str:
    value = header_text(value, "in_reply_to", 998)
    if not value.startswith("<"):
        value = f"<{value}>"
    if not _MESSAGE_ID_RE.match(value):
        raise InvalidInput(f"{value!r} is not a Message-ID (like <abc@example.com>).")
    return value


def decode_base64(value: str, filename: str, max_bytes: int) -> bytes:
    if len(value) > max_bytes * 4 // 3 + 4096:
        raise LimitExceeded(f"{filename} is larger than the message size limit.")
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInput(f"content_base64 of {filename} is not valid base64.") from exc


# --- rendering ---------------------------------------------------------------

_markdown = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable(
    ["table", "strikethrough"]
)
_ALLOWED_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "b", "i", "u", "s",
    "del", "code", "pre", "blockquote", "ul", "ol", "li", "a", "table", "thead", "tbody", "tr",
    "th", "td",
}  # fmt: skip
_ALLOWED_ATTRIBUTES = {"a": {"href", "title"}, "th": {"align"}, "td": {"align"}, "ol": {"start"}}

EMAIL_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; \
font-size: 15px; line-height: 1.5; color: #1d2330;">
{body}
</body></html>
"""

PDF_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title><style>
@page {{ size: A4; margin: 20mm 18mm; }}
body {{ font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif; font-size: 10.5pt;
  line-height: 1.45; color: #111; }}
h1 {{ font-size: 19pt; }} h2 {{ font-size: 15pt; }} h3 {{ font-size: 12.5pt; }}
table {{ border-collapse: collapse; margin: 8pt 0; }}
th, td {{ border: 0.6pt solid #999; padding: 3pt 6pt; vertical-align: top; }}
th {{ background: #f0f0f0; }}
pre, code {{ font-family: "DejaVu Sans Mono", monospace; font-size: 9pt; }}
pre {{ white-space: pre-wrap; background: #f4f4f4; padding: 6pt; }}
blockquote {{ border-left: 2pt solid #ccc; margin-left: 0; padding-left: 8pt; color: #444; }}
a {{ color: #1f4fbf; }}
</style></head><body>
{body}
</body></html>
"""


def markdown_to_html(markdown: str) -> str:
    """Markdown → sanitized HTML fragment (no raw HTML, no images, safe links only)."""
    return nh3.clean(
        _markdown.render(markdown),
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer",
    )


def render_pdf(markdown: str, title: str | None) -> bytes:
    """Markdown → PDF. Never fetches anything: external resources are refused."""
    from weasyprint import HTML
    from weasyprint.urls import URLFetcher

    class NoFetching(URLFetcher):  # type: ignore[misc]
        def fetch(self, url: str, headers: object = None) -> object:
            raise ValueError("external resources are disabled")

    html = PDF_HTML.format(title=nh3.clean_text(title or ""), body=markdown_to_html(markdown))
    pdf: bytes = HTML(string=html, url_fetcher=NoFetching(), base_url=None).write_pdf()
    return pdf


def pdf_attachment(spec: PdfSpec) -> FileAttachment:
    filename = safe_filename(spec.filename, "document.pdf")
    if not filename.lower().endswith(".pdf"):
        filename += ".pdf"
    return FileAttachment(filename, "application/pdf", render_pdf(spec.markdown, spec.title))


def inline_attachment(spec: InlineAttachment, max_bytes: int) -> FileAttachment:
    data = decode_base64(spec.content_base64, spec.filename, max_bytes)
    filename, mime = check_attachment(spec.filename, data, spec.mime_type)
    return FileAttachment(filename, mime, data)


# --- composing ---------------------------------------------------------------


def format_date(timezone: tzinfo | None = None) -> str:
    """RFC 5322 Date for now, in ``timezone`` (default: the system's local time zone)."""
    now = datetime.now(timezone) if timezone is not None else localtime()
    return format_datetime(now)


_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def transfer_encoding(text: str) -> str:
    """7bit for plain ASCII with short lines, else quoted-printable: never raw 8bit.

    Lines are split only at CR/LF, as on the wire (str.splitlines would also split at form
    feeds and other separators that don't end an SMTP line).
    """
    if text.isascii() and all(len(line) <= 900 for line in _LINE_BREAK.split(text)):
        return "7bit"
    return "quoted-printable"


def default_from_name(from_names: Mapping[str, str], address: str) -> str:
    """The configured display name for an address (matched like compose normalizes it)."""
    normalized = normalize_address(address)
    return from_names.get(normalized.lower(), "") if normalized else ""


def new_message_id(domain: str) -> str:
    return f"<{secrets.token_hex(16)}@{domain}>"


def compose(
    draft: Outgoing,
    *,
    username: str,
    max_message_bytes: int,
    from_names: Mapping[str, str] | None = None,
    timezone: tzinfo | None = None,
) -> Composed:
    """Validate and build the message. Raises InvalidInput / LimitExceeded.

    ``from_names``: default display names by sender address, used when the caller gives none.
    ``timezone``: for the Date header (default: the system's local time zone).
    """
    to = parse_addresses(draft.to, "to")
    cc = parse_addresses(draft.cc, "cc")
    bcc = parse_addresses(draft.bcc, "bcc")
    recipients = list(dict.fromkeys(a.addr_spec for a in [*to, *cc, *bcc]))
    if not recipients:
        raise InvalidInput("Give at least one recipient.")
    if len(recipients) > MAX_RECIPIENTS:
        raise LimitExceeded(f"At most {MAX_RECIPIENTS} recipients per message.")

    subject = header_text(draft.subject, "subject", MAX_SUBJECT_LENGTH)
    from_name = header_text(draft.from_name, "from_name", MAX_NAME_LENGTH)
    sender_address = parse_address(draft.from_address or username, "from_address")
    sender = sender_address.addr_spec
    # The caller's name, else a name given in from_address, else the configured default.
    from_name = (
        from_name or sender_address.display_name or (from_names or {}).get(sender.lower(), "")
    )

    if (draft.body_markdown is None) == (draft.body_text is None):
        raise InvalidInput("Give exactly one of body_markdown or body_text.")
    body = draft.body_markdown if draft.body_markdown is not None else draft.body_text
    assert body is not None  # noqa: S101 - checked just above
    if len(body) > MAX_BODY_CHARS:
        raise LimitExceeded("The body is longer than 1,000,000 characters.")
    if len(draft.attachments) > MAX_ATTACHMENTS:
        raise LimitExceeded(f"At most {MAX_ATTACHMENTS} attachments per message.")

    message = EmailMessage(policy=BUILD_POLICY)
    message["From"] = Address(display_name=from_name, addr_spec=sender)
    if to:
        message["To"] = to
    if cc:
        message["Cc"] = cc
    message["Subject"] = subject
    message["Date"] = format_date(timezone)
    message_id = new_message_id(sender.rpartition("@")[2])
    message["Message-ID"] = message_id
    if draft.in_reply_to:
        parent = normalize_message_id(draft.in_reply_to)
        message["In-Reply-To"] = parent
        chain = [r for r in draft.references if _MESSAGE_ID_RE.match(r)][-20:]
        if parent not in chain:
            chain.append(parent)
        message["References"] = " ".join(chain)

    body = body.replace("\r\n", "\n")
    if draft.body_markdown is not None:
        html = EMAIL_HTML.format(body=markdown_to_html(body))
        message.set_content(body, subtype="plain", charset="utf-8", cte=transfer_encoding(body))
        message.add_alternative(html, subtype="html", charset="utf-8", cte=transfer_encoding(html))
    else:
        message.set_content(body, subtype="plain", charset="utf-8", cte=transfer_encoding(body))
    for attachment in draft.attachments:
        maintype, _, subtype = attachment.mime_type.partition("/")
        message.add_attachment(
            attachment.data, maintype=maintype, subtype=subtype, filename=attachment.filename
        )

    for part in message.walk():
        if part is not message:
            del part["MIME-Version"]  # the stdlib adds it to sub-parts; it belongs only on top
    transmitted = message.as_bytes(policy=POLICY)
    if len(transmitted) > max_message_bytes:
        size = max_message_bytes // (1024 * 1024)
        raise LimitExceeded(f"The message is larger than the {size} MB limit.")
    copy_bytes = transmitted
    if bcc:
        # Bcc stays only in our own copies (Sent, Drafts), never in what's transmitted.
        message["Bcc"] = bcc
        copy_bytes = message.as_bytes(policy=POLICY)
        del message["Bcc"]
    return Composed(
        message=message,
        message_id=message_id,
        envelope_from=sender,
        recipients=recipients,
        copy_with_bcc=copy_bytes,
    )
