"""Contact search over CardDAV (SOGo in mailcow, any CardDAV server in generic mode).

Discovery follows RFC 6352: current-user-principal → addressbook-home-set →
address books, then an addressbook-query REPORT per address book. If a server
rejects the filtered query, all cards are fetched and filtered here.
"""

from __future__ import annotations

import logging
import re
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree as ET

import httpx

from mailcow_mcp.config import AppConfig
from mailcow_mcp.errors import ContactsAuthFailed, MailError, ServerUnavailable
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

DAV = "DAV:"
CARD = "urn:ietf:params:xml:ns:carddav"
NS = {"d": DAV, "c": CARD}
MAX_RESULTS = 50
MAX_ADDRESS_BOOKS = 20
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


@dataclass
class Contact:
    name: str
    emails: list[str] = field(default_factory=list)
    organisation: str | None = None
    phones: list[str] = field(default_factory=list)


def _unfold(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        elif raw:
            lines.append(raw)
    return lines


_ESCAPE_RE = re.compile(r"\\(.)")


def _unescape(value: str) -> str:
    """RFC 6350 escapes, in one pass (so "\\\\n" stays a backslash and an n)."""
    return _ESCAPE_RE.sub(lambda m: "\n" if m.group(1) in "nN" else m.group(1), value)


def parse_vcards(text: str) -> list[Contact]:
    contacts: list[Contact] = []
    current: dict[str, list[str]] | None = None
    for line in _unfold(text):
        name, _, value = line.partition(":")
        prop = name.split(";", 1)[0].split(".")[-1].upper()  # drop params and group prefix
        if prop == "BEGIN" and value.upper() == "VCARD":
            current = {}
        elif prop == "END" and value.upper() == "VCARD" and current is not None:
            fn = (current.get("FN") or [""])[0]
            if not fn and current.get("N"):
                # N is family;given;additional;prefixes;suffixes, any of them empty.
                family, _, rest = current["N"][0].partition(";")
                given = rest.partition(";")[0]
                fn = " ".join(p for p in (given, family) if p)
            orgs = current.get("ORG") or []
            org = orgs[0] if orgs else None
            contacts.append(
                Contact(
                    name=_unescape(fn).strip(),
                    emails=[_unescape(e).strip() for e in current.get("EMAIL", []) if e.strip()],
                    organisation=_unescape(org.replace(";", ", ")).strip(", ") if org else None,
                    phones=[_unescape(t).strip() for t in current.get("TEL", []) if t.strip()],
                )
            )
            current = None
        elif current is not None and prop in ("FN", "N", "EMAIL", "ORG", "TEL"):
            current.setdefault(prop, []).append(value)
    return contacts


def _matches(contact: Contact, query: str) -> bool:
    needle = query.casefold()
    haystack = [contact.name, contact.organisation or "", *contact.emails]
    return any(needle in value.casefold() for value in haystack)


def _query_body(query: str) -> bytes:
    escaped = query.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    filters = "".join(
        f'<c:prop-filter name="{prop}"><c:text-match collation="i;unicode-casemap" '
        f'match-type="contains">{escaped}</c:text-match></c:prop-filter>'
        for prop in ("FN", "EMAIL", "ORG")
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
        "<d:prop><d:getetag/><c:address-data/></d:prop>"
        f'<c:filter test="anyof">{filters}</c:filter></c:addressbook-query>'
    ).encode()


ALL_CARDS = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
    b"<d:prop><d:getetag/><c:address-data/></d:prop></c:addressbook-query>"
)


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.netloc.lower()


def _propfind(prop_xml: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop>{prop_xml}</d:prop></d:propfind>'
    ).encode()


class CardDav:
    def __init__(
        self,
        url: str,
        *,
        verify: ssl.SSLContext | bool = True,
        host_header: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url.rstrip("/") + "/"
        self.verify = verify
        self.headers = {"Host": host_header} if host_header else {}
        self.transport = transport
        # Reached by an internal name, the server may still answer with its public URL.
        self.public_origin = ("https", host_header.lower()) if host_header else None

    @classmethod
    def from_config(cls, config: AppConfig) -> CardDav:
        assert config.carddav_url  # noqa: S101 - only called when contacts are configured
        # Via MAILCOW_INTERNAL_URL: dial nginx directly, but ask for and verify the
        # mailcow hostname (as for the OAuth token exchange).
        host_header = None
        if config.carddav_internal and config.mailcow_url:
            host_header = urlsplit(config.mailcow_url).netloc
        return cls(
            config.carddav_url,
            verify=client_context(
                server_name=config.tls_server_name if host_header else None,
                verify=config.tls_verify,
                ca_file=config.tls_ca_file,
            ),
            host_header=host_header,
        )

    async def search(self, username: str, password: str, query: str) -> list[Contact]:
        async with httpx.AsyncClient(
            auth=(username, password),
            headers=self.headers,
            verify=self.verify,
            timeout=httpx.Timeout(20.0, connect=10.0),
            transport=self.transport,
            follow_redirects=True,
            max_redirects=5,
        ) as http:
            try:
                books = await self._address_books(http, username)
                results: list[Contact] = []
                for book in books[:MAX_ADDRESS_BOOKS]:
                    results += await self._search_book(http, book, query)
                    if len(results) >= MAX_RESULTS:
                        break
            except httpx.HTTPError as exc:
                log.warning("CardDAV request failed: %s", exc)
                raise ServerUnavailable("The contacts server") from exc
        unique: dict[tuple[str, tuple[str, ...]], Contact] = {}
        for contact in results:
            unique.setdefault((contact.name, tuple(contact.emails)), contact)
        return list(unique.values())[:MAX_RESULTS]

    async def _request(
        self, http: httpx.AsyncClient, method: str, url: str, body: bytes, depth: str
    ) -> ET.Element:
        url = self._local(url)
        async with http.stream(
            method,
            url,
            content=body,
            headers={"Depth": depth, "Content-Type": "application/xml; charset=utf-8"},
        ) as response:
            if response.status_code == 401:
                raise ContactsAuthFailed()
            if response.status_code != 207:
                raise MailError(f"The contacts server answered HTTP {response.status_code}.")
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content += chunk
                if len(content) > MAX_RESPONSE_BYTES:
                    raise MailError("The contacts server's answer is too large.")
        try:
            return ET.fromstring(bytes(content))  # noqa: S314 - stdlib parser doesn't expand external entities
        except ET.ParseError as exc:
            raise MailError("The contacts server sent invalid XML.") from exc

    def _local(self, url: str) -> str:
        """The URL to request: on this server only, whatever its answers point to
        (the credentials are for this server alone)."""
        origin = _origin(url)
        if origin == _origin(self.url):
            return url
        if origin == self.public_origin:
            scheme, netloc = _origin(self.url)
            return urlsplit(url)._replace(scheme=scheme, netloc=netloc).geturl()
        raise MailError("The contacts server referred to another server.")

    async def _href(self, http: httpx.AsyncClient, url: str, prop: str, path: str) -> str | None:
        root = await self._request(http, "PROPFIND", url, _propfind(prop), "0")
        element = root.find(path, NS)
        return urljoin(url, element.text.strip()) if element is not None and element.text else None

    async def _address_books(self, http: httpx.AsyncClient, username: str) -> list[str]:
        principal = await self._href(
            http, self.url, "<d:current-user-principal/>", ".//d:current-user-principal/d:href"
        )
        home = None
        if principal:
            home = await self._href(
                http, principal, "<c:addressbook-home-set/>", ".//c:addressbook-home-set/d:href"
            )
        home = home or urljoin(self.url, f"{username}/Contacts/")  # SOGo's layout
        root = await self._request(http, "PROPFIND", home, _propfind("<d:resourcetype/>"), "1")
        books = []
        for response in root.findall("d:response", NS):
            href = response.find("d:href", NS)
            if (
                href is not None
                and href.text
                and response.find(".//d:resourcetype/c:addressbook", NS) is not None
            ):
                books.append(urljoin(home, href.text.strip()))
        return books

    async def _search_book(self, http: httpx.AsyncClient, book: str, query: str) -> list[Contact]:
        try:
            root = await self._request(http, "REPORT", book, _query_body(query), "1")
        except MailError:
            root = await self._request(http, "REPORT", book, ALL_CARDS, "1")
        contacts: list[Contact] = []
        for data in root.iterfind(".//c:address-data", NS):
            contacts += parse_vcards(data.text or "")
        # Servers differ in how strictly they apply the filter (or ignore it): check here.
        return [c for c in contacts if _matches(c, query)]
