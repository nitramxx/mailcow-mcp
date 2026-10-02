"""Configuration loading and validation.

Configuration comes only from environment variables. Loading collects every
problem before failing, so an operator sees all mistakes at once. Error
messages never contain secret values.
"""

from __future__ import annotations

import ipaddress
import os
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import tzinfo
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cryptography.fernet import Fernet

IMAGE = "ghcr.io/nitramxx/mailcow-mcp"
GENERATE_KEY_HINT = f"generate one with: docker run --rm {IMAGE} generate-key"

DEFAULT_APP_PORT = 8090
DEFAULT_BROKER_PORT = 8091

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MIN_SECRET_LENGTH = 32


class Mode(StrEnum):
    MAILCOW = "mailcow"
    GENERIC = "generic"


class Security(StrEnum):
    SSL = "ssl"
    STARTTLS = "starttls"


class SaveSent(StrEnum):
    AUTO = "auto"
    ALWAYS = "always"
    NEVER = "never"


LANGUAGES = ("en", "cs")
FOLDER_ROLES = ("sent", "drafts", "junk", "trash")


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""

    def __init__(self, subject: str, errors: list[str]) -> None:
        self.subject = subject
        self.errors = errors
        super().__init__(str(self))

    def __str__(self) -> str:
        lines = [f"invalid {self.subject}:"]
        lines += [f"  - {e}" for e in self.errors]
        lines.append("See .env.example for every option.")
        return "\n".join(lines)


@dataclass(frozen=True)
class AppConfig:
    mode: Mode
    public_url: str
    mailcow_url: str | None
    # Inside mailcow's network: reach nginx directly (no hairpin NAT), verify TLS_SERVER_NAME.
    mailcow_internal_url: str | None
    mailcow_oauth_client_id: str | None
    mailcow_oauth_client_secret: str | None = field(repr=False)
    broker_url: str
    broker_shared_secret: str | None = field(repr=False)
    imap_host: str
    imap_port: int
    imap_security: Security
    smtp_host: str
    smtp_port: int
    smtp_security: Security
    smtp_helo_name: str
    carddav_url: str | None
    carddav_internal: bool  # carddav_url points at MAILCOW_INTERNAL_URL
    # None (generic mode only): verify each server against the host connected to.
    tls_server_name: str | None
    tls_verify: bool
    tls_ca_file: Path | None
    allow_password_login: bool
    allowed_domains: tuple[str, ...]
    enc_key: str = field(repr=False)
    save_sent: SaveSent
    from_names: dict[str, str]
    timezone: tzinfo | None  # None: the system's local time zone
    send_limit_hour: int
    send_limit_day: int
    max_message_mb: int
    trusted_proxies: tuple[str, ...]
    instance_name: str
    default_language: str
    data_dir: Path
    port: int
    host: str
    # Folder names to try after SPECIAL-USE flags, before the common names.
    folder_names: dict[str, str] = field(default_factory=dict)

    @property
    def https(self) -> bool:
        """Served over HTTPS (http:// is allowed only for local testing)."""
        return self.public_url.startswith("https://")


@dataclass(frozen=True)
class BrokerConfig:
    mailcow_api_url: str
    tls_server_name: str
    tls_verify: bool
    tls_ca_file: Path | None
    mailcow_api_key: str = field(repr=False)
    mailcow_oauth_profile_url: str
    broker_shared_secret: str = field(repr=False)
    broker_signing_key: str = field(repr=False)
    data_dir: Path
    port: int
    host: str


class _Reader:
    """Reads typed values from the environment and collects errors."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = env
        self.errors: list[str] = []

    def error(self, name: str, message: str) -> None:
        self.errors.append(f"{name}: {message}")

    def failed(self, *names: str) -> bool:
        """Whether any of these settings already has an error."""
        return any(e.split(":", 1)[0] in names for e in self.errors)

    def raw(self, name: str) -> str | None:
        """The stripped value, or None when unset or empty."""
        value = self.env.get(name)
        if value is None or not value.strip():
            return None
        return value.strip()

    def required(self, name: str, hint: str = "") -> str:
        value = self.raw(name)
        if value is None:
            self.error(name, "required" + (f" ({hint})" if hint else ""))
            return ""
        return value

    def choice[E: StrEnum](self, name: str, enum: type[E], default: E) -> E:
        value = self.raw(name)
        if value is None:
            return default
        try:
            return enum(value.lower())
        except ValueError:
            allowed = ", ".join(e.value for e in enum)
            self.error(name, f"must be one of {allowed} (got {value!r})")
            return default

    def integer(self, name: str, default: int, minimum: int, maximum: int) -> int:
        value = self.raw(name)
        if value is None:
            return default
        try:
            number = int(value)
        except ValueError:
            self.error(name, f"must be a whole number (got {value!r})")
            return default
        if not minimum <= number <= maximum:
            self.error(name, f"must be between {minimum} and {maximum} (got {number})")
            return default
        return number

    def port(self, name: str, default: int) -> int:
        return self.integer(name, default, 1, 65535)

    def boolean(self, name: str, default: bool) -> bool:
        value = self.raw(name)
        if value is None:
            return default
        lowered = value.lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off"):
            return False
        self.error(name, f"must be true or false (got {value!r})")
        return default

    def url(
        self,
        name: str,
        value: str | None,
        *,
        allow_http: bool = False,
        allow_loopback_http: bool = False,
        allow_path: bool = False,
    ) -> str:
        """Validate an absolute URL and return it without a trailing slash."""
        if not value:
            return ""
        try:
            parts = urlsplit(value)
            hostname = parts.hostname
            parts.port  # noqa: B018 - raises ValueError on an invalid port
        except ValueError:
            self.error(name, f"not a valid URL (got {value!r})")
            return ""
        scheme_ok = parts.scheme == "https" or (
            parts.scheme == "http"
            and (allow_http or (allow_loopback_http and hostname in _LOOPBACK_HOSTS))
        )
        if not scheme_ok:
            if allow_loopback_http:
                need = "https:// (http:// only for localhost)"
            elif allow_http:
                need = "http:// or https://"
            else:
                need = "https://"
            self.error(name, f"must start with {need} (got {value!r})")
            return ""
        if not hostname:
            self.error(name, f"has no host (got {value!r})")
            return ""
        if parts.username or parts.password:
            self.error(name, "must not contain credentials")
            return ""
        if parts.query or parts.fragment:
            self.error(name, f"must not contain a query or fragment (got {value!r})")
            return ""
        if not allow_path and parts.path not in ("", "/"):
            self.error(name, f"must not contain a path (got {value!r})")
            return ""
        return value.rstrip("/")

    def hostname(self, name: str, value: str | None) -> str:
        if not value:
            return ""
        lowered = value.lower().rstrip(".")
        if not _HOSTNAME_RE.match(lowered):
            self.error(name, f"not a valid hostname (got {value!r})")
            return ""
        return lowered

    def key(self, name: str) -> str:
        """A Fernet-format key (32 random bytes, URL-safe base64)."""
        value = self.raw(name)
        if value is None:
            self.error(name, f"required; {GENERATE_KEY_HINT}")
            return ""
        try:
            Fernet(value)
        except ValueError:
            self.error(name, f"not a valid key; {GENERATE_KEY_HINT}")
            return ""
        return value

    def secret(self, name: str) -> str:
        value = self.raw(name)
        if value is None:
            self.error(name, f"required; {GENERATE_KEY_HINT}")
            return ""
        if len(value) < _MIN_SECRET_LENGTH:
            self.error(
                name,
                f"too short, use at least {_MIN_SECRET_LENGTH} characters; {GENERATE_KEY_HINT}",
            )
            return ""
        return value

    def address(self, name: str) -> str:
        """An IP address to listen on (default: all interfaces)."""
        value = self.raw(name)
        if value is None:
            return "0.0.0.0"  # noqa: S104 - containers listen on their own networks
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            self.error(name, f"must be an IP address (got {value!r})")
            return "0.0.0.0"  # noqa: S104

    def networks(self, name: str) -> tuple[str, ...]:
        value = self.required(name, "the mailcow network CIDR, e.g. 172.22.1.0/24")
        result: list[str] = []
        for item in filter(None, (part.strip() for part in value.split(","))):
            if item == "*":
                self.error(name, "'*' would let any client spoof its IP; list the proxy networks")
                continue
            try:
                result.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                self.error(name, f"not an IP address or CIDR (got {item!r})")
        return tuple(result)

    def domains(self, name: str) -> tuple[str, ...]:
        value = self.raw(name)
        if value is None:
            return ()
        result: list[str] = []
        for item in filter(None, (part.strip().lstrip("@") for part in value.split(","))):
            try:
                ascii_name = item.encode("idna").decode("ascii")
            except UnicodeError:
                self.error(name, f"not a valid domain (got {item!r})")
                continue
            domain = self.hostname(name, ascii_name)
            if domain:
                result.append(domain)
        return tuple(dict.fromkeys(result))

    def file(self, name: str) -> Path | None:
        value = self.raw(name)
        if value is None:
            return None
        path = Path(value)
        if not path.is_file():
            self.error(name, f"no such file: {value}")
            return None
        return path

    def ca_file(self, name: str) -> Path | None:
        """A PEM file with CA certificates (checked now, not when the first TLS connection fails)."""
        path = self.file(name)
        if path is not None:
            try:
                ssl.create_default_context().load_verify_locations(cafile=str(path))
            except (ssl.SSLError, OSError, ValueError) as exc:
                self.error(name, f"not a readable PEM file with CA certificates: {exc}")
                return None
        return path

    def folders(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for role in FOLDER_ROLES:
            name = f"FOLDER_{role.upper()}"
            value = self.text(name, "", 200)
            if value:
                result[role] = value
        return result

    def from_names(self, name: str) -> dict[str, str]:
        """``a@example.com=Name; b@example.com=Other`` (or one per line)."""
        value = self.raw(name)
        result: dict[str, str] = {}
        if value is None:
            return result
        for entry in filter(None, (e.strip() for e in re.split(r"[;\n]", value))):
            # The name starts at the first "=" after the "@": local parts may contain "=".
            at = entry.find("@")
            eq = entry.find("=", at) if at > 0 else -1
            if eq < 0:
                self.error(name, f"expected address=Name entries (got {entry!r})")
                continue
            local, domain = entry[:at].strip(), entry[at + 1 : eq].strip()
            display = entry[eq + 1 :].strip()
            try:
                domain = domain.encode("idna").decode("ascii").lower()
            except UnicodeError:
                domain = ""
            if not local or not _HOSTNAME_RE.match(domain):
                self.error(name, f"expected address=Name entries (got {entry!r})")
                continue
            if (
                not display
                or len(display) > 100
                or any(ord(c) < 32 or ord(c) == 127 for c in display)
            ):
                self.error(name, f"invalid display name for {local}@{domain}")
                continue
            result[f"{local.lower()}@{domain}"] = display
        return result

    def timezone(self, name: str) -> tzinfo | None:
        value = self.raw(name)
        if value is None:
            return None
        try:
            return ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError, OSError):  # OSError: "Europe" is a folder
            self.error(name, f"not a time zone name like Europe/Prague (got {value!r})")
            return None

    def text(self, name: str, default: str, max_length: int) -> str:
        value = self.raw(name)
        if value is None:
            return default
        if len(value) > max_length or any(ord(c) < 32 or ord(c) == 127 for c in value):
            self.error(name, f"must be at most {max_length} printable characters")
            return default
        return value

    def raise_if_errors(self, subject: str) -> None:
        if self.errors:
            raise ConfigError(subject, self.errors)


def helo_name(name: str) -> str:
    """An EHLO argument: a domain, or an address literal ("[192.0.2.1]") for an IP (RFC 5321)."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return name
    return f"[{address}]" if address.version == 4 else f"[IPv6:{address}]"


def load_app_config(env: Mapping[str, str] | None = None) -> AppConfig:
    """Load the configuration of the internet-facing app (``serve``)."""
    r = _Reader(os.environ if env is None else env)

    mode = r.choice("MODE", Mode, Mode.MAILCOW)
    mailcow = mode is Mode.MAILCOW

    public_url = r.url(
        "PUBLIC_URL",
        r.required("PUBLIC_URL", "e.g. https://mcp.mail.example.com"),
        allow_loopback_http=True,
    )

    mailcow_url: str | None = None
    mailcow_internal_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    shared_secret: str | None = None
    if mailcow:
        mailcow_url = r.url(
            "MAILCOW_URL",
            r.required("MAILCOW_URL", "public mailcow URL, e.g. https://mail.example.com"),
        )
        mailcow_internal_url = (
            r.url("MAILCOW_INTERNAL_URL", r.raw("MAILCOW_INTERNAL_URL"), allow_path=False) or None
        )
        client_id = r.required("MAILCOW_OAUTH_CLIENT_ID", "from mailcow → OAuth2 Apps")
        client_secret = r.required("MAILCOW_OAUTH_CLIENT_SECRET", "from mailcow → OAuth2 Apps")
        shared_secret = r.secret("BROKER_SHARED_SECRET")

    broker_url = r.url(
        "BROKER_URL",
        r.raw("BROKER_URL") or f"http://mcp-broker:{DEFAULT_BROKER_PORT}",
        allow_http=True,
    )

    imap_host = r.hostname("IMAP_HOST", r.raw("IMAP_HOST") or "dovecot-mailcow")
    imap_port = r.port("IMAP_PORT", 993)
    imap_security = r.choice("IMAP_SECURITY", Security, Security.SSL)
    smtp_host = r.hostname("SMTP_HOST", r.raw("SMTP_HOST") or "postfix-mailcow")
    smtp_port = r.port("SMTP_PORT", 587)
    smtp_security = r.choice("SMTP_SECURITY", Security, Security.STARTTLS)

    carddav_raw = r.raw("CARDDAV_URL")
    carddav_internal = False
    if carddav_raw is None and mailcow and (mailcow_internal_url or mailcow_url):
        carddav_raw = f"{mailcow_internal_url or mailcow_url}/SOGo/dav/"
        carddav_internal = mailcow_internal_url is not None
    carddav_url = r.url("CARDDAV_URL", carddav_raw, allow_path=True) or None

    tls_server_name: str | None
    if mailcow:
        tls_server_name = r.hostname(
            "TLS_SERVER_NAME",
            r.required("TLS_SERVER_NAME", "the mailcow hostname, e.g. mail.example.com"),
        )
    else:
        tls_server_name = r.hostname("TLS_SERVER_NAME", r.raw("TLS_SERVER_NAME")) or None
    tls_verify = r.boolean("TLS_VERIFY", True)

    allow_password_login = r.boolean("ALLOW_PASSWORD_LOGIN", not mailcow)
    if not mailcow and not allow_password_login:
        r.error("ALLOW_PASSWORD_LOGIN", "generic mode signs users in with a password; remove it")

    send_limit_hour = r.integer("SEND_LIMIT_HOUR", 30, 1, 10_000)
    send_limit_day = r.integer("SEND_LIMIT_DAY", 300, 1, 100_000)
    if send_limit_day < send_limit_hour and not r.failed("SEND_LIMIT_HOUR", "SEND_LIMIT_DAY"):
        r.error("SEND_LIMIT_DAY", "must not be lower than SEND_LIMIT_HOUR")

    language = (r.raw("DEFAULT_LANGUAGE") or "en").lower()
    if language not in LANGUAGES:
        r.error("DEFAULT_LANGUAGE", f"must be one of {', '.join(LANGUAGES)} (got {language!r})")
        language = "en"

    config = AppConfig(
        mode=mode,
        public_url=public_url,
        mailcow_url=mailcow_url,
        mailcow_internal_url=mailcow_internal_url,
        mailcow_oauth_client_id=client_id,
        mailcow_oauth_client_secret=client_secret,
        broker_url=broker_url,
        broker_shared_secret=shared_secret,
        imap_host=imap_host,
        imap_port=imap_port,
        imap_security=imap_security,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_security=smtp_security,
        # EHLO name: the mail server's own name, not the container's ("[127.0.0.1]").
        smtp_helo_name=helo_name(
            r.hostname("SMTP_HELO_NAME", r.raw("SMTP_HELO_NAME")) or tls_server_name or smtp_host
        ),
        carddav_url=carddav_url,
        carddav_internal=carddav_internal,
        tls_server_name=tls_server_name,
        tls_verify=tls_verify,
        tls_ca_file=r.ca_file("TLS_CA_FILE"),
        allow_password_login=allow_password_login,
        allowed_domains=r.domains("ALLOWED_DOMAINS"),
        enc_key=r.key("ENC_KEY"),
        save_sent=r.choice("SAVE_SENT", SaveSent, SaveSent.ALWAYS),
        from_names=r.from_names("FROM_NAMES"),
        timezone=r.timezone("TIMEZONE"),
        send_limit_hour=send_limit_hour,
        send_limit_day=send_limit_day,
        max_message_mb=r.integer("MAX_MESSAGE_MB", 15, 1, 100),
        trusted_proxies=r.networks("TRUSTED_PROXIES"),
        instance_name=r.text("INSTANCE_NAME", "mailcow MCP", 100),
        default_language=language,
        data_dir=Path(r.raw("DATA_DIR") or "/data"),
        port=r.port("PORT", DEFAULT_APP_PORT),
        host=r.address("HOST"),
        folder_names=r.folders(),
    )
    r.raise_if_errors(f"app configuration (MODE={mode.value})")
    return config


def load_broker_config(env: Mapping[str, str] | None = None) -> BrokerConfig:
    """Load the configuration of the internal broker (``broker``)."""
    r = _Reader(os.environ if env is None else env)

    api_url = r.url(
        "MAILCOW_API_URL",
        r.required("MAILCOW_API_URL", "internal mailcow URL, e.g. https://nginx-mailcow"),
    )
    profile_raw = r.raw("MAILCOW_OAUTH_PROFILE_URL")
    if profile_raw is None and api_url:
        profile_raw = f"{api_url}/oauth/profile"

    config = BrokerConfig(
        mailcow_api_url=api_url,
        tls_server_name=r.hostname(
            "TLS_SERVER_NAME",
            r.required("TLS_SERVER_NAME", "the mailcow hostname, e.g. mail.example.com"),
        ),
        tls_verify=r.boolean("TLS_VERIFY", True),
        tls_ca_file=r.ca_file("TLS_CA_FILE"),
        mailcow_api_key=r.required("MAILCOW_API_KEY", "mailcow → System → Configuration → Access"),
        mailcow_oauth_profile_url=r.url("MAILCOW_OAUTH_PROFILE_URL", profile_raw, allow_path=True),
        broker_shared_secret=r.secret("BROKER_SHARED_SECRET"),
        broker_signing_key=r.key("BROKER_SIGNING_KEY"),
        data_dir=Path(r.raw("DATA_DIR") or "/data"),
        port=r.port("PORT", DEFAULT_BROKER_PORT),
        host=r.address("HOST"),
    )
    r.raise_if_errors("broker configuration")
    return config


def generate_key() -> str:
    """A new random key, valid for ENC_KEY, BROKER_SIGNING_KEY and BROKER_SHARED_SECRET."""
    return Fernet.generate_key().decode("ascii")
