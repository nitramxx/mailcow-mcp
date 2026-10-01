"""IMAP access."""

from __future__ import annotations

import enum
import logging
import ssl
from typing import Protocol

import anyio
import imapclient
from imapclient.exceptions import IMAPClientError, LoginError

from mailcow_mcp.config import AppConfig, Security
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 20


class LoginResult(enum.Enum):
    OK = "ok"
    INVALID = "invalid_credentials"
    UNAVAILABLE = "server_unavailable"


class PasswordVerifier(Protocol):
    async def __call__(self, username: str, password: str) -> LoginResult: ...


class ImapPasswordVerifier:
    """Checks credentials with an IMAP login (AUTHENTICATE PLAIN, UTF-8 safe)."""

    def __init__(self, config: AppConfig) -> None:
        self.host = config.imap_host
        self.port = config.imap_port
        self.security = config.imap_security
        self.context = client_context(server_name=config.tls_server_name, verify=config.tls_verify)

    async def __call__(self, username: str, password: str) -> LoginResult:
        return await anyio.to_thread.run_sync(self._verify, username, password)

    def _verify(self, username: str, password: str) -> LoginResult:
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
            return LoginResult.UNAVAILABLE
        try:
            if self.security is Security.STARTTLS:
                client.starttls(self.context)
            client.plain_login(username, password)
        except LoginError:
            return LoginResult.INVALID
        except (OSError, ssl.SSLError, IMAPClientError) as exc:
            log.warning("IMAP login on %s:%d failed: %s", self.host, self.port, exc)
            return LoginResult.UNAVAILABLE
        finally:
            try:
                client.logout()
            except (OSError, IMAPClientError):
                client.shutdown()
        return LoginResult.OK
