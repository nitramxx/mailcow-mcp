"""The app as an OAuth client of mailcow ("Sign in with mailcow").

mailcow's OAuth server (bshaffer/oauth2-server-php) has no PKCE, requires
``state`` and an exact redirect URI, and only knows the ``profile`` scope. The
code is exchanged here with the client secret; the access token goes straight
to the broker, which asks mailcow whose it is, and is then discarded.
"""

from __future__ import annotations

import logging
import ssl
from urllib.parse import urlencode, urlsplit

import httpx

from mailcow_mcp.config import AppConfig
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

CALLBACK_PATH = "/oauth/mailcow/callback"


class MailcowLoginFailed(Exception):
    pass


class MailcowLoginUnavailable(MailcowLoginFailed):
    pass


class MailcowOAuth:
    def __init__(
        self,
        config: AppConfig,
        *,
        verify: ssl.SSLContext | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        assert config.mailcow_url and config.mailcow_oauth_client_id  # noqa: S101 - mailcow mode
        self.base_url = config.mailcow_url
        self.client_id = config.mailcow_oauth_client_id
        self.client_secret = config.mailcow_oauth_client_secret or ""
        self.redirect_uri = config.public_url + CALLBACK_PATH
        # The browser goes to the public URL; our token request may go to nginx directly.
        self.token_base = config.mailcow_internal_url or config.mailcow_url
        headers = {}
        if config.mailcow_internal_url:
            headers["Host"] = urlsplit(config.mailcow_url).netloc
        context = verify or client_context(
            server_name=config.tls_server_name if config.mailcow_internal_url else None,
            verify=config.tls_verify,
            ca_file=config.tls_ca_file,
        )
        self._http = httpx.AsyncClient(
            headers=headers,
            verify=context,
            timeout=httpx.Timeout(20.0, connect=10.0),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def authorize_url(self, state: str) -> str:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "state": state,
                "scope": "profile",
            }
        )
        return f"{self.base_url}/oauth/authorize?{query}"

    async def exchange(self, code: str) -> str:
        """Authorization code → mailcow access token."""
        try:
            response = await self._http.post(
                f"{self.token_base}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            log.warning("mailcow token request failed: %s", exc)
            raise MailcowLoginUnavailable(str(exc)) from exc
        try:
            data = response.json()
        except ValueError:
            data = {}
        token = data.get("access_token") if isinstance(data, dict) else None
        if response.status_code != 200 or not isinstance(token, str) or not token:
            error = data.get("error") if isinstance(data, dict) else None
            log.warning("mailcow token request refused: HTTP %s %s", response.status_code, error)
            raise MailcowLoginFailed(f"mailcow refused the code ({error or response.status_code})")
        return token
