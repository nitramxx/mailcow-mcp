"""Client for the mailcow API and OAuth profile endpoint. Used by the broker only.

Verified against mailcow-dockerized 2026-09 (see docs/development/mailcow-api.md):
- every API key acts as admin; write calls answer HTTP 200 with a JSON list of
  {type, msg} where type "danger"/"error" means failure;
- creating an app password doesn't return its ID: list and match by name;
- listing app passwords includes the password hash, which we drop.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

import httpx

from mailcow_mcp.limits import HTTP_TIMEOUT
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

APP_PASSWORD_PROTOCOLS = ["imap_access", "smtp_access", "dav_access"]


class MailcowError(Exception):
    """The mailcow API refused or failed a request."""


class MailcowUnavailable(MailcowError):
    pass


class TokenRejected(MailcowError):
    """mailcow didn't accept the OAuth token (expired, wrong scope, inactive mailbox)."""


def _message(response: httpx.Response) -> str:
    """mailcow's reason, e.g. "api access denied for ip 172.22.1.9" (never contains the key)."""
    try:
        data = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(data, dict):
        return str(data.get("msg") or data.get("message") or "")[:200]
    return ""


def _is_active(row: dict[str, Any]) -> bool:
    """mailcow's "active" flag, which comes as 1, "1" or "true" depending on the endpoint."""
    return str(row.get("active", "1")) in ("1", "True", "true")


class MailcowApi:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        profile_url: str,
        *,
        server_name: str,
        verify: bool = True,
        ca_file: Any = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        context = client_context(server_name=server_name, verify=verify, ca_file=ca_file)
        # Connect to the internal name, but present and verify the mailcow hostname.
        headers = {"Host": server_name, "Accept": "application/json"}
        self._api = httpx.AsyncClient(
            base_url=api_url,
            headers={**headers, "X-API-Key": api_key},
            verify=context,
            timeout=HTTP_TIMEOUT,
            transport=transport,
            follow_redirects=False,
        )
        self._profile = httpx.AsyncClient(
            headers=headers,
            verify=context,
            timeout=HTTP_TIMEOUT,
            transport=transport,
            follow_redirects=False,
        )
        self._profile_url = profile_url

    async def aclose(self) -> None:
        await self._api.aclose()
        await self._profile.aclose()

    async def _request(self, method: str, path: str, json: Any = None) -> Any:
        try:
            response = await self._api.request(method, path, json=json)
        except httpx.HTTPError as exc:
            log.warning("mailcow API %s %s failed: %s", method, path, exc)
            raise MailcowUnavailable(f"mailcow API unreachable: {type(exc).__name__}") from exc
        if response.status_code in (401, 403):
            reason = _message(response)
            log.warning(
                "mailcow API refused %s %s: HTTP %s %s", method, path, response.status_code, reason
            )
            raise MailcowError(
                f"mailcow API refused the request (HTTP {response.status_code}: {reason}); "
                "check the API key and 'Allow API access from'"
            )
        if response.status_code >= 400:
            raise MailcowError(f"mailcow API error: HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise MailcowError("mailcow API returned invalid JSON") from exc

    async def _write(self, path: str, body: Any) -> None:
        result = await self._request("POST", path, body)
        items = result if isinstance(result, list) else [result]
        failures = [
            i for i in items if isinstance(i, dict) and i.get("type") in ("danger", "error")
        ]
        # Success is an explicit {"type": "success"}; anything else ({}, [], unknown shapes)
        # means mailcow didn't do it.
        succeeded = any(isinstance(i, dict) and i.get("type") == "success" for i in items)
        if failures or not succeeded:
            message = failures[0].get("msg") if failures else "no success reported"
            raise MailcowError(f"mailcow refused {path}: {message}")

    async def _get(self, path: str) -> Any:
        return await self._request("GET", path)

    @staticmethod
    def _rows(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return [r for r in result if isinstance(r, dict)]
        if isinstance(result, dict) and result and "id" in result:
            return [result]
        return []  # mailcow answers {} or [] for "nothing found"

    # --- OAuth ---------------------------------------------------------------

    async def profile_username(self, access_token: str) -> str:
        """The mailbox an OAuth access token belongs to (asked of mailcow, never trusted from the app)."""
        try:
            response = await self._profile.get(
                self._profile_url, headers={"Authorization": f"Bearer {access_token}"}
            )
        except httpx.HTTPError as exc:
            raise MailcowUnavailable(
                f"mailcow OAuth profile unreachable: {type(exc).__name__}"
            ) from exc
        if response.status_code >= 500:
            raise MailcowUnavailable(f"mailcow OAuth profile: HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise TokenRejected("invalid profile response") from exc
        if not isinstance(data, dict):
            raise TokenRejected("invalid profile response")
        username = data.get("username")
        if response.status_code != 200 or not data.get("success") or not isinstance(username, str):
            raise TokenRejected("mailcow did not accept the token")
        if not _is_active(data):
            raise TokenRejected("the mailbox is inactive")
        return username.strip().lower()

    # --- app passwords -------------------------------------------------------

    async def password_policy(self) -> dict[str, int]:
        data = await self._get("/api/v1/get/passwordpolicy")
        policy: dict[str, int] = {}
        if isinstance(data, dict):
            for key in ("length", "chars", "special_chars", "lowerupper", "numbers"):
                try:
                    policy[key] = int(data.get(key, 0))
                except (TypeError, ValueError):
                    policy[key] = 0
        return policy

    async def add_app_password(self, username: str, name: str, password: str) -> None:
        await self._write(
            "/api/v1/add/app-passwd",
            {
                "username": username,
                "app_name": name,
                "app_passwd": password,
                "app_passwd2": password,
                "active": "1",
                "protocols": APP_PASSWORD_PROTOCOLS,
            },
        )

    async def app_passwords(self, username: str) -> list[dict[str, Any]]:
        rows = self._rows(
            await self._get(f"/api/v1/get/app-passwd/all/{quote(username, safe='@')}")
        )
        result = []
        for row in rows:
            row.pop("password", None)  # mailcow includes the hash
            try:
                row["id"] = int(row["id"])
            except (KeyError, TypeError, ValueError):
                continue
            if str(row.get("mailbox", username)).lower() == username:
                result.append(row)
        return result

    async def delete_app_passwords(self, ids: list[int]) -> None:
        if ids:
            await self._write("/api/v1/delete/app-passwd", [str(i) for i in ids])

    # --- mailboxes, aliases, quarantine, logs ---------------------------------

    async def mailbox_name(self, username: str) -> str:
        """The mailbox's full name as set in mailcow ("" if none)."""
        data = await self._get(f"/api/v1/get/mailbox/{quote(username, safe='@')}")
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else {}
        name = data.get("name") if isinstance(data, dict) else None
        return " ".join(name.split()) if isinstance(name, str) else ""

    async def aliases(self, mailbox: str) -> list[str]:
        """Active aliases that deliver to the mailbox."""
        pattern = re.compile(rf"(^|,)\s*{re.escape(mailbox)}\s*($|,)", re.IGNORECASE)
        result = []
        for row in self._rows(await self._get("/api/v1/get/alias/all")):
            address = str(row.get("address", "")).strip().lower()
            if not address or address.startswith("@"):
                continue  # catch-all
            if not _is_active(row):
                continue
            if pattern.search(str(row.get("goto", ""))):
                result.append(address)
        return sorted(set(result))

    async def quarantine(self) -> list[dict[str, Any]]:
        return self._rows(await self._get("/api/v1/get/quarantine/all"))

    async def quarantine_item(self, item_id: int) -> dict[str, Any] | None:
        rows = self._rows(await self._get(f"/api/v1/get/quarantine/{item_id}"))
        return rows[0] if rows else None

    async def quarantine_release(self, item_id: int) -> None:
        await self._write(
            "/api/v1/edit/qitem", {"items": [str(item_id)], "attr": {"action": "release"}}
        )

    async def quarantine_delete(self, item_id: int) -> None:
        await self._write("/api/v1/delete/qitem", [str(item_id)])

    async def postfix_logs(self, count: int) -> list[dict[str, Any]]:
        data = await self._get(f"/api/v1/get/logs/postfix/{count}")
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
