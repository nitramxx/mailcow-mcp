"""A mock mailcow (OAuth server + API), shaped like mailcow-dockerized 2026-09.

It reproduces the quirks the broker relies on: write calls answer HTTP 200 with
a list of {type, msg}; creating an app password doesn't return its ID; listing
app passwords includes the password hash; every API key is an admin.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

API_KEY = "MOCK-API-KEY-1234"
CLIENT_ID = "0123456789ab"
CLIENT_SECRET = "0123456789abcdef01234567"


@dataclass
class MockMailcow:
    redirect_uri: str = ""
    login_as: str = "alice@example.test"  # who is "signed in" at the authorize page
    deny: bool = False
    app_passwords: list[dict[str, Any]] = field(default_factory=list)
    aliases: list[dict[str, Any]] = field(default_factory=list)
    quarantine: list[dict[str, Any]] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)
    released: list[int] = field(default_factory=list)
    on_app_password: Callable[[str, str | None], None] | None = None
    codes: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)
    _next_id: int = 100

    def add_existing_app_password(self, mailbox: str, name: str) -> int:
        self._next_id += 1
        self.app_passwords.append(
            {
                "id": self._next_id,
                "name": name,
                "mailbox": mailbox,
                "password": "{BLF-CRYPT}x",
                "active": "1",
            }
        )
        return self._next_id

    def passwords_of(self, mailbox: str) -> list[dict[str, Any]]:
        return [p for p in self.app_passwords if p["mailbox"] == mailbox]

    # --- OAuth ---------------------------------------------------------------

    async def authorize(self, request: Request) -> Response:
        q = request.query_params
        if q.get("client_id") != CLIENT_ID or q.get("redirect_uri") != self.redirect_uri:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if not q.get("state"):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "state required"}, status_code=400
            )
        if self.deny:
            return RedirectResponse(
                f"{self.redirect_uri}?{urlencode({'error': 'access_denied', 'state': q['state']})}",
                302,
            )
        code = secrets.token_hex(20)
        self.codes[code] = self.login_as
        return RedirectResponse(
            f"{self.redirect_uri}?{urlencode({'code': code, 'state': q['state']})}", 302
        )

    async def token(self, request: Request) -> Response:
        form = await request.form()
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if form.get("redirect_uri") != self.redirect_uri:
            return JSONResponse({"error": "redirect_uri_mismatch"}, status_code=400)
        user = self.codes.pop(str(form.get("code")), None)
        if user is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        token = secrets.token_hex(20)
        self.tokens[token] = user
        return JSONResponse(
            {
                "access_token": token,
                "expires_in": 86400,
                "token_type": "Bearer",
                "scope": "profile",
                "refresh_token": secrets.token_hex(20),
            }
        )

    async def profile(self, request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        user = self.tokens.get(auth.removeprefix("Bearer ").strip())
        if user is None:
            return JSONResponse({"success": False})
        return JSONResponse(
            {
                "success": True,
                "username": user,
                "id": user,
                "identifier": user,
                "email": user,
                "full_name": "Alice",
                "displayName": "Alice",
                "created": "2026-01-01 00:00:00",
                "modified": None,
                "active": "1",
            }
        )

    # --- API -----------------------------------------------------------------

    def _authorized(self, request: Request) -> bool:
        self.requests.append((request.method, request.url.path))
        return request.headers.get("x-api-key") == API_KEY

    async def api(self, request: Request) -> Response:
        if not self._authorized(request):
            return JSONResponse({"type": "error", "msg": "authentication failed"}, status_code=401)
        path = request.url.path.removeprefix("/api/v1/")
        body: Any = await request.json() if request.method == "POST" else None
        ok = [{"type": "success", "log": [], "msg": "ok"}]
        if path == "get/passwordpolicy":
            return JSONResponse(
                {
                    "length": "8",
                    "chars": "1",
                    "special_chars": "1",
                    "lowerupper": "1",
                    "numbers": "1",
                }
            )
        if path == "add/app-passwd":
            assert isinstance(body, dict)
            if (
                body.get("app_passwd") != body.get("app_passwd2")
                or len(body.get("app_passwd", "")) < 8
            ):
                return JSONResponse([{"type": "danger", "msg": "password_complexity"}])
            if body.get("active") != "1" or not set(body.get("protocols", [])) <= {
                "imap_access",
                "smtp_access",
                "dav_access",
                "eas_access",
                "pop3_access",
                "sieve_access",
            }:
                return JSONResponse([{"type": "danger", "msg": "unexpected attributes"}])
            self._next_id += 1
            self.app_passwords.append(
                {
                    "id": self._next_id,
                    "name": body["app_name"],
                    "mailbox": body["username"],
                    "password": "{BLF-CRYPT}hash",
                    "protocols": body["protocols"],
                    "active": "1",
                    "created": "2026-10-01 12:00:00",
                }
            )
            if self.on_app_password:
                self.on_app_password(body["username"], body["app_passwd"])
            return JSONResponse(
                [{"type": "success", "log": ["app_passwd", "add", {}], "msg": "app_passwd_added"}]
            )
        if path.startswith("get/app-passwd/all/"):
            mailbox = path.rsplit("/", 1)[1]
            rows = [
                {k: v for k, v in p.items() if k != "protocols"} for p in self.passwords_of(mailbox)
            ]
            return JSONResponse(rows or {})
        if path == "delete/app-passwd":
            ids = {int(i) for i in body}
            for p in [p for p in self.app_passwords if p["id"] in ids]:
                self.app_passwords.remove(p)
                if self.on_app_password:
                    self.on_app_password(p["mailbox"], None)
            return JSONResponse(ok)
        if path == "get/alias/all":
            return JSONResponse(self.aliases or {})
        if path == "get/quarantine/all":
            return JSONResponse(
                [{k: v for k, v in q.items() if k != "msg"} for q in self.quarantine] or {}
            )
        if path.startswith("get/quarantine/"):
            item_id = int(path.rsplit("/", 1)[1])
            found = [q for q in self.quarantine if q["id"] == item_id]
            return JSONResponse(found[0] if found else {})
        if path == "edit/qitem":
            item_id = int(body["items"][0])
            if body["attr"]["action"] == "release":
                self.quarantine = [q for q in self.quarantine if q["id"] != item_id]
                self.released.append(item_id)
            return JSONResponse(ok)
        if path == "delete/qitem":
            ids = {int(i) for i in body}
            self.quarantine = [q for q in self.quarantine if q["id"] not in ids]
            return JSONResponse(ok)
        if path.startswith("get/logs/postfix/"):
            return JSONResponse(sorted(self.logs, key=lambda r: -int(r["time"])))
        return JSONResponse({"type": "error", "msg": "route not found"}, status_code=404)

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/oauth/authorize", self.authorize, methods=["GET"]),
                Route("/oauth/token", self.token, methods=["POST"]),
                Route("/oauth/profile", self.profile, methods=["GET"]),
                Route("/api/v1/{path:path}", self.api, methods=["GET", "POST"]),
            ]
        )


@dataclass
class RunningMailcow:
    mock: MockMailcow
    url: str


def run_mailcow(certs: Path) -> Iterator[RunningMailcow]:
    """Serve the mock over HTTPS (certificate for mail.test) on a random port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    mock = MockMailcow()
    config = uvicorn.Config(
        mock.app(),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ssl_certfile=str(certs / "server.crt"),
        ssl_keyfile=str(certs / "server.key"),
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("mock mailcow did not start")
        time.sleep(0.02)
    try:
        yield RunningMailcow(mock, f"https://127.0.0.1:{port}")
    finally:
        server.should_exit = True
        thread.join(timeout=10)
