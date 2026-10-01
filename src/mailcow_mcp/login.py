"""The sign-in and consent page that /authorize redirects to.

GET shows who is asking for access and where it goes; POST checks the password
with the mail server and sends the browser back to the client with a code.
"""

from __future__ import annotations

import hmac
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import jinja2
from mcp.server.transport_security import RequestBodyLimitMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route, request_response

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.config import AppConfig
from mailcow_mcp.i18n import Translator, pick_language
from mailcow_mcp.imap import LoginResult, PasswordVerifier
from mailcow_mcp.oauth import LOOPBACK_HOSTS, PendingAuthorization, Provider, client_ip
from mailcow_mcp.ratelimit import RateLimiter

LOGIN_PATH = "/login"
MAX_FORM_BYTES = 16 * 1024
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 1024

_EMAIL_RE = re.compile(r"^[^\s@\"(),:;<>\[\\\]]{1,64}@[^\s@]{1,253}$")
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def normalize_email(value: str) -> str | None:
    """Lowercased address with an IDNA domain, or None if it isn't one."""
    value = value.strip()
    if len(value) > MAX_EMAIL_LENGTH or not _EMAIL_RE.match(value):
        return None
    local, _, domain = value.rpartition("@")
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return f"{local.lower()}@{domain}"


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class LoginPages:
    def __init__(
        self,
        config: AppConfig,
        provider: Provider,
        verifier: PasswordVerifier,
        audit: AuditLog,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.provider = provider
        self.verifier = verifier
        self.audit = audit
        self.public_origin = _origin(config.public_url)
        self.secure_cookies = config.public_url.startswith("https://")
        self.templates = jinja2.Environment(
            loader=jinja2.PackageLoader("mailcow_mcp", "templates"),
            autoescape=True,
            undefined=jinja2.StrictUndefined,
        )
        # Per client IP: page views and sign-in attempts. Per mailbox: failures.
        self.page_limit = RateLimiter(60, 600, clock=clock)
        self.attempt_limit = RateLimiter(10, 600, clock=clock)
        self.failure_limit = RateLimiter(10, 900, clock=clock)

    def routes(self) -> list[Route]:
        endpoint = RequestBodyLimitMiddleware(request_response(self.handle), MAX_FORM_BYTES)
        return [Route(LOGIN_PATH, endpoint=endpoint, methods=["GET", "POST"])]

    # --- rendering -----------------------------------------------------------

    def _translator(self, request: Request) -> Translator:
        return Translator(
            pick_language(request.headers.get("accept-language"), self.config.default_language)
        )

    def _render(
        self,
        template: str,
        t: Translator,
        status_code: int = 200,
        form_target: str | None = None,
        **context: Any,
    ) -> HTMLResponse:
        html = self.templates.get_template(template).render(
            lang=t.lang, t=t, instance_name=self.config.instance_name, **context
        )
        # The form posts to us, and we redirect to the client: CSP form-action
        # covers that redirect, so the client's origin must be listed too.
        form_action = "'self'" + (f" {form_target}" if form_target else "")
        csp = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            f"form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
        )
        return HTMLResponse(
            html,
            status_code=status_code,
            headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"},
        )

    def _message(self, t: Translator, title: str, body: str, status_code: int) -> HTMLResponse:
        return self._render("message.html", t, status_code, title=t(title), body=t(body))

    def _expired(self, t: Translator) -> HTMLResponse:
        return self._message(t, "expired_title", "expired_body", 400)

    def _login_page(
        self,
        t: Translator,
        pending: PendingAuthorization,
        *,
        status_code: int = 200,
        error: str | None = None,
        email: str = "",
    ) -> HTMLResponse:
        parts = urlsplit(pending.redirect_uri)
        loopback = parts.hostname in LOOPBACK_HOSTS
        return self._render(
            "login.html",
            t,
            status_code,
            form_target=_origin(pending.redirect_uri),
            client_name=pending.client_name,
            redirect_host=parts.netloc if loopback else parts.hostname,
            redirect_loopback=loopback,
            request_id=pending.request_id,
            csrf=pending.csrf,
            password_login=self.config.allow_password_login,
            error=error,
            email=email,
        )

    # --- handlers ------------------------------------------------------------

    async def handle(self, request: Request) -> Response:
        t = self._translator(request)
        ip = client_ip.get() or "unknown"
        if request.method == "POST":
            return await self._post(request, t, ip)
        if not self.page_limit.hit(ip):
            return self._message(t, "expired_title", "error_rate_limited", 429)
        if not self.config.allow_password_login:
            return self._message(t, "no_login_title", "no_login_body", 503)
        pending = await self.provider.load_pending(request.query_params.get("request", ""))
        if pending is None:
            return self._expired(t)
        return self._login_page(t, pending)

    async def _post(self, request: Request, t: Translator, ip: str) -> Response:
        origin = request.headers.get("origin")
        if origin is not None and origin != self.public_origin:
            return PlainTextResponse("cross-origin request refused", status_code=403)
        form = await request.form()

        def field(name: str) -> str:
            value = form.get(name)
            return value if isinstance(value, str) else ""

        pending = await self.provider.load_pending(field("request"))
        if pending is None or not hmac.compare_digest(field("csrf"), pending.csrf):
            return self._expired(t)

        if field("action") == "deny":
            return RedirectResponse(self.provider.deny(pending), status_code=303)
        if not self.config.allow_password_login:
            return self._message(t, "no_login_title", "no_login_body", 503)

        if not self.attempt_limit.hit(ip):
            self.audit("login", result="rate_limited", ip=ip, client=pending.client_name)
            return self._login_page(t, pending, status_code=429, error=t("error_rate_limited"))

        email_input = field("email")[:MAX_EMAIL_LENGTH]
        username = normalize_email(email_input)
        password = field("password")
        if username is None:
            return self._login_page(
                t, pending, status_code=400, error=t("error_email"), email=email_input
            )
        if not password or len(password) > MAX_PASSWORD_LENGTH or "\x00" in password:
            return self._login_page(
                t, pending, status_code=401, error=t("error_credentials"), email=username
            )

        domain = username.rpartition("@")[2]
        if self.config.allowed_domains and domain not in self.config.allowed_domains:
            self.audit("login", result="domain_not_allowed", mailbox=username, ip=ip)
            return self._login_page(
                t, pending, status_code=403, error=t("error_domain", domain=domain), email=username
            )

        if not self.failure_limit.allowed(username):
            self.audit("login", result="rate_limited", mailbox=username, ip=ip)
            return self._login_page(
                t, pending, status_code=429, error=t("error_rate_limited"), email=username
            )

        result = await self.verifier(username, password)
        if result is LoginResult.UNAVAILABLE:
            self.audit("login", result="server_unavailable", mailbox=username, ip=ip)
            return self._login_page(
                t, pending, status_code=503, error=t("error_unavailable"), email=username
            )
        if result is LoginResult.INVALID:
            self.failure_limit.hit(username)
            self.audit("login", result="invalid_credentials", mailbox=username, ip=ip)
            return self._login_page(
                t, pending, status_code=401, error=t("error_credentials"), email=username
            )

        self.failure_limit.reset(username)
        redirect = self.provider.complete(
            pending, username=username, credential=password, login_method="password"
        )
        if redirect is None:
            return self._expired(t)
        return RedirectResponse(redirect, status_code=303, headers={"Cache-Control": "no-store"})
