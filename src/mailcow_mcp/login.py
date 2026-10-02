"""The sign-in pages: consent for a new connection, and adding a mailbox to one.

/login (where /authorize redirects): shows who is asking for access and where it
goes; signing in sends the browser back to the client with a code.
/connect (the add_mailbox link): signs another mailbox into an existing connection.
Both sign in with mailcow or with a password checked by the mail server.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import jinja2
from mcp.server.transport_security import RequestBodyLimitMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route, request_response

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.broker_client import BrokerClient
from mailcow_mcp.config import AppConfig, Sending
from mailcow_mcp.crypto import hash_secret, new_secret
from mailcow_mcp.errors import MailError, ServerUnavailable
from mailcow_mcp.i18n import Translator, pick_language
from mailcow_mcp.imap import LoginResult, PasswordVerifier
from mailcow_mcp.mailcow_login import (
    CALLBACK_PATH,
    MailcowLoginFailed,
    MailcowLoginUnavailable,
    MailcowOAuth,
)
from mailcow_mcp.oauth import (
    AUTH_REQUEST_TTL,
    CONNECT_PATH,
    LOOPBACK_HOSTS,
    AddResult,
    PendingAuthorization,
    PendingConnect,
    Provider,
    canonical_url,
)
from mailcow_mcp.ratelimit import RateLimiter, client_key
from mailcow_mcp.request_context import client_ip

log = logging.getLogger(__name__)

LOGIN_PATH = "/login"
STYLESHEET_PATH = "/static/style.css"
MAX_FORM_BYTES = 16 * 1024
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 1024

_BROWSER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
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


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# A sign-in in progress: for a new connection, or a mailbox to add to one.
Pending = PendingAuthorization | PendingConnect


def form_token(pending: Pending, browser_id: str) -> str:
    """The form's CSRF value: valid only for this sign-in request in this browser."""
    return hmac.new(pending.csrf.encode(), browser_id.encode(), hashlib.sha256).hexdigest()


class LoginPages:
    def __init__(
        self,
        config: AppConfig,
        provider: Provider,
        verifier: PasswordVerifier,
        audit: AuditLog,
        *,
        mailcow: MailcowOAuth | None = None,
        broker: BrokerClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.provider = provider
        self.verifier = verifier
        self.audit = audit
        self.mailcow = mailcow
        self.broker = broker
        self.secure_cookies = config.https
        prefix = "__Host-" if self.secure_cookies else ""
        self.state_cookie_prefix = prefix + "mcp_mailcow_"
        self.browser_cookie = prefix + "mcp_login"
        self.public_origin = canonical_url(config.public_url)
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
        connect = RequestBodyLimitMiddleware(request_response(self.handle_connect), MAX_FORM_BYTES)
        routes = [
            Route(LOGIN_PATH, endpoint=endpoint, methods=["GET", "POST"]),
            Route(CONNECT_PATH, endpoint=connect, methods=["GET", "POST"]),
        ]
        if self.mailcow is not None:
            routes.append(Route(CALLBACK_PATH, self.mailcow_callback, methods=["GET"]))
        return routes

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
            lang=t.lang,
            t=t,
            instance_name=self.config.instance_name,
            stylesheet=STYLESHEET_PATH,
            login_path=LOGIN_PATH,
            connect_path=CONNECT_PATH,
            max_email=MAX_EMAIL_LENGTH,
            max_password=MAX_PASSWORD_LENGTH,
            **context,
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
            headers={
                "Content-Security-Policy": csp,
                "Cache-Control": "no-store",
                # Our own form posts carry our Origin; other sites never see the URL
                # (it contains the sign-in request id).
                "Referrer-Policy": "same-origin",
            },
        )

    def _message(self, t: Translator, title: str, body: str, status_code: int) -> HTMLResponse:
        return self._render("message.html", t, status_code, title=t(title), body=t(body))

    def _expired(self, t: Translator) -> HTMLResponse:
        return self._message(t, "expired_title", "expired_body", 400)

    def _state_cookie(self, state: str) -> str:
        # One cookie per sign-in, so two tabs signing in at once don't undo each other.
        return self.state_cookie_prefix + hash_secret(state)[:16]

    def _browser_id(self, request: Request) -> str | None:
        value = request.cookies.get(self.browser_cookie, "")
        return value if _BROWSER_ID_RE.match(value) else None

    def _set_cookie(self, response: Response, name: str, value: str, samesite: str) -> None:
        response.set_cookie(
            name,
            value,
            max_age=AUTH_REQUEST_TTL,
            path="/",
            secure=self.secure_cookies,
            httponly=True,
            samesite=samesite,  # type: ignore[arg-type]
        )

    def _delete_cookie(self, response: Response, name: str) -> None:
        # Browsers ignore a deletion of a Secure cookie that isn't Secure itself.
        response.delete_cookie(
            name, path="/", secure=self.secure_cookies, httponly=True, samesite="lax"
        )

    def _login_page(
        self,
        request: Request,
        t: Translator,
        pending: PendingAuthorization,
        *,
        status_code: int = 200,
        error: str | None = None,
        email: str = "",
    ) -> HTMLResponse:
        parts = urlsplit(pending.redirect_uri)
        loopback = parts.hostname in LOOPBACK_HOSTS
        targets = _origin(pending.redirect_uri)
        if self.mailcow is not None:
            targets += " " + _origin(self.mailcow.base_url)
        # The form only works from the browser that loaded it: a page elsewhere can't
        # post a request it started itself on behalf of someone else's browser
        # (SameSite keeps the cookie off cross-site posts).
        browser_id = self._browser_id(request) or new_secret()
        response = self._render(
            "login.html",
            t,
            status_code,
            form_target=targets,
            mailcow_login=self.mailcow is not None,
            client_name=pending.client_name,
            redirect_host=parts.netloc if loopback else parts.hostname,
            redirect_loopback=loopback,
            request_id=pending.request_id,
            resume=pending.resume or "",
            csrf=form_token(pending, browser_id),
            password_login=self.config.allow_password_login,
            sending=self.config.sending is Sending.ENABLED,
            error=error,
            email=email,
        )
        self._set_cookie(response, self.browser_cookie, browser_id, "lax")
        return response

    def _connect_page(
        self,
        request: Request,
        t: Translator,
        pending: PendingConnect,
        *,
        status_code: int = 200,
        error: str | None = None,
        email: str = "",
    ) -> HTMLResponse:
        browser_id = self._browser_id(request) or new_secret()
        response = self._render(
            "connect.html",
            t,
            status_code,
            form_target=_origin(self.mailcow.base_url) if self.mailcow is not None else None,
            mailcow_login=self.mailcow is not None,
            client_name=pending.client_name,
            connected=", ".join(pending.mailboxes),
            code=pending.code,
            resume=pending.resume or "",
            csrf=form_token(pending, browser_id),
            password_login=self.config.allow_password_login,
            error=error,
            email=email,
        )
        self._set_cookie(response, self.browser_cookie, browser_id, "lax")
        return response

    def _page(
        self,
        request: Request,
        t: Translator,
        pending: Pending,
        *,
        status_code: int = 200,
        error: str | None = None,
        email: str = "",
    ) -> HTMLResponse:
        page = self._login_page if isinstance(pending, PendingAuthorization) else self._connect_page
        return page(request, t, pending, status_code=status_code, error=error, email=email)  # type: ignore[arg-type]

    # --- handlers ------------------------------------------------------------

    async def handle(self, request: Request) -> Response:
        t = self._translator(request)
        ip = client_ip.get() or "unknown"
        if request.method == "POST":
            return await self._post(request, t, ip)
        if not self.page_limit.hit(client_key(ip)):
            return self._message(t, "rate_limited_title", "error_rate_limited", 429)
        if not self.config.allow_password_login and self.mailcow is None:
            return self._message(t, "no_login_title", "no_login_body", 503)
        pending = await self.provider.load_pending(request.query_params.get("request", ""))
        if pending is None:
            return self._expired(t)
        return self._login_page(request, t, pending)

    def _cross_origin(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        # Our page sends its Origin (Referrer-Policy same-origin). "null" comes from
        # sandboxed frames and privacy redirects, never from our own form.
        return origin is not None and (
            origin == "null" or canonical_url(origin) != self.public_origin
        )

    def _form_matches(self, request: Request, pending: Pending | None, csrf: str) -> bool:
        browser_id = self._browser_id(request)
        return (
            pending is not None
            and browser_id is not None
            and _same(csrf, form_token(pending, browser_id))
        )

    async def _post(self, request: Request, t: Translator, ip: str) -> Response:
        if self._cross_origin(request):
            return self._message(t, "expired_title", "error_cross_origin", 403)
        form = await request.form()

        def field(name: str) -> str:
            value = form.get(name)
            return value if isinstance(value, str) else ""

        if field("request"):
            pending = await self.provider.load_pending(field("request"))
        else:
            # A retry from the error page after mailcow's redirect back.
            pending = await self.provider.load_pending_by_state(field("resume"))
        if not self._form_matches(request, pending, field("csrf")):
            return self._expired(t)
        assert pending is not None  # noqa: S101 - checked by _form_matches

        if field("action") == "deny":
            return RedirectResponse(self.provider.deny(pending), status_code=303)
        return await self._sign_in(request, t, pending, ip, field)

    async def handle_connect(self, request: Request) -> Response:
        """The add_mailbox link: sign another mailbox into an existing connection."""
        t = self._translator(request)
        ip = client_ip.get() or "unknown"
        if request.method == "GET":
            if not self.page_limit.hit(client_key(ip)):
                return self._message(t, "rate_limited_title", "error_rate_limited", 429)
            pending = self.provider.load_connect(request.query_params.get("code", ""))
            if pending is None:
                return self._message(t, "connect_expired_title", "connect_expired_body", 400)
            return self._connect_page(request, t, pending)

        if self._cross_origin(request):
            return self._message(t, "expired_title", "error_cross_origin", 403)
        form = await request.form()

        def field(name: str) -> str:
            value = form.get(name)
            return value if isinstance(value, str) else ""

        if field("code"):
            connect = self.provider.load_connect(field("code"))
        else:
            connect = self.provider.load_connect_by_state(field("resume"))
        if not self._form_matches(request, connect, field("csrf")):
            return self._message(t, "connect_expired_title", "connect_expired_body", 400)
        assert connect is not None  # noqa: S101 - checked by _form_matches

        if field("action") == "deny":
            self.provider.cancel_connect(connect)
            return self._message(t, "connect_cancelled_title", "connect_cancelled_body", 200)
        return await self._sign_in(request, t, connect, ip, field)

    async def _sign_in(
        self,
        request: Request,
        t: Translator,
        pending: Pending,
        ip: str,
        field: Callable[[str], str],
    ) -> Response:
        """The sign-in buttons of either page: with mailcow, or with a password."""
        if field("action") == "mailcow" and self.mailcow is not None:
            return self._start_mailcow(request, t, pending, ip)
        if not self.config.allow_password_login:
            return self._message(t, "no_login_title", "no_login_body", 503)

        if not self.attempt_limit.hit(client_key(ip)):
            self.audit("login", result="rate_limited", ip=ip, client=pending.client_name)
            return self._page(request, t, pending, status_code=429, error=t("error_rate_limited"))

        email_input = field("email")
        username = normalize_email(email_input)
        password = field("password")
        if username is None:
            return self._page(
                request,
                t,
                pending,
                status_code=400,
                error=t("error_email"),
                email=email_input[:MAX_EMAIL_LENGTH],
            )
        if not password or len(password) > MAX_PASSWORD_LENGTH or "\x00" in password:
            return self._page(
                request, t, pending, status_code=401, error=t("error_credentials"), email=username
            )

        domain = username.rpartition("@")[2]
        if self.config.allowed_domains and domain not in self.config.allowed_domains:
            self.audit("login", result="domain_not_allowed", mailbox=username, ip=ip)
            return self._page(
                request,
                t,
                pending,
                status_code=403,
                error=t("error_domain", domain=domain),
                email=username,
            )

        # Counted before the check, so parallel attempts can't all get through.
        if not self.failure_limit.hit(username):
            self.audit("login", result="rate_limited", mailbox=username, ip=ip)
            return self._page(
                request, t, pending, status_code=429, error=t("error_rate_limited"), email=username
            )

        result = await self.verifier(username, password)
        if result is LoginResult.UNAVAILABLE:
            self.audit("login", result="server_unavailable", mailbox=username, ip=ip)
            return self._page(
                request, t, pending, status_code=503, error=t("error_unavailable"), email=username
            )
        if result is LoginResult.INVALID:
            self.audit("login", result="invalid_credentials", mailbox=username, ip=ip)
            return self._page(
                request, t, pending, status_code=401, error=t("error_credentials"), email=username
            )

        self.failure_limit.reset(username)
        done, _ = self._complete(
            t, pending, username=username, credential=password, login_method="password"
        )
        return done

    def _complete(
        self,
        t: Translator,
        pending: Pending,
        *,
        username: str,
        credential: str,
        login_method: str,
        app_password_id: int | None = None,
        capability: str | None = None,
    ) -> tuple[Response, bool]:
        """Finish a sign-in: (the response, whether the credential is now in use)."""
        if isinstance(pending, PendingAuthorization):
            redirect = self.provider.complete(
                pending,
                username=username,
                credential=credential,
                login_method=login_method,
                app_password_id=app_password_id,
                capability=capability,
            )
            if redirect is None:
                return self._expired(t), False
            return RedirectResponse(
                redirect, status_code=303, headers={"Cache-Control": "no-store"}
            ), True
        added = self.provider.add_mailbox(
            pending,
            username=username,
            credential=credential,
            login_method=login_method,
            app_password_id=app_password_id,
            capability=capability,
        )
        client = pending.client_name or t("client_unnamed")
        if added is AddResult.ADDED:
            body = t("connect_done_body", mailbox=username, client=client)
            return self._render(
                "message.html", t, 200, title=t("connect_done_title"), body=body
            ), True
        if added is AddResult.ALREADY_CONNECTED:
            body = t("connect_already_body", mailbox=username, client=client)
            return self._render(
                "message.html", t, 409, title=t("connect_already_title"), body=body
            ), False
        if added is AddResult.FULL:
            return self._message(t, "connect_full_title", "connect_full_body", 409), False
        return self._message(t, "connect_expired_title", "connect_expired_body", 400), False

    # --- sign in with mailcow ------------------------------------------------

    def _start_mailcow(
        self, request: Request, t: Translator, pending: Pending, ip: str
    ) -> Response:
        assert self.mailcow is not None  # noqa: S101 - checked by the caller
        if not self.attempt_limit.hit(client_key(ip)):
            return self._page(request, t, pending, status_code=429, error=t("error_rate_limited"))
        state = new_secret()
        if isinstance(pending, PendingAuthorization):
            self.provider.set_mailcow_state(pending, state)
        else:
            self.provider.set_connect_state(pending, state)
        response = RedirectResponse(self.mailcow.authorize_url(state), status_code=303)
        # Binds the callback to this browser: mailcow's redirect back must carry the
        # same state as the cookie (Lax: sent on that top-level navigation).
        self._set_cookie(response, self._state_cookie(state), state, "lax")
        return response

    def _mailcow_error(
        self, request: Request, t: Translator, pending: Pending, key: str, status: int
    ) -> Response:
        response = self._page(request, t, pending, status_code=status, error=t(key))
        self._clear_state(request, response)
        return response

    def _clear_state(self, callback: Request, response: Response) -> None:
        """Delete the state cookie of the sign-in this mailcow callback belongs to."""
        self._delete_cookie(response, self._state_cookie(callback.query_params.get("state", "")))

    async def mailcow_callback(self, request: Request) -> Response:
        assert self.mailcow is not None and self.broker is not None  # noqa: S101 - mailcow mode
        t = self._translator(request)
        ip = client_ip.get() or "unknown"
        if not self.page_limit.hit(client_key(ip)):
            return self._message(t, "rate_limited_title", "error_rate_limited", 429)
        state = request.query_params.get("state", "")
        cookie = request.cookies.get(self._state_cookie(state), "") if state else ""
        if not state or not _same(state, cookie):
            self.audit("login", result="state_mismatch", ip=ip)
            return self._expired(t)
        pending: Pending | None = await self.provider.load_pending_by_state(state)
        if pending is None:
            pending = self.provider.load_connect_by_state(state)
        if pending is None:
            return self._expired(t)
        if request.query_params.get("error"):
            # The user declined at mailcow's consent page.
            self.audit("login", result="mailcow_declined", client=pending.client_name, ip=ip)
            return self._mailcow_error(request, t, pending, "error_mailcow_cancelled", 400)
        code = request.query_params.get("code", "")
        if not code or len(code) > 1024:
            return self._mailcow_error(request, t, pending, "error_mailcow_failed", 400)

        try:
            token = await self.mailcow.exchange(code)
            provisioned = await self.broker.provision(token, pending.client_name)
        except MailcowLoginUnavailable:
            return self._mailcow_error(request, t, pending, "error_mailcow_unavailable", 503)
        except ServerUnavailable:
            return self._mailcow_error(request, t, pending, "error_mailcow_unavailable", 503)
        except (MailcowLoginFailed, MailError) as exc:
            self.audit(
                "login",
                result="mailcow_failed",
                client=pending.client_name,
                ip=ip,
                error=str(exc)[:200],
            )
            return self._mailcow_error(request, t, pending, "error_mailcow_failed", 502)
        del token  # not kept: the broker has used it

        capability = str(provisioned["capability"])
        try:
            return await self._finish_mailcow(request, t, pending, provisioned, ip)
        except Exception:
            await self._undo(capability)
            raise

    async def _finish_mailcow(
        self,
        request: Request,
        t: Translator,
        pending: Pending,
        provisioned: dict[str, Any],
        ip: str,
    ) -> Response:
        """Checks the new app password and completes the sign-in; undoes it on any refusal."""
        username = str(provisioned["username"])
        capability = str(provisioned["capability"])
        password = str(provisioned["app_password"])
        domain = username.rpartition("@")[2]
        if self.config.allowed_domains and domain not in self.config.allowed_domains:
            await self._undo(capability)
            self.audit("login", result="domain_not_allowed", mailbox=username, ip=ip)
            return self._mailcow_error(request, t, pending, "error_domain_mailcow", 403)
        # The new app password must work before the client gets a code.
        if await self.verifier(username, password) is not LoginResult.OK:
            await self._undo(capability)
            self.audit("login", result="app_password_rejected", mailbox=username, ip=ip)
            return self._mailcow_error(request, t, pending, "error_mailcow_failed", 502)

        response, kept = self._complete(
            t,
            pending,
            username=username,
            credential=password,
            login_method="mailcow",
            app_password_id=int(provisioned["app_password_id"]),
            capability=capability,
        )
        if not kept:
            await self._undo(capability)
        self._clear_state(request, response)
        return response

    async def _undo(self, capability: str) -> None:
        assert self.broker is not None  # noqa: S101
        try:
            await self.broker.deprovision(capability)
        except MailError:
            log.warning("could not delete an app password after a failed sign-in; reconcile will")
