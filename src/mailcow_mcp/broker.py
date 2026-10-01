"""The broker: the only process with the mailcow API key.

Internal only (no published port, no nginx route). Callers must send the shared
secret, and every operation except ``provision`` needs a capability token. The
broker acts only for the mailbox in the token, and only while its own records
say that token's app password is active. There is no generic API passthrough.

Operations (POST /v1/<operation>, JSON):

- provision(mailcow_oauth_token, client_name)
- deprovision(capability)
- reconcile(capabilities)          app passwords the app no longer holds are deleted
- aliases(capability)
- quarantine_list(capability)
- quarantine_release(capability, id)
- quarantine_delete(capability, id)
- delivery_status(capability, message_id)
"""

from __future__ import annotations

import hmac
import re
import secrets
import string
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mailcow_mcp import __version__
from mailcow_mcp.audit import AuditLog
from mailcow_mcp.capability import Capability, CapabilitySigner, InvalidCapability
from mailcow_mcp.config import BrokerConfig
from mailcow_mcp.db import Database
from mailcow_mcp.mailcow_api import MailcowApi, MailcowError, MailcowUnavailable, TokenRejected
from mailcow_mcp.ratelimit import RateLimiter

SECRET_HEADER = "X-Broker-Secret"  # noqa: S105 - a header name
NAME_PREFIX = "MCP: "
MIGRATIONS = "mailcow_mcp.broker_migrations"
MAX_BODY_BYTES = 64 * 1024
LOG_LINES = 10_000
ALIAS_CACHE_SECONDS = 300
PROVISIONS_PER_MAILBOX_HOUR = 10
RECONCILE_GRACE_SECONDS = 600

_NAME_UNSAFE = re.compile(r"[^\w .()\-]", re.UNICODE)
_QUEUE_ID = re.compile(r"^([0-9A-Za-z]{6,20}): (.*)$")
_MESSAGE_ID = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")


class BrokerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def app_password_name(client_name: str | None, today: str, tag: str) -> str:
    """``MCP: Claude (2026-10-01, a1b2)``: recognisable in mailcow, unique enough to match."""
    cleaned = " ".join(_NAME_UNSAFE.sub("", client_name or "").split())[:40] or "MCP client"
    return f"{NAME_PREFIX}{cleaned} ({today}, {tag})"


def generate_password(policy: dict[str, int]) -> str:
    """A random password satisfying mailcow's password policy (and then some)."""
    length = max(32, policy.get("length", 0))
    alphabet = string.ascii_letters + string.digits + "-_"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "-_" for c in password)
        ):
            return password


def parse_delivery(
    logs: list[dict[str, Any]], message_id: str, senders: set[str]
) -> list[dict[str, Any]]:
    """Per-recipient delivery status from Postfix log lines (any order).

    Only queue IDs whose message-id matches *and* whose from= is one of
    ``senders`` count, so a mailbox can't read about someone else's mail.
    """
    entries = []
    for row in logs:
        match = _QUEUE_ID.match(str(row.get("message", "")))
        if match:
            try:
                when = int(row.get("time", 0))
            except (TypeError, ValueError):
                when = 0
            entries.append((when, match.group(1), match.group(2)))
    entries.sort(key=lambda e: e[0])
    queue_ids = {qid for _, qid, text in entries if text.strip() == f"message-id={message_id}"}
    owned = set()
    for _, qid, text in entries:
        if qid in queue_ids and text.startswith("from=<"):
            sender = text[6:].split(">", 1)[0].lower()
            if sender in senders:
                owned.add(qid)
    recipients: dict[str, dict[str, Any]] = {}
    for when, qid, text in entries:
        if qid not in owned or not text.startswith("to=<"):
            continue
        fields, _, response = text.partition(" (")
        values = dict(part.split("=", 1) for part in fields.split(", ") if "=" in part)
        recipient = values.get("to", "").strip("<>").lower()
        status = values.get("status", "")
        if not recipient or not status:
            continue
        recipients[recipient] = {
            "recipient": recipient,
            "status": status,
            "dsn": values.get("dsn"),
            "relay": values.get("relay"),
            "response": response.rstrip(")") if response else None,
            "time": datetime.fromtimestamp(when, UTC).isoformat() if when else None,
            "queue_id": qid,
        }
    return sorted(recipients.values(), key=lambda r: str(r["recipient"]))


class Broker:
    def __init__(
        self,
        config: BrokerConfig,
        db: Database,
        api: MailcowApi,
        audit: AuditLog,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.db = db
        self.api = api
        self.audit = audit
        self.signer = CapabilitySigner(config.broker_signing_key)
        self._clock = clock
        self._lock = anyio.Lock()  # provisioning vs. reconcile
        self._aliases: dict[str, tuple[float, list[str]]] = {}
        self.provision_limit = RateLimiter(PROVISIONS_PER_MAILBOX_HOUR, 3600, clock=clock)
        self.operation_limit = RateLimiter(120, 60, clock=clock)

    # --- helpers -------------------------------------------------------------

    def now(self) -> int:
        return int(self._clock())

    def mailbox_of(self, token: Any, operation: str) -> Capability:
        try:
            capability = self.signer.verify(token)
        except InvalidCapability as exc:
            self.audit(operation, result="invalid_capability")
            raise BrokerError(403, "invalid_capability", "capability token is invalid") from exc
        row = self.db.one(
            "SELECT mailbox FROM app_passwords WHERE app_password_id = ? AND deprovisioned_at IS NULL",
            (capability.app_password_id,),
        )
        if row is None or row["mailbox"] != capability.mailbox:
            self.audit(operation, result="revoked_capability", mailbox=capability.mailbox)
            raise BrokerError(
                403, "revoked_capability", "this connection's app password was removed"
            )
        if not self.operation_limit.hit(capability.mailbox):
            raise BrokerError(429, "rate_limited", "too many requests for this mailbox")
        return capability

    async def owned_addresses(self, mailbox: str) -> set[str]:
        cached = self._aliases.get(mailbox)
        if cached and cached[0] > self._clock():
            aliases = cached[1]
        else:
            aliases = await self.api.aliases(mailbox)
            self._aliases[mailbox] = (self._clock() + ALIAS_CACHE_SECONDS, aliases)
        return {mailbox, *aliases}

    # --- operations ----------------------------------------------------------

    async def provision(self, body: dict[str, Any]) -> dict[str, Any]:
        token = body.get("mailcow_oauth_token")
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise BrokerError(400, "invalid_request", "mailcow_oauth_token is required")
        client_name = body.get("client_name")
        client_name = client_name if isinstance(client_name, str) else None
        try:
            # Ask mailcow who this is; never trust a username from the caller.
            mailbox = await self.api.profile_username(token)
        except TokenRejected as exc:
            self.audit("provision", result="token_rejected")
            raise BrokerError(403, "token_rejected", "mailcow did not accept the sign-in") from exc
        if not self.provision_limit.hit(mailbox):
            self.audit("provision", result="rate_limited", mailbox=mailbox)
            raise BrokerError(
                429, "rate_limited", "too many new connections for this mailbox, try again later"
            )
        today = datetime.fromtimestamp(self._clock(), UTC).strftime("%Y-%m-%d")
        name = app_password_name(client_name, today, secrets.token_hex(2))
        password = generate_password(await self.api.password_policy())
        async with self._lock:
            await self.api.add_app_password(mailbox, name, password)
            matches = [
                p["id"] for p in await self.api.app_passwords(mailbox) if p.get("name") == name
            ]
            if not matches:
                raise BrokerError(502, "mailcow_error", "the new app password could not be found")
            app_password_id = max(matches)
            self.db.execute(
                "INSERT INTO app_passwords (app_password_id, mailbox, name, created_at) VALUES (?, ?, ?, ?)",
                (app_password_id, mailbox, name, self.now()),
            )
        self.audit(
            "provision", mailbox=mailbox, client=client_name, app_password_id=app_password_id
        )
        return {
            "username": mailbox,
            "app_password_id": app_password_id,
            "app_password": password,
            "capability": self.signer.issue(mailbox, app_password_id, self._clock()),
        }

    async def _delete_app_password(self, mailbox: str, app_password_id: int) -> bool:
        """Delete it in mailcow if it's still there and ours; returns whether it was there."""
        existing = {p["id"]: p for p in await self.api.app_passwords(mailbox)}
        found = existing.get(app_password_id)
        if found is not None and str(found.get("name", "")).startswith(NAME_PREFIX):
            await self.api.delete_app_passwords([app_password_id])
        self.db.execute(
            "UPDATE app_passwords SET deprovisioned_at = ? WHERE app_password_id = ?",
            (self.now(), app_password_id),
        )
        return found is not None

    async def deprovision(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "deprovision")
        existed = await self._delete_app_password(capability.mailbox, capability.app_password_id)
        self.audit(
            "deprovision",
            mailbox=capability.mailbox,
            app_password_id=capability.app_password_id,
            existed=existed,
        )
        return {"deleted": existed}

    async def reconcile(self, body: dict[str, Any]) -> dict[str, Any]:
        tokens = body.get("capabilities")
        if not isinstance(tokens, list) or len(tokens) > 100_000:
            raise BrokerError(400, "invalid_request", "capabilities must be a list")
        live: set[int] = set()
        for token in tokens:
            try:
                live.add(self.signer.verify(token).app_password_id)
            except InvalidCapability:
                continue
        deleted = 0
        # The app may not have stored a just-provisioned capability yet.
        grace_until = self.now() - RECONCILE_GRACE_SECONDS
        async with self._lock:
            rows = self.db.all(
                "SELECT app_password_id, mailbox, created_at, deprovisioned_at FROM app_passwords"
            )
            keep = {
                r["app_password_id"]
                for r in rows
                if r["deprovisioned_at"] is None
                and (r["app_password_id"] in live or r["created_at"] > grace_until)
            }
            stale = [
                r
                for r in rows
                if r["deprovisioned_at"] is None and r["app_password_id"] not in keep
            ]
            for row in stale:
                if await self._delete_app_password(row["mailbox"], row["app_password_id"]):
                    deleted += 1
            # "MCP: " app passwords on known mailboxes that we have no live record of.
            for mailbox in sorted({r["mailbox"] for r in rows}):
                orphans = [
                    p["id"]
                    for p in await self.api.app_passwords(mailbox)
                    if str(p.get("name", "")).startswith(NAME_PREFIX) and p["id"] not in keep
                ]
                if orphans:
                    await self.api.delete_app_passwords(orphans)
                    deleted += len(orphans)
        self.audit("reconcile", live=len(live), deleted=deleted)
        return {"deleted": deleted}

    async def aliases(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "aliases")
        addresses = await self.owned_addresses(capability.mailbox)
        self.audit("aliases", mailbox=capability.mailbox, count=len(addresses) - 1)
        return {"mailbox": capability.mailbox, "aliases": sorted(addresses - {capability.mailbox})}

    @staticmethod
    def _quarantine_view(item: dict[str, Any]) -> dict[str, Any]:
        def number(value: Any) -> float | None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return None

        created = number(item.get("created"))
        return {
            "id": int(item["id"]),
            "sender": str(item.get("sender") or ""),
            "recipient": str(item.get("rcpt") or ""),
            "subject": str(item.get("subject") or ""),
            "score": number(item.get("score")),
            "action": str(item.get("action") or ""),
            "virus": bool(number(item.get("virus_flag"))),
            "created": datetime.fromtimestamp(created, UTC).isoformat() if created else None,
        }

    async def _owned_item(
        self, capability: Capability, item_id: Any, operation: str
    ) -> dict[str, Any]:
        if not isinstance(item_id, int) or isinstance(item_id, bool) or item_id <= 0:
            raise BrokerError(400, "invalid_request", "id must be a positive integer")
        item = await self.api.quarantine_item(item_id)
        owned = await self.owned_addresses(capability.mailbox)
        if item is None or str(item.get("rcpt", "")).lower() not in owned:
            self.audit(operation, result="not_found", mailbox=capability.mailbox, id=item_id)
            raise BrokerError(404, "not_found", "no such quarantine item for this mailbox")
        return item

    async def quarantine_list(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "quarantine_list")
        owned = await self.owned_addresses(capability.mailbox)
        items = [
            self._quarantine_view(i)
            for i in await self.api.quarantine()
            if str(i.get("rcpt", "")).lower() in owned and "id" in i
        ]
        items.sort(key=lambda i: i["created"] or "", reverse=True)
        self.audit("quarantine_list", mailbox=capability.mailbox, count=len(items))
        return {"items": items}

    async def quarantine_release(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "quarantine_release")
        item = await self._owned_item(capability, body.get("id"), "quarantine_release")
        await self.api.quarantine_release(int(item["id"]))
        self.audit("quarantine_release", mailbox=capability.mailbox, id=int(item["id"]))
        return {"released": int(item["id"])}

    async def quarantine_delete(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "quarantine_delete")
        item = await self._owned_item(capability, body.get("id"), "quarantine_delete")
        await self.api.quarantine_delete(int(item["id"]))
        self.audit("quarantine_delete", mailbox=capability.mailbox, id=int(item["id"]))
        return {"deleted": int(item["id"])}

    async def delivery_status(self, body: dict[str, Any]) -> dict[str, Any]:
        capability = self.mailbox_of(body.get("capability"), "delivery_status")
        message_id = body.get("message_id")
        if not isinstance(message_id, str) or not _MESSAGE_ID.match(message_id):
            raise BrokerError(400, "invalid_request", "message_id must look like <id@domain>")
        owned = await self.owned_addresses(capability.mailbox)
        recipients = parse_delivery(await self.api.postfix_logs(LOG_LINES), message_id, owned)
        self.audit("delivery_status", mailbox=capability.mailbox, count=len(recipients))
        return {"message_id": message_id, "recipients": recipients}


def create_broker_app(
    config: BrokerConfig,
    *,
    db: Database | None = None,
    api: MailcowApi | None = None,
    audit: AuditLog | None = None,
    clock: Callable[[], float] = time.time,
) -> Starlette:
    db = db if db is not None else Database.in_data_dir(config.data_dir)
    db.migrate(MIGRATIONS)
    api = api or MailcowApi(
        config.mailcow_api_url,
        config.mailcow_api_key,
        config.mailcow_oauth_profile_url,
        server_name=config.tls_server_name,
        verify=config.tls_verify,
        ca_file=config.tls_ca_file,
    )
    audit = audit if audit is not None else AuditLog(config.data_dir / "broker-audit.log")
    broker = Broker(config, db, api, audit, clock=clock)
    secret = config.broker_shared_secret.encode()
    operations: dict[str, Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]] = {
        "provision": broker.provision,
        "deprovision": broker.deprovision,
        "reconcile": broker.reconcile,
        "aliases": broker.aliases,
        "quarantine_list": broker.quarantine_list,
        "quarantine_release": broker.quarantine_release,
        "quarantine_delete": broker.quarantine_delete,
        "delivery_status": broker.delivery_status,
    }

    async def operation(request: Request) -> JSONResponse:
        provided = request.headers.get(SECRET_HEADER, "").encode()
        if not hmac.compare_digest(provided, secret):
            audit(
                "broker_auth",
                result="bad_secret",
                ip=request.client.host if request.client else None,
            )
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        handler = operations.get(request.path_params["name"])
        if handler is None:
            return JSONResponse({"error": "unknown_operation"}, status_code=404)
        body_bytes = await request.body()
        if len(body_bytes) > MAX_BODY_BYTES:
            return JSONResponse({"error": "too_large"}, status_code=413)
        try:
            body = await request.json() if body_bytes else {}
        except ValueError:
            return JSONResponse(
                {"error": "invalid_request", "message": "body must be JSON"}, status_code=400
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "invalid_request", "message": "body must be an object"}, status_code=400
            )
        try:
            return JSONResponse(await handler(body))
        except BrokerError as exc:
            return JSONResponse({"error": exc.code, "message": exc.message}, status_code=exc.status)
        except MailcowUnavailable as exc:
            return JSONResponse(
                {"error": "mailcow_unavailable", "message": str(exc)}, status_code=503
            )
        except MailcowError as exc:
            return JSONResponse({"error": "mailcow_error", "message": str(exc)}, status_code=502)

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "role": "broker", "version": __version__})

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        yield
        await api.aclose()

    app = Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/v1/{name}", operation, methods=["POST"]),
        ],
        lifespan=lifespan,
    )
    app.state.broker = broker
    return app
