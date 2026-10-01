"""OAuth 2.1 authorization server for MCP clients, backed by SQLite.

The MCP SDK handles the HTTP side (metadata, /authorize validation, /token with
PKCE, /register, /revoke). This provider stores clients, sign-in requests,
grants, authorization codes and tokens. Codes and tokens are stored as hashes.

A *grant* is one client's access to one mailbox, created when the user signs in.
Codes and tokens belong to a grant; revoking any token deletes the whole grant,
and reusing a rotated refresh token or a spent code revokes it too.
"""

from __future__ import annotations

import contextvars
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

from mailcow_mcp.audit import AuditLog
from mailcow_mcp.crypto import Box, hash_secret, new_secret
from mailcow_mcp.db import Database

ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 86400  # sliding: each rotation starts a new period
AUTH_CODE_TTL = 300
AUTH_REQUEST_TTL = 900
UNUSED_CLIENT_TTL = 86400
MAX_PENDING_CLIENTS = 1000
MAX_REDIRECT_URIS = 10
MAX_CLIENT_METADATA_BYTES = 16 * 1024
MAX_CLIENT_NAME_LENGTH = 80
_LAST_USED_RESOLUTION = 60

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]")

# The client IP of the current HTTP request, set by the app's middleware.
client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("client_ip", default=None)


class MailboxAccessToken(AccessToken):
    grant_id: int


class GrantAuthorizationCode(AuthorizationCode):
    grant_id: int


class GrantRefreshToken(RefreshToken):
    grant_id: int


@dataclass(frozen=True)
class PendingAuthorization:
    """A validated /authorize request waiting for the user to sign in."""

    request_id: str
    client: OAuthClientInformationFull
    params: AuthorizationParams
    csrf: str
    id_hash: str | None = None  # when loaded by mailcow state (the request id isn't known)
    resume: str | None = None  # that state: lets the page's form continue this request

    @property
    def key(self) -> str:
        return self.id_hash or hash_secret(self.request_id)

    @property
    def client_name(self) -> str | None:
        return self.client.client_name

    @property
    def redirect_uri(self) -> str:
        return str(self.params.redirect_uri)


def _loopback_matches(requested: str, registered: str) -> bool:
    """RFC 8252 §7.3: for loopback redirect URIs, any port matches."""
    a, b = urlsplit(requested), urlsplit(registered)
    return (
        a.scheme == b.scheme == "http"
        and a.hostname in LOOPBACK_HOSTS
        and a.hostname == b.hostname
        and a.path == b.path
        and a.query == b.query
    )


class RegisteredClient(OAuthClientInformationFull):
    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None and self.redirect_uris:
            requested = str(redirect_uri)
            if any(_loopback_matches(requested, str(uri)) for uri in self.redirect_uris):
                return redirect_uri
        return super().validate_redirect_uri(redirect_uri)


def is_allowed_redirect_uri(uri: str) -> bool:
    """Any https:// URI, or http:// on a loopback address (any port)."""
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError:
        return False
    if parts.fragment or parts.username or parts.password or not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def clean_client_name(name: str | None) -> str | None:
    """Strip control and bidi characters; collapse whitespace; cap the length."""
    if not name:
        return None
    spaced = " ".join(name.split())  # tabs and newlines become spaces
    cleaned = " ".join(_CONTROL_CHARS.sub("", spaced).split())[:MAX_CLIENT_NAME_LENGTH]
    return cleaned or None


def canonical_url(url: str) -> str:
    parts = urlsplit(url)
    netloc = (parts.hostname or "").lower()
    if parts.port is not None and parts.port != {"https": 443, "http": 80}.get(parts.scheme):
        netloc += f":{parts.port}"
    return f"{parts.scheme.lower()}://{netloc}{parts.path.rstrip('/')}"


class Provider(
    OAuthAuthorizationServerProvider[GrantAuthorizationCode, GrantRefreshToken, MailboxAccessToken]
):
    def __init__(
        self,
        db: Database,
        box: Box,
        *,
        issuer_url: str,
        resource_url: str,
        login_url: str,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db = db
        self.box = box
        self.issuer_url = issuer_url
        self.resource_url = resource_url
        self.login_url = login_url
        self.audit = audit
        self._clock = clock

    def now(self) -> int:
        return int(self._clock())

    # --- clients -------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = self.db.one(
            "SELECT metadata, client_secret_enc FROM clients WHERE client_id = ?", (client_id,)
        )
        if row is None:
            return None
        data = json.loads(row["metadata"])
        if row["client_secret_enc"]:
            data["client_secret"] = self.box.decrypt(row["client_secret_enc"])
        return RegisteredClient.model_validate(data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(uri) for uri in client_info.redirect_uris or []]
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError(
                "invalid_redirect_uri", f"register between 1 and {MAX_REDIRECT_URIS} redirect URIs"
            )
        for uri in uris:
            if not is_allowed_redirect_uri(uri):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "redirect URIs must use https://, or http:// on 127.0.0.1, localhost or [::1]",
                )
        name = clean_client_name(client_info.client_name)
        info = client_info.model_copy(update={"client_name": name})
        metadata = info.model_dump(mode="json", exclude_none=True, exclude={"client_secret"})
        encoded = json.dumps(metadata, separators=(",", ":"))
        if len(encoded) > MAX_CLIENT_METADATA_BYTES:
            raise RegistrationError("invalid_client_metadata", "client metadata is too large")

        pending = self.db.one(
            "SELECT count(*) AS n FROM clients c"
            " WHERE NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = c.client_id)"
        )
        if pending is not None and pending["n"] >= MAX_PENDING_CLIENTS:
            self.audit("client_register", result="rejected_too_many", ip=client_ip.get())
            raise RegistrationError(
                "invalid_client_metadata", "too many pending registrations, try again later"
            )
        now = self.now()
        secret_enc = self.box.encrypt(info.client_secret) if info.client_secret else None
        self.db.execute(
            "INSERT INTO clients (client_id, client_name, metadata, client_secret_enc,"
            " registered_ip, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (info.client_id, name, encoded, secret_enc, client_ip.get(), now, now),
        )
        self.audit("client_register", client=name, client_id=info.client_id, ip=client_ip.get())

    # --- sign-in -------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource is not None and canonical_url(params.resource) != canonical_url(
            self.resource_url
        ):
            raise AuthorizeError(
                "invalid_target", f"this server only issues tokens for {self.resource_url}"
            )
        request_id = new_secret()
        self.db.execute(
            "INSERT INTO auth_requests (id_hash, client_id, params, csrf, expires_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                hash_secret(request_id),
                client.client_id,
                params.model_dump_json(),
                new_secret(),
                self.now() + AUTH_REQUEST_TTL,
            ),
        )
        return construct_redirect_uri(self.login_url, request=request_id)

    async def load_pending(self, request_id: str) -> PendingAuthorization | None:
        row = self.db.one(
            "SELECT client_id, params, csrf FROM auth_requests WHERE id_hash = ? AND expires_at > ?",
            (hash_secret(request_id), self.now()),
        )
        if row is None:
            return None
        client = await self.get_client(row["client_id"])
        if client is None:
            return None
        return PendingAuthorization(
            request_id=request_id,
            client=client,
            params=AuthorizationParams.model_validate_json(row["params"]),
            csrf=row["csrf"],
        )

    def set_mailcow_state(self, pending: PendingAuthorization, state: str) -> None:
        """Remember the OAuth state sent to mailcow for this sign-in request."""
        self.db.execute(
            "UPDATE auth_requests SET mailcow_state_hash = ? WHERE id_hash = ?",
            (hash_secret(state), pending.key),
        )

    async def load_pending_by_state(self, state: str) -> PendingAuthorization | None:
        row = self.db.one(
            "SELECT id_hash, client_id, params, csrf FROM auth_requests"
            " WHERE mailcow_state_hash = ? AND expires_at > ?",
            (hash_secret(state), self.now()),
        )
        if row is None:
            return None
        client = await self.get_client(row["client_id"])
        if client is None:
            return None
        return PendingAuthorization(
            request_id="",
            client=client,
            params=AuthorizationParams.model_validate_json(row["params"]),
            csrf=row["csrf"],
            id_hash=row["id_hash"],
            resume=state,
        )

    def _take_pending(self, pending: PendingAuthorization) -> bool:
        """Consume the sign-in request; False if it was already used."""
        cursor = self.db.execute("DELETE FROM auth_requests WHERE id_hash = ?", (pending.key,))
        return cursor.rowcount == 1

    def deny(self, pending: PendingAuthorization) -> str:
        """Cancel the sign-in; returns the client redirect carrying ``access_denied``."""
        self._take_pending(pending)
        self.audit("login", result="denied", client=pending.client_name, ip=client_ip.get())
        return construct_redirect_uri(
            pending.redirect_uri,
            error="access_denied",
            error_description="The user cancelled the sign-in.",
            state=pending.params.state,
            iss=self.issuer_url,
        )

    def complete(
        self,
        pending: PendingAuthorization,
        *,
        username: str,
        credential: str,
        login_method: str,
        app_password_id: int | None = None,
        capability: str | None = None,
    ) -> str | None:
        """Create the grant and an authorization code; returns the client redirect.

        None if the sign-in request was used meanwhile (double submit).
        """
        now = self.now()
        code = new_secret()
        with self.db.transaction() as conn:
            if not self._take_pending(pending):
                return None
            conn.execute(
                "INSERT INTO mailboxes (username, created_at, last_login_at) VALUES (?, ?, ?)"
                " ON CONFLICT (username) DO UPDATE SET last_login_at = excluded.last_login_at",
                (username, now, now),
            )
            mailbox = conn.execute(
                "SELECT id FROM mailboxes WHERE username = ?", (username,)
            ).fetchone()
            grant_id = conn.execute(
                "INSERT INTO grants (client_id, mailbox_id, login_method, credential_enc, scopes,"
                " resource, created_at, last_used_at, app_password_id, capability_enc)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pending.client.client_id,
                    mailbox["id"],
                    login_method,
                    self.box.encrypt(credential),
                    " ".join(pending.params.scopes or []),
                    self.resource_url,
                    now,
                    now,
                    app_password_id,
                    self.box.encrypt(capability) if capability else None,
                ),
            ).lastrowid
            conn.execute(
                "INSERT INTO auth_codes (code_hash, grant_id, code_challenge, redirect_uri,"
                " redirect_uri_explicit, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    hash_secret(code),
                    grant_id,
                    pending.params.code_challenge,
                    pending.redirect_uri,
                    int(pending.params.redirect_uri_provided_explicitly),
                    now + AUTH_CODE_TTL,
                ),
            )
            conn.execute(
                "UPDATE clients SET last_used_at = ? WHERE client_id = ?",
                (now, pending.client.client_id),
            )
        self.audit(
            "login",
            mailbox=username,
            client=pending.client_name,
            method=login_method,
            ip=client_ip.get(),
        )
        return construct_redirect_uri(
            pending.redirect_uri, code=code, state=pending.params.state, iss=self.issuer_url
        )

    # --- authorization codes -------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> GrantAuthorizationCode | None:
        row = self.db.one(
            "SELECT a.*, g.client_id, g.scopes, g.resource, m.username FROM auth_codes a"
            " JOIN grants g ON g.id = a.grant_id JOIN mailboxes m ON m.id = g.mailbox_id"
            " WHERE a.code_hash = ? AND g.client_id = ?",
            (hash_secret(authorization_code), client.client_id),
        )
        if row is None:
            return None
        if row["used_at"] is not None:
            # RFC 6749 §4.1.2: a code used twice revokes the tokens issued from it.
            self.revoke_grant(row["grant_id"], reason="code_reuse")
            return None
        if row["expires_at"] <= self.now():
            return None
        return GrantAuthorizationCode(
            code=authorization_code,
            scopes=row["scopes"].split(),
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
            subject=row["username"],
            grant_id=row["grant_id"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: GrantAuthorizationCode
    ) -> OAuthToken:
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL",
                (self.now(), hash_secret(authorization_code.code)),
            )
            if cursor.rowcount != 1:
                raise TokenError("invalid_grant", "authorization code was already used")
            return self._issue_tokens(authorization_code.grant_id, authorization_code.scopes)

    # --- tokens --------------------------------------------------------------

    def _issue_tokens(self, grant_id: int, scopes: list[str]) -> OAuthToken:
        now = self.now()
        access, refresh = new_secret("mcp_at_"), new_secret("mcp_rt_")
        self.db.execute(
            "INSERT INTO tokens (token_hash, grant_id, kind, expires_at) VALUES"
            " (?, ?, 'access', ?), (?, ?, 'refresh', ?)",
            (
                hash_secret(access),
                grant_id,
                now + ACCESS_TOKEN_TTL,
                hash_secret(refresh),
                grant_id,
                now + REFRESH_TOKEN_TTL,
            ),
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",  # noqa: S106 - not a password
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh,
            scope=" ".join(scopes) or None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> GrantRefreshToken | None:
        row = self.db.one(
            "SELECT t.*, g.client_id, g.scopes, g.resource, m.username FROM tokens t"
            " JOIN grants g ON g.id = t.grant_id JOIN mailboxes m ON m.id = g.mailbox_id"
            " WHERE t.token_hash = ? AND t.kind = 'refresh' AND g.client_id = ?",
            (hash_secret(refresh_token), client.client_id),
        )
        if row is None:
            return None
        if row["used_at"] is not None:
            # OAuth 2.1 §4.3.1: a rotated refresh token used again means it leaked.
            self.revoke_grant(row["grant_id"], reason="refresh_token_reuse")
            return None
        if row["expires_at"] <= self.now():
            return None
        return GrantRefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["username"],
            grant_id=row["grant_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: GrantRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "UPDATE tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
                (self.now(), hash_secret(refresh_token.token)),
            )
            if cursor.rowcount != 1:
                raise TokenError("invalid_grant", "refresh token was already used")
            # Old access tokens stay valid until they expire (at most an hour).
            return self._issue_tokens(refresh_token.grant_id, scopes)

    async def load_access_token(self, token: str) -> MailboxAccessToken | None:
        now = self.now()
        row = self.db.one(
            "SELECT t.grant_id, t.expires_at, g.client_id, g.scopes, g.resource, g.last_used_at,"
            " m.username FROM tokens t"
            " JOIN grants g ON g.id = t.grant_id JOIN mailboxes m ON m.id = g.mailbox_id"
            " WHERE t.token_hash = ? AND t.kind = 'access' AND t.expires_at > ?",
            (hash_secret(token), now),
        )
        if row is None:
            return None
        if row["last_used_at"] < now - _LAST_USED_RESOLUTION:
            self.db.execute(
                "UPDATE grants SET last_used_at = ? WHERE id = ?", (now, row["grant_id"])
            )
        return MailboxAccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["username"],
            grant_id=row["grant_id"],
        )

    async def revoke_token(self, token: MailboxAccessToken | GrantRefreshToken) -> None:
        self.revoke_grant(token.grant_id, reason="revoked")

    # --- grants and cleanup --------------------------------------------------

    def _grant_info(self, grant_id: int) -> tuple[str | None, str | None]:
        row = self.db.one(
            "SELECT m.username, c.client_name FROM grants g JOIN mailboxes m ON m.id = g.mailbox_id"
            " JOIN clients c ON c.client_id = g.client_id WHERE g.id = ?",
            (grant_id,),
        )
        return (row["username"], row["client_name"]) if row else (None, None)

    def revoke_grant(self, grant_id: int, *, reason: str) -> None:
        """End a grant. A mailcow app password is queued for deletion via the broker."""
        mailbox, client = self._grant_info(grant_id)
        if mailbox is None:
            return
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO deprovision_queue (mailbox, capability_enc, queued_at)"
                " SELECT ?, capability_enc, ? FROM grants WHERE id = ? AND capability_enc IS NOT NULL",
                (mailbox, self.now(), grant_id),
            )
            conn.execute("DELETE FROM grants WHERE id = ?", (grant_id,))
        self.audit(
            "grant_revoke",
            result="ok" if reason == "revoked" else reason,
            mailbox=mailbox,
            client=client,
            ip=client_ip.get(),
        )

    def revoke_mailbox(self, username: str) -> int:
        """Revoke every grant of a mailbox; returns how many there were."""
        rows = self.db.all(
            "SELECT g.id FROM grants g JOIN mailboxes m ON m.id = g.mailbox_id WHERE m.username = ?",
            (username,),
        )
        for row in rows:
            self.revoke_grant(row["id"], reason="revoked")
        self.db.execute("DELETE FROM mailboxes WHERE username = ?", (username,))
        return len(rows)

    def capability_of(self, grant_id: int) -> str | None:
        row = self.db.one("SELECT capability_enc FROM grants WHERE id = ?", (grant_id,))
        return self.box.decrypt(row["capability_enc"]) if row and row["capability_enc"] else None

    def live_capabilities(self) -> list[str]:
        rows = self.db.all("SELECT capability_enc FROM grants WHERE capability_enc IS NOT NULL")
        return [self.box.decrypt(r["capability_enc"]) for r in rows]

    def pending_deprovisions(self, limit: int = 50) -> list[tuple[int, str, str]]:
        rows = self.db.all(
            "SELECT id, mailbox, capability_enc FROM deprovision_queue ORDER BY id LIMIT ?",
            (limit,),
        )
        return [(r["id"], r["mailbox"], self.box.decrypt(r["capability_enc"])) for r in rows]

    def deprovisioned(self, queue_id: int) -> None:
        self.db.execute("DELETE FROM deprovision_queue WHERE id = ?", (queue_id,))

    def deprovision_failed(self, queue_id: int, error: str) -> None:
        self.db.execute(
            "UPDATE deprovision_queue SET attempts = attempts + 1, last_error = ? WHERE id = ?",
            (error[:500], queue_id),
        )

    def purge_expired(self) -> dict[str, int]:
        """Delete expired data. Grants with no live code or token end here."""
        now = self.now()
        counts: dict[str, int] = {}
        with self.db.transaction() as conn:
            counts["auth_requests"] = conn.execute(
                "DELETE FROM auth_requests WHERE expires_at <= ?", (now,)
            ).rowcount
            counts["auth_codes"] = conn.execute(
                "DELETE FROM auth_codes WHERE expires_at <= ?", (now,)
            ).rowcount
            counts["tokens"] = conn.execute(
                "DELETE FROM tokens WHERE expires_at <= ?", (now,)
            ).rowcount
        ended = self.db.all(
            "SELECT g.id FROM grants g"
            " WHERE NOT EXISTS (SELECT 1 FROM tokens t WHERE t.grant_id = g.id AND t.used_at IS NULL)"
            " AND NOT EXISTS (SELECT 1 FROM auth_codes a WHERE a.grant_id = g.id AND a.used_at IS NULL)"
        )
        for row in ended:
            self.revoke_grant(row["id"], reason="expired")
        counts["grants"] = len(ended)
        with self.db.transaction() as conn:
            counts["clients"] = conn.execute(
                "DELETE FROM clients WHERE last_used_at <= ? AND NOT EXISTS"
                " (SELECT 1 FROM grants g WHERE g.client_id = clients.client_id)",
                (now - UNUSED_CLIENT_TTL,),
            ).rowcount
            counts["mailboxes"] = conn.execute(
                "DELETE FROM mailboxes WHERE NOT EXISTS"
                " (SELECT 1 FROM grants g WHERE g.mailbox_id = mailboxes.id)"
            ).rowcount
        return counts
