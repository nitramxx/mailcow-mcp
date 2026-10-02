"""OAuth 2.1 authorization server for MCP clients, backed by SQLite.

The MCP SDK handles the HTTP side (metadata, /authorize validation, /token with
PKCE, /register, /revoke). This provider stores clients, sign-in requests,
grants, authorization codes and tokens. Codes and tokens are stored as hashes.

A *grant* is one client's access to one mailbox, created when the user signs in.
Codes and tokens belong to a grant; revoking any token deletes the whole grant,
and reusing a rotated refresh token or a spent code revokes it too.
"""

from __future__ import annotations

import enum
import json
import logging
import sqlite3
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
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
from mailcow_mcp.request_context import client_ip

log = logging.getLogger(__name__)

ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 86400  # sliding: each rotation starts a new period
AUTH_CODE_TTL = 300
AUTH_REQUEST_TTL = 900
UNUSED_CLIENT_TTL = 86400
MAX_PENDING_CLIENTS = 1000
MAX_REDIRECT_URIS = 10
MAX_CLIENT_METADATA_BYTES = 16 * 1024
MAX_CLIENT_NAME_LENGTH = 80
MAX_MAILBOXES_PER_GRANT = 10
CONNECT_REQUEST_TTL = 900  # an add_mailbox link
CONNECT_PATH = "/connect"  # where that link points
_LAST_USED_RESOLUTION = 60

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
# Control, format (zero-width, bidi overrides), separator, private-use and surrogate
# characters: invisible or misleading in a client name shown on the consent page.
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs"})


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


@dataclass(frozen=True)
class ConnectedMailbox:
    """One mailbox of a connection, with what's needed to act for it."""

    username: str
    credential: str  # password or app password
    login_method: str  # "password" or "mailcow"
    capability: str | None  # the broker's token for its app password (mailcow sign-in)


@dataclass(frozen=True)
class PendingConnect:
    """An add_mailbox link waiting for the user to sign in another mailbox."""

    grant_id: int
    id_hash: str
    csrf: str
    client_name: str | None
    mailboxes: list[str]  # already connected
    code: str = ""  # when loaded by the link's code
    resume: str | None = None  # when loaded by mailcow state: lets the page's form continue


class AddResult(enum.Enum):
    ADDED = "added"
    ALREADY_CONNECTED = "already_connected"
    FULL = "full"
    GONE = "gone"  # the connection ended meanwhile


def _loopback_matches(requested: str, registered: str) -> bool:
    """RFC 8252 §7.3: for loopback redirect URIs, any port matches."""
    a, b = urlsplit(requested), urlsplit(registered)
    return (
        not (a.fragment or a.username or a.password)
        and a.scheme == b.scheme == "http"
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
    visible = "".join(c for c in spaced if unicodedata.category(c) not in _HIDDEN_CATEGORIES)
    cleaned = " ".join(visible.split())[:MAX_CLIENT_NAME_LENGTH]
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
        client_info.client_name = name  # the registration response shows the cleaned name
        info = client_info.model_copy()
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
        if params.resource is not None and not self._is_our_resource(params.resource):
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

    def _is_our_resource(self, resource: str) -> bool:
        try:
            return canonical_url(resource) == canonical_url(self.resource_url)
        except ValueError:  # e.g. an invalid port
            return False

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
            grant_id = conn.execute(
                "INSERT INTO grants (client_id, scopes, resource, created_at, last_used_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    pending.client.client_id,
                    " ".join(pending.params.scopes or []),
                    self.resource_url,
                    now,
                    now,
                ),
            ).lastrowid
            assert grant_id is not None  # noqa: S101 - an INSERT always has one
            self._attach(
                conn, grant_id, username, credential, login_method, app_password_id, capability
            )
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
            "SELECT a.*, g.client_id, g.scopes, g.resource"
            " FROM auth_codes a JOIN grants g ON g.id = a.grant_id"
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
            subject=self._subject(row["grant_id"]),
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
        self._client_used(grant_id, now)
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
            "SELECT t.*, g.client_id, g.scopes, g.resource"
            " FROM tokens t JOIN grants g ON g.id = t.grant_id"
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
            subject=self._subject(row["grant_id"]),
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
            "SELECT t.grant_id, t.expires_at, g.client_id, g.scopes, g.resource, g.last_used_at"
            " FROM tokens t JOIN grants g ON g.id = t.grant_id"
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
            subject=self._subject(row["grant_id"]),
            grant_id=row["grant_id"],
        )

    async def revoke_token(self, token: MailboxAccessToken | GrantRefreshToken) -> None:
        self.revoke_grant(token.grant_id, reason="revoked")

    def grant_of_token(self, token: str, client_id: str) -> int | None:
        """The grant a token (access or refresh, current or rotated) belongs to, for
        revocation: without the side effects of loading it for use."""
        row = self.db.one(
            "SELECT t.grant_id FROM tokens t JOIN grants g ON g.id = t.grant_id"
            " WHERE t.token_hash = ? AND g.client_id = ?",
            (hash_secret(token), client_id),
        )
        return int(row["grant_id"]) if row else None

    def _client_used(self, grant_id: int, now: int) -> None:
        # Keeps a client registration alive while it refreshes, and for a day after its
        # last connection ends (so a reconnect with the same client_id still works).
        self.db.execute(
            "UPDATE clients SET last_used_at = ?"
            " WHERE client_id = (SELECT client_id FROM grants WHERE id = ?)",
            (now, grant_id),
        )

    # --- grants and cleanup --------------------------------------------------

    def _subject(self, grant_id: int) -> str | None:
        """The grant's first mailbox: the token's subject."""
        usernames = self.usernames_of(grant_id)
        return usernames[0] if usernames else None

    def client_name_of(self, grant_id: int) -> str | None:
        row = self.db.one(
            "SELECT c.client_name FROM grants g JOIN clients c ON c.client_id = g.client_id"
            " WHERE g.id = ?",
            (grant_id,),
        )
        return row["client_name"] if row else None

    def usernames_of(self, grant_id: int) -> list[str]:
        """The grant's mailboxes, in the order they were connected."""
        rows = self.db.all(
            "SELECT m.username FROM grant_mailboxes gm JOIN mailboxes m ON m.id = gm.mailbox_id"
            " WHERE gm.grant_id = ? ORDER BY gm.added_at, gm.id",
            (grant_id,),
        )
        return [r["username"] for r in rows]

    def connected(self, grant_id: int) -> list[ConnectedMailbox]:
        """The grant's mailboxes with their credentials, in the order they were connected."""
        rows = self.db.all(
            "SELECT m.username, gm.credential_enc, gm.login_method, gm.capability_enc"
            " FROM grant_mailboxes gm JOIN mailboxes m ON m.id = gm.mailbox_id"
            " WHERE gm.grant_id = ? ORDER BY gm.added_at, gm.id",
            (grant_id,),
        )
        return [
            ConnectedMailbox(
                username=r["username"],
                credential=self.box.decrypt(r["credential_enc"]),
                login_method=r["login_method"],
                capability=self.box.decrypt(r["capability_enc"]) if r["capability_enc"] else None,
            )
            for r in rows
        ]

    def _attach(
        self,
        conn: sqlite3.Connection,
        grant_id: int,
        username: str,
        credential: str,
        login_method: str,
        app_password_id: int | None,
        capability: str | None,
    ) -> None:
        now = self.now()
        conn.execute(
            "INSERT INTO mailboxes (username, created_at, last_login_at) VALUES (?, ?, ?)"
            " ON CONFLICT (username) DO UPDATE SET last_login_at = excluded.last_login_at",
            (username, now, now),
        )
        mailbox = conn.execute(
            "SELECT id FROM mailboxes WHERE username = ?", (username,)
        ).fetchone()
        conn.execute(
            "INSERT INTO grant_mailboxes (grant_id, mailbox_id, login_method, credential_enc,"
            " app_password_id, capability_enc, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                grant_id,
                mailbox["id"],
                login_method,
                self.box.encrypt(credential),
                app_password_id,
                self.box.encrypt(capability) if capability else None,
                now,
            ),
        )

    def add_mailbox(
        self,
        pending: PendingConnect,
        *,
        username: str,
        credential: str,
        login_method: str,
        app_password_id: int | None = None,
        capability: str | None = None,
    ) -> AddResult:
        """Connect another mailbox to the grant of an add_mailbox link (used up by this)."""
        with self.db.transaction() as conn:
            taken = conn.execute(
                "DELETE FROM connect_requests WHERE id_hash = ?", (pending.id_hash,)
            ).rowcount
            exists = conn.execute(
                "SELECT 1 FROM grants WHERE id = ?", (pending.grant_id,)
            ).fetchone()
            if not taken or exists is None:
                return AddResult.GONE
            current = [
                r["username"]
                for r in conn.execute(
                    "SELECT m.username FROM grant_mailboxes gm"
                    " JOIN mailboxes m ON m.id = gm.mailbox_id WHERE gm.grant_id = ?",
                    (pending.grant_id,),
                )
            ]
            if username in current:
                return AddResult.ALREADY_CONNECTED
            if len(current) >= MAX_MAILBOXES_PER_GRANT:
                return AddResult.FULL
            self._attach(
                conn,
                pending.grant_id,
                username,
                credential,
                login_method,
                app_password_id,
                capability,
            )
        self.audit(
            "mailbox_add",
            mailbox=username,
            client=pending.client_name,
            method=login_method,
            ip=client_ip.get(),
        )
        return AddResult.ADDED

    def remove_mailbox(self, grant_id: int, username: str, *, reason: str) -> bool:
        """Take one mailbox out of a grant (its app password is deleted via the broker).

        Removing the last one ends the grant. Returns whether the mailbox was connected.
        """
        if self.usernames_of(grant_id) == [username]:
            self.revoke_grant(grant_id, reason=reason)
            return True
        client = self.client_name_of(grant_id)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO deprovision_queue (mailbox, capability_enc, queued_at)"
                " SELECT ?, gm.capability_enc, ? FROM grant_mailboxes gm"
                " JOIN mailboxes m ON m.id = gm.mailbox_id"
                " WHERE gm.grant_id = ? AND m.username = ? AND gm.capability_enc IS NOT NULL",
                (username, self.now(), grant_id, username),
            )
            removed = conn.execute(
                "DELETE FROM grant_mailboxes WHERE grant_id = ? AND mailbox_id ="
                " (SELECT id FROM mailboxes WHERE username = ?)",
                (grant_id, username),
            ).rowcount
        if removed:
            self.audit(
                "mailbox_remove",
                result="ok" if reason == "revoked" else reason,
                mailbox=username,
                client=client,
                ip=client_ip.get(),
            )
        return bool(removed)

    def revoke_grant(self, grant_id: int, *, reason: str) -> None:
        """End a grant. Its mailcow app passwords are queued for deletion via the broker."""
        usernames = self.usernames_of(grant_id)
        client = self.client_name_of(grant_id)
        if not usernames and client is None:
            return
        self._client_used(grant_id, self.now())
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO deprovision_queue (mailbox, capability_enc, queued_at)"
                " SELECT m.username, gm.capability_enc, ? FROM grant_mailboxes gm"
                " JOIN mailboxes m ON m.id = gm.mailbox_id"
                " WHERE gm.grant_id = ? AND gm.capability_enc IS NOT NULL",
                (self.now(), grant_id),
            )
            conn.execute("DELETE FROM grants WHERE id = ?", (grant_id,))
        self.audit(
            "grant_revoke",
            result="ok" if reason == "revoked" else reason,
            mailbox=", ".join(usernames) or None,
            client=client,
            ip=client_ip.get(),
        )

    def revoke_mailbox(self, username: str) -> int:
        """Disconnect a mailbox from every grant (ending those it was the last one of);
        returns how many grants it was in."""
        rows = self.db.all(
            "SELECT gm.grant_id FROM grant_mailboxes gm JOIN mailboxes m ON m.id = gm.mailbox_id"
            " WHERE m.username = ?",
            (username,),
        )
        for row in rows:
            self.remove_mailbox(row["grant_id"], username, reason="revoked")
        self.db.execute("DELETE FROM mailboxes WHERE username = ?", (username,))
        return len(rows)

    def mailboxes(self) -> list[str]:
        """Every mailbox with a connection (or one that just ended)."""
        return [r["username"] for r in self.db.all("SELECT username FROM mailboxes")]

    # --- add_mailbox links ---------------------------------------------------

    def create_connect_request(self, grant_id: int) -> str:
        """A one-time code for the add_mailbox link of this grant (earlier links stop working)."""
        code = new_secret()
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM connect_requests WHERE grant_id = ?", (grant_id,))
            conn.execute(
                "INSERT INTO connect_requests (id_hash, grant_id, csrf, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (hash_secret(code), grant_id, new_secret(), self.now() + CONNECT_REQUEST_TTL),
            )
        return code

    def _pending_connect(
        self, row: sqlite3.Row | None, *, code: str = "", resume: str | None = None
    ) -> PendingConnect | None:
        if row is None:
            return None
        return PendingConnect(
            grant_id=row["grant_id"],
            id_hash=row["id_hash"],
            csrf=row["csrf"],
            client_name=self.client_name_of(row["grant_id"]),
            mailboxes=self.usernames_of(row["grant_id"]),
            code=code,
            resume=resume,
        )

    def load_connect(self, code: str) -> PendingConnect | None:
        return self._pending_connect(
            self.db.one(
                "SELECT id_hash, grant_id, csrf FROM connect_requests"
                " WHERE id_hash = ? AND expires_at > ?",
                (hash_secret(code), self.now()),
            ),
            code=code,
        )

    def load_connect_by_state(self, state: str) -> PendingConnect | None:
        return self._pending_connect(
            self.db.one(
                "SELECT id_hash, grant_id, csrf FROM connect_requests"
                " WHERE mailcow_state_hash = ? AND expires_at > ?",
                (hash_secret(state), self.now()),
            ),
            resume=state,
        )

    def set_connect_state(self, pending: PendingConnect, state: str) -> None:
        self.db.execute(
            "UPDATE connect_requests SET mailcow_state_hash = ? WHERE id_hash = ?",
            (hash_secret(state), pending.id_hash),
        )

    def cancel_connect(self, pending: PendingConnect) -> None:
        self.db.execute("DELETE FROM connect_requests WHERE id_hash = ?", (pending.id_hash,))

    def _decrypt_or_none(self, ciphertext: str) -> str | None:
        try:
            return self.box.decrypt(ciphertext)
        except InvalidToken:
            return None

    def live_capabilities(self) -> list[str]:
        """Capabilities of active grants (unreadable ones, e.g. after an ENC_KEY change, are
        left out: those grants can't be used anyway)."""
        rows = self.db.all(
            "SELECT capability_enc FROM grant_mailboxes WHERE capability_enc IS NOT NULL"
        )
        found = [self._decrypt_or_none(r["capability_enc"]) for r in rows]
        if None in found:
            log.warning(
                "%d stored capabilities can't be decrypted (ENC_KEY changed?)", found.count(None)
            )
        return [c for c in found if c is not None]

    def pending_deprovisions(self, limit: int = 50) -> list[tuple[int, str, str]]:
        """The queue, items that failed least often first (so failing ones don't block)."""
        rows = self.db.all(
            "SELECT id, mailbox, capability_enc FROM deprovision_queue"
            " ORDER BY attempts, id LIMIT ?",
            (limit,),
        )
        result = []
        for row in rows:
            capability = self._decrypt_or_none(row["capability_enc"])
            if capability is None:
                log.warning("dropping an unreadable deprovisioning item; reconcile will clean up")
                self.mark_deprovisioned(row["id"])
            else:
                result.append((row["id"], row["mailbox"], capability))
        return result

    def mark_deprovisioned(self, queue_id: int) -> None:
        self.db.execute("DELETE FROM deprovision_queue WHERE id = ?", (queue_id,))

    def deprovision_failed(self, queue_id: int, error: str) -> int:
        """Record a failed attempt; returns the number of attempts so far."""
        self.db.execute(
            "UPDATE deprovision_queue SET attempts = attempts + 1, last_error = ? WHERE id = ?",
            (error[:500], queue_id),
        )
        row = self.db.one("SELECT attempts FROM deprovision_queue WHERE id = ?", (queue_id,))
        return int(row["attempts"]) if row else 0

    def purge_expired(self) -> dict[str, int]:
        """Delete expired data. Grants with no live code or token end here."""
        now = self.now()
        counts: dict[str, int] = {}
        with self.db.transaction() as conn:
            counts["auth_requests"] = conn.execute(
                "DELETE FROM auth_requests WHERE expires_at <= ?", (now,)
            ).rowcount
            counts["connect_requests"] = conn.execute(
                "DELETE FROM connect_requests WHERE expires_at <= ?", (now,)
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
                " (SELECT 1 FROM grant_mailboxes gm WHERE gm.mailbox_id = mailboxes.id)"
            ).rowcount
        return counts
