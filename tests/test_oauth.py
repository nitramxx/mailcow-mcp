"""MCP authorization: metadata, registration, sign-in, tokens, revocation."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

import pytest

from mailcow_mcp.imap import LoginResult
from mailcow_mcp.oauth import (
    ACCESS_TOKEN_TTL,
    AUTH_CODE_TTL,
    REFRESH_TOKEN_TTL,
    UNUSED_CLIENT_TTL,
    clean_client_name,
    is_allowed_redirect_uri,
)

from conftest import (
    BASE_URL,
    EMAIL,
    PASSWORD,
    REDIRECT_URI,
    FakeVerifier,
    Harness,
    app_config,
    make_harness,
    pkce_pair,
    query_of,
)


class TestMetadata:
    def test_unauthenticated_mcp_points_to_resource_metadata(self, harness: Harness) -> None:
        response = harness.mcp(None)
        assert response.status_code == 401
        assert (
            f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource/mcp"'
            in response.headers["www-authenticate"]
        )

    def test_mcp_allows_browser_clients(self, harness: Harness) -> None:
        preflight = harness.client.options(
            "/mcp",
            headers={
                "Origin": "http://localhost:6274",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization, content-type, mcp-protocol-version",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "*"
        response = harness.client.post("/mcp", json={}, headers={"Origin": "http://localhost:6274"})
        assert response.status_code == 401
        assert "www-authenticate" in response.headers["access-control-expose-headers"]
        assert "access-control-allow-credentials" not in response.headers

    @pytest.mark.parametrize(
        "path",
        ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"],
    )
    def test_protected_resource_metadata(self, harness: Harness, path: str) -> None:
        data = harness.client.get(path).json()
        assert data["resource"] == f"{BASE_URL}/mcp"
        assert data["authorization_servers"] == [BASE_URL]
        assert data["resource_name"] == "mailcow MCP"

    def test_authorization_server_metadata(self, harness: Harness) -> None:
        response = harness.client.get(
            "/.well-known/oauth-authorization-server", headers={"Origin": "http://localhost:6274"}
        )
        data = response.json()
        assert data["issuer"] == BASE_URL  # exact, no trailing slash
        assert data["authorization_endpoint"] == f"{BASE_URL}/authorize"
        assert data["token_endpoint"] == f"{BASE_URL}/token"
        assert data["registration_endpoint"] == f"{BASE_URL}/register"
        assert data["revocation_endpoint"] == f"{BASE_URL}/revoke"
        assert data["code_challenge_methods_supported"] == ["S256"]
        assert "none" in data["token_endpoint_auth_methods_supported"]
        assert data["authorization_response_iss_parameter_supported"] is True
        assert response.headers["access-control-allow-origin"] == "*"


class TestRegistration:
    @pytest.mark.parametrize(
        ("uri", "allowed"),
        [
            ("https://claude.ai/api/mcp/auth_callback", True),
            ("https://example.com:8443/cb?x=1", True),
            ("http://127.0.0.1:33418/callback", True),
            ("http://localhost:6274/oauth/callback", True),
            ("http://[::1]:9000/cb", True),
            ("http://example.com/cb", False),
            ("http://127.0.0.2/cb", False),
            ("https://example.com/cb#frag", False),
            ("https://user:pw@example.com/cb", False),
            ("cursor://anysphere.cursor-mcp/oauth/callback", False),
            ("javascript:alert(1)", False),
            ("https:///nohost", False),
        ],
    )
    def test_redirect_uri_rules(self, uri: str, allowed: bool) -> None:
        assert is_allowed_redirect_uri(uri) is allowed

    def test_rejects_non_loopback_http(self, harness: Harness) -> None:
        response = harness.client.post(
            "/register", json={"redirect_uris": ["http://evil.example/cb"]}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_rejects_too_many_redirect_uris(self, harness: Harness) -> None:
        uris = [f"https://example.com/cb{i}" for i in range(11)]
        response = harness.client.post("/register", json={"redirect_uris": uris})
        assert response.status_code == 400

    def test_client_name_is_cleaned(self, harness: Harness) -> None:
        client = harness.register(client_name="Evil‮Name\n<b>")
        row = harness.db.one(
            "SELECT client_name FROM clients WHERE client_id = ?", (client["client_id"],)
        )
        assert row is not None
        assert row["client_name"] == "EvilName <b>"

    def test_clean_client_name(self) -> None:
        assert clean_client_name("  a\tb  ") == "a b"
        assert clean_client_name("​") is None
        assert clean_client_name("x" * 200) == "x" * 80

    def test_confidential_client_secret_is_encrypted(self, harness: Harness) -> None:
        client = harness.register(token_endpoint_auth_method="client_secret_post")
        row = harness.db.one("SELECT metadata, client_secret_enc FROM clients")
        assert row is not None
        assert client["client_secret"] not in row["metadata"]
        assert client["client_secret"] not in row["client_secret_enc"]

    def test_rate_limited_per_ip(self, harness: Harness) -> None:
        for _ in range(20):
            harness.register()
        response = harness.client.post("/register", json={"redirect_uris": [REDIRECT_URI]})
        assert response.status_code == 429


class TestAuthorize:
    def test_wrong_resource_is_refused(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        location = harness.authorize(client_id, challenge, resource="https://other.example/mcp")
        params = query_of(location)
        assert location.startswith(REDIRECT_URI)
        assert params["error"] == "invalid_target"
        assert params["state"] == "state-123"

    def test_resource_is_optional(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        query = {
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
        }
        response = harness.client.get("/authorize", params=query, follow_redirects=False)
        assert response.headers["location"].startswith(f"{BASE_URL}/login?request=")

    def test_unregistered_redirect_uri_is_not_redirected_to(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        query = {
            "client_id": client_id,
            "redirect_uri": "https://attacker.example/cb",
            "response_type": "code",
            "code_challenge": challenge,
        }
        response = harness.client.get("/authorize", params=query, follow_redirects=False)
        assert response.status_code == 400

    def test_loopback_redirect_may_use_any_port(self, harness: Harness) -> None:
        # VS Code registers http://127.0.0.1/ and may then listen on a random port.
        client_id = harness.register(
            redirect_uris=["http://127.0.0.1/", "https://vscode.dev/redirect"]
        )["client_id"]
        _, challenge = pkce_pair()
        for uri, ok in [
            ("http://127.0.0.1:54321/", True),
            ("http://127.0.0.1/", True),
            ("http://127.0.0.1:54321/other", False),
            ("http://localhost:54321/", False),
            ("https://vscode.dev:8443/redirect", False),
        ]:
            query = {
                "client_id": client_id,
                "redirect_uri": uri,
                "response_type": "code",
                "code_challenge": challenge,
            }
            response = harness.client.get("/authorize", params=query, follow_redirects=False)
            assert (response.status_code == 302) is ok, uri

    def test_pkce_is_required(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        query = {"client_id": client_id, "redirect_uri": REDIRECT_URI, "response_type": "code"}
        response = harness.client.get("/authorize", params=query, follow_redirects=False)
        assert query_of(response.headers["location"])["error"] == "invalid_request"


class TestLoginPage:
    def test_page_shows_client_and_redirect_host(self, harness: Harness) -> None:
        client_id = harness.register(
            client_name="Claude", redirect_uris=["https://claude.ai/api/mcp/auth_callback"]
        )["client_id"]
        _, challenge = pkce_pair()
        login_url = harness.authorize(
            client_id, challenge, redirect_uri="https://claude.ai/api/mcp/auth_callback"
        )
        page = harness.client.get(login_url)
        assert "Claude wants to use your mailbox." in page.text
        assert "<strong>claude.ai</strong>" in page.text
        assert "mailcow MCP" in page.text

    def test_security_headers(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        page = harness.client.get(harness.authorize(client_id, challenge))
        csp = page.headers["content-security-policy"]
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "form-action 'self' http://127.0.0.1:3333" in csp
        assert "script-src" not in csp
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["x-content-type-options"] == "nosniff"
        assert page.headers["referrer-policy"] == "no-referrer"
        assert page.headers["cache-control"] == "no-store"
        assert "<script" not in page.text
        # no third-party assets: every src/href is a local path
        assert re.findall(r'(?:src|href)="([^"]*)"', page.text) == ["/static/style.css"]

    def test_client_name_is_escaped(self, harness: Harness) -> None:
        client_id = harness.register(client_name='<img src=x onerror="alert(1)">')["client_id"]
        _, challenge = pkce_pair()
        page = harness.client.get(harness.authorize(client_id, challenge))
        assert "<img" not in page.text
        assert "&lt;img" in page.text

    def test_czech(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        page = harness.client.get(
            harness.authorize(client_id, challenge),
            headers={"Accept-Language": "cs-CZ,cs;q=0.9,en;q=0.5"},
        )
        assert '<html lang="cs">' in page.text
        assert "Přihlásit a povolit" in page.text

    def test_unknown_or_expired_request(self, harness: Harness) -> None:
        page = harness.client.get("/login?request=nope")
        assert page.status_code == 400
        assert "This sign-in has expired" in page.text

    def test_request_expires(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        login_url = harness.authorize(client_id, challenge)
        harness.clock.advance(16 * 60)
        assert harness.client.get(login_url).status_code == 400


class TestSignIn:
    def test_wrong_password(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, csrf, password="wrong")
        assert response.status_code == 401
        assert "Wrong email address or password." in response.text
        assert f'value="{EMAIL}"' in response.text
        assert harness.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]

    def test_email_is_normalized(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, csrf, email="  User@EXAMPLE.org ")
        assert response.status_code == 303
        assert harness.verifier.calls[-1] == (EMAIL, PASSWORD)

    def test_invalid_email(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, csrf, email="not an email")
        assert response.status_code == 400
        assert harness.verifier.calls == []

    def test_wrong_csrf(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, _ = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, "forged")
        assert response.status_code == 400
        assert harness.verifier.calls == []

    def test_cross_origin_post_is_refused(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.client.post(
            "/login",
            data={
                "request": request_id,
                "csrf": csrf,
                "action": "login",
                "email": EMAIL,
                "password": PASSWORD,
            },
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 403
        assert harness.verifier.calls == []

    def test_cancel(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, csrf, action="deny")
        params = query_of(response.headers["location"])
        assert response.status_code == 303
        assert params["error"] == "access_denied"
        assert params["state"] == "state-123"
        assert params["iss"] == BASE_URL
        # the request is used up
        assert harness.submit_login(request_id, csrf).status_code == 400

    def test_success_redirects_with_code_state_and_issuer(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        response = harness.submit_login(request_id, csrf)
        assert response.status_code == 303
        assert response.headers["location"].startswith(REDIRECT_URI + "?")
        params = query_of(response.headers["location"])
        assert set(params) == {"code", "state", "iss"}
        assert params["iss"] == BASE_URL
        # a sign-in request works once
        assert harness.submit_login(request_id, csrf).status_code == 400

    def test_password_is_stored_encrypted(self, harness: Harness) -> None:
        harness.tokens()
        dump = "\n".join(harness.db.conn.iterdump())
        assert PASSWORD not in dump
        assert EMAIL in dump

    def test_mail_server_unavailable(self) -> None:
        for h in make_harness(app_config(), FakeVerifier(result=LoginResult.UNAVAILABLE)):
            client_id = h.register()["client_id"]
            _, challenge = pkce_pair()
            request_id, csrf = h.open_login(h.authorize(client_id, challenge))
            response = h.submit_login(request_id, csrf)
            assert response.status_code == 503
            assert "be reached right now" in response.text

    def test_allowed_domains_checked_before_mail_server(self) -> None:
        for h in make_harness(app_config(ALLOWED_DOMAINS="example.com")):
            client_id = h.register()["client_id"]
            _, challenge = pkce_pair()
            request_id, csrf = h.open_login(h.authorize(client_id, challenge))
            response = h.submit_login(request_id, csrf)
            assert response.status_code == 403
            assert "example.org" in response.text
            assert h.verifier.calls == []

    def test_attempts_are_limited_per_ip(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        for i in range(10):
            harness.submit_login(request_id, csrf, email=f"user{i}@example.org", password="x")
        response = harness.submit_login(request_id, csrf)
        assert response.status_code == 429
        assert len(harness.verifier.calls) == 10

    def test_failures_lock_the_mailbox_for_15_minutes(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        for _ in range(10):
            harness.submit_login(request_id, csrf, password="wrong")
        harness.clock.advance(11 * 60)  # the per-IP window has passed
        response = harness.submit_login(request_id, csrf)
        assert response.status_code == 429  # the mailbox is still locked
        assert len(harness.verifier.calls) == 10
        harness.clock.advance(5 * 60)
        request_id, csrf = harness.open_login(harness.authorize(client_id, challenge))
        assert harness.submit_login(request_id, csrf).status_code == 303

    def test_audit_has_no_secrets(self, harness: Harness) -> None:
        _, tokens = harness.tokens()
        log = harness.audit_stream.getvalue()
        assert PASSWORD not in log
        assert tokens["access_token"] not in log
        events = [json.loads(line) for line in harness.audit_lines()]
        login = next(e for e in events if e["audit"] == "login")
        assert login == {
            "ts": login["ts"],
            "audit": "login",
            "result": "ok",
            "mailbox": EMAIL,
            "client": "Test Client",
            "method": "password",
            "ip": "testclient",
        }


class TestPasswordLoginDisabled:
    @pytest.fixture
    def mailcow(self) -> Iterator[Harness]:
        yield from make_harness(
            app_config(
                MODE="mailcow",
                MAILCOW_URL="https://mail.example.com",
                MAILCOW_OAUTH_CLIENT_ID="id",
                MAILCOW_OAUTH_CLIENT_SECRET="secret",
                BROKER_SHARED_SECRET="s" * 40,
                TLS_SERVER_NAME="mail.example.com",
            )
        )

    def test_no_password_form_in_mailcow_mode(self, mailcow: Harness) -> None:
        client_id = mailcow.register()["client_id"]
        _, challenge = pkce_pair()
        page = mailcow.client.get(mailcow.authorize(client_id, challenge))
        assert page.status_code == 200
        assert "Sign in with mailcow" in page.text
        assert 'type="password"' not in page.text
        assert (
            "form-action 'self' http://127.0.0.1:3333 https://mail.example.com"
            in page.headers["content-security-policy"]
        )


class TestTokens:
    def test_full_flow_reaches_mcp_with_no_tools(self, harness: Harness) -> None:
        _, tokens = harness.tokens()
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == ACCESS_TOKEN_TTL
        assert tokens["access_token"].startswith("mcp_at_")
        assert tokens["refresh_token"].startswith("mcp_rt_")
        initialize = harness.mcp(tokens["access_token"])
        assert initialize.status_code == 200
        assert '"serverInfo"' in initialize.text

    def test_tokens_are_stored_hashed(self, harness: Harness) -> None:
        _, tokens = harness.tokens()
        dump = "\n".join(harness.db.conn.iterdump())
        assert tokens["access_token"] not in dump
        assert tokens["refresh_token"] not in dump

    def test_wrong_pkce_verifier(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        code, _ = harness.sign_in(client_id)
        response = harness.exchange(client_id, code, "x" * 50)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    def test_code_is_bound_to_its_client(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        other_id = harness.register()["client_id"]
        code, verifier = harness.sign_in(client_id)
        assert harness.exchange(other_id, code, verifier).json()["error"] == "invalid_grant"

    def test_code_expires(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        code, verifier = harness.sign_in(client_id)
        harness.clock.advance(AUTH_CODE_TTL + 1)
        assert harness.exchange(client_id, code, verifier).json()["error"] == "invalid_grant"

    def test_code_reuse_revokes_the_grant(self, harness: Harness) -> None:
        client_id = harness.register()["client_id"]
        code, verifier = harness.sign_in(client_id)
        tokens = harness.exchange(client_id, code, verifier).json()
        assert harness.exchange(client_id, code, verifier).json()["error"] == "invalid_grant"
        assert harness.mcp(tokens["access_token"]).status_code == 401
        assert any('"code_reuse"' in line for line in harness.audit_lines())

    def test_refresh_rotates(self, harness: Harness) -> None:
        client_id, tokens = harness.tokens()
        response = harness.refresh(client_id, tokens["refresh_token"])
        assert response.status_code == 200
        new = response.json()
        assert new["refresh_token"] != tokens["refresh_token"]
        assert harness.mcp(new["access_token"]).status_code == 200

    def test_refresh_token_reuse_revokes_the_grant(self, harness: Harness) -> None:
        client_id, tokens = harness.tokens()
        new = harness.refresh(client_id, tokens["refresh_token"]).json()
        reuse = harness.refresh(client_id, tokens["refresh_token"])
        assert reuse.status_code == 400
        assert harness.mcp(new["access_token"]).status_code == 401
        assert harness.refresh(client_id, new["refresh_token"]).status_code == 400

    def test_access_token_expires(self, harness: Harness) -> None:
        _, tokens = harness.tokens()
        harness.clock.advance(ACCESS_TOKEN_TTL + 1)
        assert harness.mcp(tokens["access_token"]).status_code == 401

    def test_refresh_token_expires(self, harness: Harness) -> None:
        client_id, tokens = harness.tokens()
        harness.clock.advance(REFRESH_TOKEN_TTL + 1)
        assert harness.refresh(client_id, tokens["refresh_token"]).status_code == 400

    def test_revoke_ends_the_grant(self, harness: Harness) -> None:
        client_id, tokens = harness.tokens()
        response = harness.client.post(
            "/revoke", data={"token": tokens["refresh_token"], "client_id": client_id}
        )
        assert response.status_code == 200
        assert harness.mcp(tokens["access_token"]).status_code == 401
        assert harness.db.one("SELECT count(*) AS n FROM grants")["n"] == 0  # type: ignore[index]

    def test_garbage_token(self, harness: Harness) -> None:
        assert harness.mcp("mcp_at_nope").status_code == 401


class TestPurge:
    def test_unused_clients_and_ended_grants_are_deleted(self, harness: Harness) -> None:
        provider = harness.provider
        harness.register()  # never used
        client_id, _ = harness.tokens()
        harness.clock.advance(UNUSED_CLIENT_TTL + 1)
        provider.purge_expired()
        # the used client keeps its grant (its refresh token is still valid)
        rows = harness.db.all("SELECT client_id FROM clients")
        assert [r["client_id"] for r in rows] == [client_id]

        harness.clock.advance(REFRESH_TOKEN_TTL)
        counts = provider.purge_expired()
        assert counts["grants"] == 1
        harness.clock.advance(UNUSED_CLIENT_TTL + 1)
        provider.purge_expired()
        for table in ("clients", "grants", "mailboxes", "tokens", "auth_codes"):
            assert harness.db.one(f"SELECT count(*) AS n FROM {table}")["n"] == 0  # type: ignore[index]  # noqa: S608

    def test_abandoned_sign_in_is_cleaned_up(self, harness: Harness) -> None:
        provider = harness.provider
        client_id = harness.register()["client_id"]
        harness.sign_in(client_id)  # code never exchanged
        harness.clock.advance(AUTH_CODE_TTL + 1)
        assert provider.purge_expired()["grants"] == 1
