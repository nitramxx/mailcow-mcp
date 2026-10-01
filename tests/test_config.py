from __future__ import annotations

from pathlib import Path

import pytest

from mailcow_mcp.config import (
    ConfigError,
    Mode,
    SaveSent,
    Security,
    generate_key,
    load_app_config,
    load_broker_config,
)

ENC_KEY = generate_key()
SHARED = generate_key()
SIGNING = generate_key()


def mailcow_env(**overrides: str) -> dict[str, str]:
    env = {
        "PUBLIC_URL": "https://mcp.mail.example.com/",
        "MAILCOW_URL": "https://mail.example.com",
        "MAILCOW_OAUTH_CLIENT_ID": "client-id",
        "MAILCOW_OAUTH_CLIENT_SECRET": "client-secret-value",
        "BROKER_SHARED_SECRET": SHARED,
        "TLS_SERVER_NAME": "mail.example.com",
        "ENC_KEY": ENC_KEY,
        "TRUSTED_PROXIES": "172.22.1.0/24",
    }
    env.update(overrides)
    return env


def generic_env(**overrides: str) -> dict[str, str]:
    env = {
        "MODE": "generic",
        "PUBLIC_URL": "https://mcp.example.org",
        "IMAP_HOST": "imap.example.org",
        "SMTP_HOST": "smtp.example.org",
        "ENC_KEY": ENC_KEY,
        "TRUSTED_PROXIES": "127.0.0.1",
    }
    env.update(overrides)
    return env


def broker_env(**overrides: str) -> dict[str, str]:
    env = {
        "MAILCOW_API_URL": "https://nginx-mailcow",
        "TLS_SERVER_NAME": "mail.example.com",
        "MAILCOW_API_KEY": "ABCDEF-123456-ABCDEF-123456-ABCDEF",
        "BROKER_SHARED_SECRET": SHARED,
        "BROKER_SIGNING_KEY": SIGNING,
    }
    env.update(overrides)
    return env


def errors_of(exc: pytest.ExceptionInfo[ConfigError]) -> str:
    return "\n".join(exc.value.errors)


class TestAppMailcowMode:
    def test_defaults(self) -> None:
        c = load_app_config(mailcow_env())
        assert c.mode is Mode.MAILCOW
        assert c.public_url == "https://mcp.mail.example.com"
        assert c.broker_url == "http://broker:8091"
        assert (c.imap_host, c.imap_port, c.imap_security) == ("dovecot-mailcow", 993, Security.SSL)
        assert (c.smtp_host, c.smtp_port, c.smtp_security) == (
            "postfix-mailcow",
            587,
            Security.STARTTLS,
        )
        assert c.carddav_url == "https://mail.example.com/SOGo/dav"
        assert c.carddav_internal is False
        assert c.mailcow_internal_url is None
        assert c.tls_verify is True
        assert c.allow_password_login is False
        assert c.allowed_domains == ()
        assert c.save_sent is SaveSent.ALWAYS
        assert (c.send_limit_hour, c.send_limit_day, c.max_message_mb) == (30, 300, 15)
        assert c.trusted_proxies == ("172.22.1.0/24",)
        assert (c.instance_name, c.default_language) == ("mailcow MCP", "en")
        assert c.data_dir == Path("/data")
        assert c.port == 8090

    def test_all_missing_reports_every_required_variable(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config({})
        text = errors_of(exc)
        for name in (
            "PUBLIC_URL",
            "MAILCOW_URL",
            "MAILCOW_OAUTH_CLIENT_ID",
            "MAILCOW_OAUTH_CLIENT_SECRET",
            "BROKER_SHARED_SECRET",
            "TLS_SERVER_NAME",
            "ENC_KEY",
            "TRUSTED_PROXIES",
        ):
            assert name in text
        # one line per variable, no follow-up noise
        assert len(exc.value.errors) == 8
        assert "generate-key" in str(exc.value)

    def test_internal_url(self) -> None:
        c = load_app_config(mailcow_env(MAILCOW_INTERNAL_URL="https://nginx-mailcow"))
        assert c.mailcow_internal_url == "https://nginx-mailcow"
        assert c.carddav_url == "https://nginx-mailcow/SOGo/dav"
        assert c.carddav_internal is True

    def test_sending_settings(self) -> None:
        c = load_app_config(
            mailcow_env(
                FROM_NAMES="URX@lexorate.com = Martin Urx; sales@lexorate.com=Lexorate Sales\n",
                TIMEZONE="Europe/Prague",
                SMTP_HELO_NAME="Email.Ozpr.cz",
            )
        )
        assert c.from_names == {
            "urx@lexorate.com": "Martin Urx",
            "sales@lexorate.com": "Lexorate Sales",
        }
        assert str(c.timezone) == "Europe/Prague"
        assert c.smtp_helo_name == "email.ozpr.cz"
        defaults = load_app_config(mailcow_env())
        assert defaults.smtp_helo_name == "mail.example.com"  # TLS_SERVER_NAME
        assert defaults.timezone is None and defaults.from_names == {}

    @pytest.mark.parametrize(
        ("name", "value", "message"),
        [
            ("FROM_NAMES", "no-equals-sign", "address=Name"),
            ("FROM_NAMES", "a@example.com=", "invalid display name"),
            ("FROM_NAMES", "a@example.com=Bad\x01Name", "invalid display name"),
            ("TIMEZONE", "Mars/Olympus", "time zone"),
            ("TIMEZONE", "Europe", "time zone"),
            ("FROM_NAMES", "a@example.com=Bad\x7fName", "invalid display name"),
            ("SMTP_HELO_NAME", "not a host", "not a valid hostname"),
        ],
    )
    def test_invalid_sending_settings(self, name: str, value: str, message: str) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(**{name: value}))
        assert message in "\n".join(exc.value.errors)

    def test_from_names_edge_cases(self) -> None:
        c = load_app_config(
            mailcow_env(FROM_NAMES="a=b@example.com=Equals Name; info@příklad.cz=Info")
        )
        assert c.from_names == {
            "a=b@example.com": "Equals Name",
            "info@xn--pklad-zsa96e.cz": "Info",
        }
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(FROM_NAMES="a@bad_domain=X"))
        assert len(exc.value.errors) == 1  # reported once

    def test_helo_name_for_an_ip(self) -> None:
        c = load_app_config(generic_env(SMTP_HOST="192.168.1.20"))
        assert c.smtp_helo_name == "[192.168.1.20]"

    def test_empty_values_count_as_missing(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(PUBLIC_URL="  ", ENC_KEY=""))
        assert exc.value.errors[0].startswith("PUBLIC_URL: required")
        assert any(e.startswith("ENC_KEY: required") for e in exc.value.errors)

    @pytest.mark.parametrize(
        ("name", "value", "message"),
        [
            ("MODE", "exchange", "must be one of mailcow, generic"),
            ("PUBLIC_URL", "http://mcp.example.com", "must start with https://"),
            ("PUBLIC_URL", "https://mcp.example.com/mcp", "must not contain a path"),
            ("PUBLIC_URL", "https://user:pw@mcp.example.com", "must not contain credentials"),
            ("PUBLIC_URL", "https://mcp.example.com/?x=1", "query"),
            ("PUBLIC_URL", "https://mcp.example.com:99999", "not a valid URL"),
            ("MAILCOW_URL", "mail.example.com", "must start with https://"),
            ("BROKER_URL", "ftp://broker", "http:// or https://"),
            ("IMAP_PORT", "0", "between 1 and 65535"),
            ("IMAP_PORT", "abc", "whole number"),
            ("IMAP_SECURITY", "none", "must be one of ssl, starttls"),
            ("SMTP_HOST", "bad host", "not a valid hostname"),
            ("TLS_SERVER_NAME", "-bad.example.com", "not a valid hostname"),
            ("TLS_VERIFY", "maybe", "true or false"),
            ("ENC_KEY", "not-a-key", "not a valid key"),
            ("BROKER_SHARED_SECRET", "short", "too short"),
            ("SAVE_SENT", "sometimes", "auto, always, never"),
            ("SEND_LIMIT_HOUR", "-1", "between"),
            ("MAX_MESSAGE_MB", "500", "between 1 and 100"),
            ("TRUSTED_PROXIES", "*", "spoof"),
            ("TRUSTED_PROXIES", "10.0.0.0/33", "not an IP address or CIDR"),
            ("ALLOWED_DOMAINS", "example.com,not_a domain", "not a valid hostname"),
            ("DEFAULT_LANGUAGE", "de", "must be one of en, cs"),
            ("INSTANCE_NAME", "bad\nname", "printable"),
            ("PORT", "70000", "between 1 and 65535"),
        ],
    )
    def test_invalid_values(self, name: str, value: str, message: str) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(**{name: value}))
        assert len(exc.value.errors) == 1, exc.value.errors
        assert exc.value.errors[0].startswith(f"{name}:")
        assert message in exc.value.errors[0]

    def test_send_limit_day_below_hour(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(SEND_LIMIT_HOUR="50", SEND_LIMIT_DAY="10"))
        assert "SEND_LIMIT_DAY" in errors_of(exc)

    def test_loopback_http_public_url_allowed_for_local_testing(self) -> None:
        c = load_app_config(mailcow_env(PUBLIC_URL="http://localhost:8090"))
        assert c.public_url == "http://localhost:8090"

    def test_parsing(self) -> None:
        c = load_app_config(
            mailcow_env(
                MODE="MAILCOW",
                ALLOWED_DOMAINS=" Example.COM, @příklad.cz ,example.com",
                TRUSTED_PROXIES="172.22.1.0/24, fd4d:6169:6c63:6f77::/64, 10.0.0.5",
                TLS_VERIFY="no",
                ALLOW_PASSWORD_LOGIN="true",
                SAVE_SENT="Never",
                CARDDAV_URL="https://dav.example.com/dav/",
                TLS_SERVER_NAME="Mail.Example.com.",
            )
        )
        assert c.allowed_domains == ("example.com", "xn--pklad-zsa96e.cz")
        assert c.trusted_proxies == ("172.22.1.0/24", "fd4d:6169:6c63:6f77::/64", "10.0.0.5/32")
        assert c.tls_verify is False
        assert c.allow_password_login is True
        assert c.save_sent is SaveSent.NEVER
        assert c.carddav_url == "https://dav.example.com/dav"
        assert c.tls_server_name == "mail.example.com"

    def test_secrets_are_not_in_repr(self) -> None:
        c = load_app_config(mailcow_env())
        text = repr(c)
        assert ENC_KEY not in text
        assert SHARED not in text
        assert "client-secret-value" not in text

    def test_secrets_are_not_in_errors(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(mailcow_env(ENC_KEY="secret-but-invalid", BROKER_SHARED_SECRET="tiny"))
        assert "secret-but-invalid" not in str(exc.value)
        assert "tiny" not in str(exc.value)


class TestAppGenericMode:
    def test_defaults(self) -> None:
        c = load_app_config(generic_env())
        assert c.mode is Mode.GENERIC
        assert c.allow_password_login is True
        assert c.mailcow_url is None
        assert c.broker_shared_secret is None
        assert c.carddav_url is None
        assert c.tls_server_name is None

    def test_mailcow_settings_not_required(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config({"MODE": "generic"})
        assert set(e.split(":")[0] for e in exc.value.errors) == {
            "PUBLIC_URL",
            "ENC_KEY",
            "TRUSTED_PROXIES",
        }

    def test_password_login_cannot_be_disabled(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_app_config(generic_env(ALLOW_PASSWORD_LOGIN="false"))
        assert "ALLOW_PASSWORD_LOGIN" in errors_of(exc)

    def test_optional_carddav_and_tls_name(self) -> None:
        c = load_app_config(
            generic_env(CARDDAV_URL="https://dav.example.org/", TLS_SERVER_NAME="mx.example.org")
        )
        assert c.carddav_url == "https://dav.example.org"
        assert c.tls_server_name == "mx.example.org"


class TestBroker:
    def test_defaults(self) -> None:
        c = load_broker_config(broker_env())
        assert c.mailcow_api_url == "https://nginx-mailcow"
        assert c.mailcow_oauth_profile_url == "https://nginx-mailcow/oauth/profile"
        assert c.tls_verify is True
        assert c.port == 8091

    def test_all_missing(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_broker_config({})
        assert set(e.split(":")[0] for e in exc.value.errors) == {
            "MAILCOW_API_URL",
            "TLS_SERVER_NAME",
            "MAILCOW_API_KEY",
            "BROKER_SHARED_SECRET",
            "BROKER_SIGNING_KEY",
        }

    def test_api_must_use_https(self) -> None:
        with pytest.raises(ConfigError) as exc:
            load_broker_config(broker_env(MAILCOW_API_URL="http://nginx-mailcow"))
        assert "MAILCOW_API_URL: must start with https://" in errors_of(exc)

    def test_secrets_are_not_in_repr_or_errors(self) -> None:
        text = repr(load_broker_config(broker_env()))
        assert "ABCDEF-123456" not in text
        assert SHARED not in text
        assert SIGNING not in text
        with pytest.raises(ConfigError) as exc:
            load_broker_config(broker_env(BROKER_SIGNING_KEY="leaky-value"))
        assert "leaky-value" not in str(exc.value)


def test_generate_key_is_unique_and_valid() -> None:
    a, b = generate_key(), generate_key()
    assert a != b
    load_app_config(mailcow_env(ENC_KEY=a, BROKER_SHARED_SECRET=b))
