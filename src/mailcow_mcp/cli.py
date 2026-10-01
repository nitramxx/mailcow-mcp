"""Command-line entry point: ``mailcow-mcp <command>``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
import time
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio
import uvicorn

from mailcow_mcp import __version__
from mailcow_mcp.app import MCP_PATH, create_app
from mailcow_mcp.audit import AuditLog
from mailcow_mcp.broker import create_broker_app
from mailcow_mcp.broker_client import BrokerClient
from mailcow_mcp.config import (
    DEFAULT_APP_PORT,
    DEFAULT_BROKER_PORT,
    AppConfig,
    ConfigError,
    Mode,
    generate_key,
    load_app_config,
    load_broker_config,
)
from mailcow_mcp.crypto import Box
from mailcow_mcp.db import Database
from mailcow_mcp.errors import MailError
from mailcow_mcp.lifecycle import drain_deprovision_queue, reconcile
from mailcow_mcp.login import LOGIN_PATH, normalize_email
from mailcow_mcp.logs import setup_logging
from mailcow_mcp.oauth import Provider

log = logging.getLogger("mailcow_mcp")

EXIT_CONFIG = 2


def _fail(message: str) -> int:
    print(f"mailcow-mcp: {message}", file=sys.stderr)
    return EXIT_CONFIG


def _check_data_dir(path: Path) -> str | None:
    """An error message if ``path`` is not a writable directory."""
    if not path.is_dir():
        return f"DATA_DIR {path} does not exist; mount a volume there"
    try:
        with tempfile.TemporaryFile(dir=path):
            pass
    except OSError as exc:
        return f"DATA_DIR {path} is not writable ({exc.strerror}); check the volume permissions"
    return None


def app_server_options(config: AppConfig) -> dict[str, Any]:
    """uvicorn settings for the app: the real client IP only from TRUSTED_PROXIES."""
    return {
        "host": config.host,
        "port": config.port,
        "proxy_headers": True,
        "forwarded_allow_ips": list(config.trusted_proxies),
        "server_header": False,
        "log_config": None,
    }


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        config = load_app_config()
    except ConfigError as exc:
        return _fail(str(exc))
    if error := _check_data_dir(config.data_dir):
        return _fail(error)
    setup_logging()
    if not config.tls_verify:
        log.warning("TLS_VERIFY=false: mail server certificates are not verified")
    log.info("starting app %s in %s mode on port %d", __version__, config.mode, config.port)
    uvicorn.run(create_app(config), **app_server_options(config))
    return 0


def cmd_broker(args: argparse.Namespace) -> int:
    try:
        config = load_broker_config()
    except ConfigError as exc:
        return _fail(str(exc))
    if error := _check_data_dir(config.data_dir):
        return _fail(error)
    setup_logging()
    if not config.tls_verify:
        log.warning("TLS_VERIFY=false: the mailcow API certificate is not verified")
    log.info("starting broker %s on port %d", __version__, config.port)
    uvicorn.run(
        create_broker_app(config),
        host=config.host,  # set to its internal-network IP by the compose file
        port=config.port,
        proxy_headers=False,
        server_header=False,
        log_config=None,
    )
    return 0


def _open_database(config: AppConfig) -> Database:
    db = Database.in_data_dir(config.data_dir)
    db.migrate()
    return db


def _app_config() -> AppConfig | int:
    try:
        return load_app_config()
    except ConfigError as exc:
        return _fail(str(exc))


def _when(timestamp: int | None) -> str:
    if not timestamp:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
    for row in [header, *rows]:
        print(
            "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        )


def cmd_migrate(args: argparse.Namespace) -> int:
    config = _app_config()
    if isinstance(config, int):
        return config
    db = Database.in_data_dir(config.data_dir)
    applied = db.migrate()
    print(f"applied: {', '.join(applied)}" if applied else "database is up to date")
    print(f"schema version {db.version}")
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    config = _app_config()
    if isinstance(config, int):
        return config
    rows = _open_database(config).all(
        "SELECT m.username, count(g.id) AS grants, max(g.last_used_at) AS last_used,"
        " m.last_login_at, group_concat(DISTINCT coalesce(c.client_name, '?')) AS clients"
        " FROM mailboxes m LEFT JOIN grants g ON g.mailbox_id = m.id"
        " LEFT JOIN clients c ON c.client_id = g.client_id"
        " GROUP BY m.id ORDER BY m.username"
    )
    _print_table(
        ("MAILBOX", "CONNECTIONS", "LAST LOGIN", "LAST USED", "CLIENTS"),
        [
            (
                r["username"],
                str(r["grants"]),
                _when(r["last_login_at"]),
                _when(r["last_used"]),
                r["clients"] or "-",
            )
            for r in rows
        ],
    )
    return 0


def cmd_clients(args: argparse.Namespace) -> int:
    config = _app_config()
    if isinstance(config, int):
        return config
    rows = _open_database(config).all(
        "SELECT c.client_id, c.client_name, c.created_at, c.last_used_at, count(g.id) AS grants"
        " FROM clients c LEFT JOIN grants g ON g.client_id = c.client_id"
        " GROUP BY c.client_id ORDER BY c.created_at"
    )
    _print_table(
        ("CLIENT ID", "NAME", "REGISTERED", "LAST USED", "CONNECTIONS"),
        [
            (
                r["client_id"],
                r["client_name"] or "-",
                _when(r["created_at"]),
                _when(r["last_used_at"]),
                str(r["grants"]),
            )
            for r in rows
        ],
    )
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    config = _app_config()
    if isinstance(config, int):
        return config
    if args.all == bool(args.mailbox):
        return _fail("give a mailbox, or --all")
    username = normalize_email(args.mailbox) if args.mailbox else None
    if args.mailbox and username is None:
        return _fail(f"not an email address: {args.mailbox!r}")
    provider = Provider(
        _open_database(config),
        Box(config.enc_key),
        issuer_url=config.public_url,
        resource_url=config.public_url + MCP_PATH,
        login_url=config.public_url + LOGIN_PATH,
        audit=AuditLog.in_data_dir(config.data_dir),
    )
    if username is not None:
        count = provider.revoke_mailbox(username)
        print(f"revoked {count} connection(s) of {username}")
    else:
        mailboxes = [r["username"] for r in provider.db.all("SELECT username FROM mailboxes")]
        count = sum(provider.revoke_mailbox(m) for m in mailboxes)
        print(f"revoked {count} connection(s) of {len(mailboxes)} mailbox(es)")
    if config.mode is Mode.MAILCOW:
        return _deprovision_now(config, provider, everything=username is None)
    return 0


def _deprovision_now(config: AppConfig, provider: Provider, *, everything: bool) -> int:
    """Delete the app passwords through the broker now (the app would retry anyway)."""

    async def run() -> tuple[int, int]:
        broker = BrokerClient(config.broker_url, config.broker_shared_secret or "")
        try:
            done = await drain_deprovision_queue(provider, broker)
            # With --all, the broker also removes "MCP: " app passwords it knows of.
            extra = await reconcile(provider, broker) if everything else 0
            return done, extra
        finally:
            await broker.aclose()

    try:
        done, extra = anyio.run(run)
    except MailError as exc:
        print(f"mailcow-mcp: {exc} The app retries deleting the app passwords.", file=sys.stderr)
        return 1
    left = len(provider.pending_deprovisions())
    print(
        f"deleted {done + extra} app password(s) in mailcow"
        + (f"; {left} still queued" if left else "")
    )
    return 0


def cmd_check_mailcow(args: argparse.Namespace) -> int:
    """Broker: can it use the mailcow API with its key, from its address?"""
    try:
        config = load_broker_config()
    except ConfigError as exc:
        return _fail(str(exc))
    from mailcow_mcp.mailcow_api import MailcowApi, MailcowError

    async def run() -> str | None:
        api = MailcowApi(
            config.mailcow_api_url,
            config.mailcow_api_key,
            config.mailcow_oauth_profile_url,
            server_name=config.tls_server_name,
            verify=config.tls_verify,
            ca_file=config.tls_ca_file,
        )
        try:
            await api.password_policy()
        except MailcowError as exc:
            return str(exc)
        finally:
            await api.aclose()
        return None

    error = anyio.run(run)
    if error:
        print(f"mailcow-mcp: {error}", file=sys.stderr)
        return 1
    print("mailcow API: ok")
    return 0


def cmd_generate_key(args: argparse.Namespace) -> int:
    print(generate_key())
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Probe the local /healthz; used by the container HEALTHCHECK."""
    if args.port:
        ports = [args.port]
    elif os.environ.get("PORT", "").strip():
        ports = [int(os.environ["PORT"])]
    else:
        # The same image runs either role; only one of them listens here.
        ports = [DEFAULT_APP_PORT, DEFAULT_BROKER_PORT]
    host = os.environ.get("HOST", "").strip()
    host = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host  # noqa: S104
    if ":" in host:
        host = f"[{host}]"
    for port in ports:
        try:
            url = f"http://{host}:{port}/healthz"
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return 0
        except OSError:
            continue
    print("mailcow-mcp: unhealthy", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailcow-mcp", description="Self-hosted remote MCP server for mailcow."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    sub.add_parser("serve", help="run the MCP app (internet-facing, behind nginx)").set_defaults(
        func=cmd_serve
    )
    sub.add_parser(
        "broker", help="run the internal broker that holds the mailcow API key"
    ).set_defaults(func=cmd_broker)
    sub.add_parser(
        "generate-key", help="print a new key for ENC_KEY, BROKER_SIGNING_KEY, BROKER_SHARED_SECRET"
    ).set_defaults(func=cmd_generate_key)
    sub.add_parser(
        "check-mailcow", help="broker: check that the mailcow API accepts its key and address"
    ).set_defaults(func=cmd_check_mailcow)
    sub.add_parser("migrate", help="apply database migrations (also done on start)").set_defaults(
        func=cmd_migrate
    )
    sub.add_parser("users", help="list connected mailboxes").set_defaults(func=cmd_users)
    sub.add_parser("clients", help="list registered MCP clients").set_defaults(func=cmd_clients)
    revoke = sub.add_parser(
        "revoke", help="disconnect every client of a mailbox (and delete its MCP app passwords)"
    )
    revoke.add_argument("mailbox", nargs="?", help="email address of the mailbox")
    revoke.add_argument("--all", action="store_true", help="every mailbox (before uninstalling)")
    revoke.set_defaults(func=cmd_revoke)
    health = sub.add_parser("healthcheck", help="exit 0 if the local server is healthy")
    health.add_argument(
        "--port", type=int, help="port to probe (default: PORT, else 8090 and 8091)"
    )
    health.set_defaults(func=cmd_healthcheck)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result
