"""Command-line entry point: ``mailcow-mcp <command>``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
import urllib.request
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from mailcow_mcp import __version__
from mailcow_mcp.config import (
    DEFAULT_APP_PORT,
    DEFAULT_BROKER_PORT,
    ConfigError,
    generate_key,
    load_app_config,
    load_broker_config,
)
from mailcow_mcp.web import create_app

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


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        config = load_app_config()
    except ConfigError as exc:
        return _fail(str(exc))
    if error := _check_data_dir(config.data_dir):
        return _fail(error)
    _setup_logging()
    if not config.tls_verify:
        log.warning("TLS_VERIFY=false: mail server certificates are not verified")
    log.info("starting app %s in %s mode on port %d", __version__, config.mode, config.port)
    uvicorn.run(
        create_app("app"),
        host="0.0.0.0",  # noqa: S104 - runs in a container; nginx is the only route in
        port=config.port,
        proxy_headers=True,
        forwarded_allow_ips=list(config.trusted_proxies),
        server_header=False,
        log_config=None,
    )
    return 0


def cmd_broker(args: argparse.Namespace) -> int:
    try:
        config = load_broker_config()
    except ConfigError as exc:
        return _fail(str(exc))
    if error := _check_data_dir(config.data_dir):
        return _fail(error)
    _setup_logging()
    if not config.tls_verify:
        log.warning("TLS_VERIFY=false: the mailcow API certificate is not verified")
    log.info("starting broker %s on port %d", __version__, config.port)
    uvicorn.run(
        create_app("broker"),
        host="0.0.0.0",  # noqa: S104 - internal network only, never published
        port=config.port,
        proxy_headers=False,
        server_header=False,
        log_config=None,
    )
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
    for port in ports:
        try:
            url = f"http://127.0.0.1:{port}/healthz"
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
