"""The mailcow deployment kit, with Docker: setup script, compose file, nginx site file.

Needs the image built locally as mailcow-mcp:kit-test (CI's kit job builds it; locally the
fixture builds it). Marked ``kit``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from mailserver_fixture import make_certificates

pytestmark = [pytest.mark.integration, pytest.mark.kit]

ROOT = Path(__file__).parent.parent
KIT = ROOT / "deploy" / "mailcow"
IMAGE = "ghcr.io/nitramxx/mailcow-mcp"
TAG = "kit-test"


def run(
    *args: str, check: bool = True, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args), capture_output=True, text=True, cwd=cwd, env=env, check=False
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )
    return result


@dataclass
class FakeMailcow:
    directory: Path
    kit: Path
    network: str
    project: str
    subnet: str

    @property
    def compose_env(self) -> dict[str, str]:
        return {**os.environ, "COMPOSE_PROJECT_NAME": f"mailcow-mcp-{self.project}"}


@pytest.fixture(scope="module")
def image() -> str:
    if not os.environ.get("MCP_KIT_TESTS"):
        pytest.skip("set MCP_KIT_TESTS=1 to run the deployment kit tests (they build the image)")
    if (
        shutil.which("docker") is None
        or run("docker", "compose", "version", check=False).returncode != 0
    ):
        pytest.skip("Docker with the compose plugin is not available")
    if not os.environ.get("CI"):  # CI builds it in an earlier step
        run("docker", "build", "-q", "-t", f"{IMAGE}:{TAG}", str(ROOT))
    return f"{IMAGE}:{TAG}"


@pytest.fixture(scope="module")
def fake_mailcow(tmp_path_factory: pytest.TempPathFactory, image: str) -> Iterator[FakeMailcow]:
    base = tmp_path_factory.mktemp("kit")
    directory = base / "mailcow-dockerized"
    (directory / "data" / "conf" / "nginx").mkdir(parents=True)
    project = f"kit{uuid.uuid4().hex[:6]}"
    octet = 100 + int(uuid.uuid4().hex[:2], 16) % 100
    subnet = f"172.30.{octet}"
    (directory / "mailcow.conf").write_text(
        f"MAILCOW_HOSTNAME=mail.test\nCOMPOSE_PROJECT_NAME={project}\nIPV4_NETWORK={subnet}\n"
        "HTTPS_PORT=443\nENABLE_IPV6=false\nADDITIONAL_SAN=\n"
    )
    kit = base / "mailcow-mcp"
    kit.mkdir()
    for name in ("docker-compose.yml", "mailcow-mcp.conf.template", "setup-mailcow.sh"):
        shutil.copy2(KIT / name, kit / name)
    network = f"{project}_mailcow-network"
    # Dual-stack, like mailcow with IPv6 enabled.
    v6 = f"fd00:{octet:x}:{uuid.uuid4().hex[:4]}::/64"
    run(
        "docker",
        "network",
        "create",
        "--ipv6",
        "--subnet",
        f"{subnet}.0/24",
        "--subnet",
        v6,
        network,
    )
    fake = FakeMailcow(directory, kit, network, project, subnet)
    try:
        yield fake
    finally:
        run(
            "docker",
            "compose",
            "down",
            "-v",
            "--remove-orphans",
            check=False,
            cwd=kit,
            env=fake.compose_env,
        )
        run("docker", "network", "rm", network, check=False)


def setup(fake: FakeMailcow, *extra: str, kit: Path | None = None) -> str:
    return run(
        "bash",
        str((kit or fake.kit) / "setup-mailcow.sh"),
        "--mailcow-dir",
        str(fake.directory),
        "--hostname",
        "mcp.test",
        "--version",
        TAG,
        *extra,
    ).stdout


def test_setup_is_read_only_by_default(fake_mailcow: FakeMailcow, tmp_path: Path) -> None:
    kit = tmp_path / "kit"  # a fresh one: other tests apply the shared kit
    shutil.copytree(KIT, kit)
    site = fake_mailcow.directory / "data/conf/nginx/mailcow-mcp.conf"
    before = site.read_bytes() if site.exists() else None
    out = setup(fake_mailcow, kit=kit)
    assert "Nothing was written" in out
    assert not (kit / "app.env").exists()
    assert (site.read_bytes() if site.exists() else None) == before
    assert f"{fake_mailcow.subnet}.231" in out
    assert "https://mcp.test/oauth/mailcow/callback" in out
    assert "ADDITIONAL_SAN=mcp.test" in out


def test_apply_writes_config_and_keeps_keys(fake_mailcow: FakeMailcow) -> None:
    setup(
        fake_mailcow,
        "--oauth-client-id",
        "abc123",
        "--oauth-client-secret",
        "s3cret",
        "--api-key",
        "KEY-1",
        "--apply",
    )
    app_env = (fake_mailcow.kit / "app.env").read_text()
    broker_env = (fake_mailcow.kit / "broker.env").read_text()
    assert "MODE=mailcow" in app_env and "PUBLIC_URL=https://mcp.test" in app_env
    assert f"TRUSTED_PROXIES={fake_mailcow.subnet}.0/24" in app_env
    secret = next(line for line in app_env.splitlines() if line.startswith("BROKER_SHARED_SECRET="))
    assert secret in broker_env
    assert oct((fake_mailcow.kit / "app.env").stat().st_mode)[-3:] == "600"
    site = (fake_mailcow.directory / "data/conf/nginx/mailcow-mcp.conf").read_text()
    assert "server_name mcp.test;" in site and "listen 443 ssl;" in site and "[::]" not in site
    # Running again keeps the keys.
    setup(fake_mailcow, "--apply")
    assert (fake_mailcow.kit / "app.env").read_text() == app_env
    # A setting added later is appended on its own line, even without a final newline.
    stripped = "\n".join(line for line in app_env.splitlines() if not line.startswith("TIMEZONE="))
    (fake_mailcow.kit / "app.env").write_text(stripped)  # no trailing newline
    try:
        setup(fake_mailcow, "--apply")
        lines = (fake_mailcow.kit / "app.env").read_text().splitlines()
        assert "TIMEZONE=UTC" in lines
        assert lines[lines.index("TIMEZONE=UTC") - 1] == stripped.splitlines()[-1]
    finally:
        (fake_mailcow.kit / "app.env").write_text(app_env)  # later tests share this kit


@pytest.fixture(scope="module")
def applied(fake_mailcow: FakeMailcow) -> FakeMailcow:
    if not (fake_mailcow.kit / "app.env").exists():
        setup(
            fake_mailcow,
            "--oauth-client-id",
            "abc123",
            "--oauth-client-secret",
            "s3cret",
            "--api-key",
            "KEY-1",
            "--apply",
        )
    return fake_mailcow


def test_compose_file_is_valid(applied: FakeMailcow) -> None:
    config = run("docker", "compose", "config", cwd=applied.kit).stdout
    assert "read_only: true" in config
    assert "no-new-privileges:true" in config
    assert "internal: true" in config


def _curl(container: str, url: str, host: str = "mcp.test") -> str:
    return run(
        "docker",
        "exec",
        container,
        "sh",
        "-c",
        f"wget -q -S -O - --no-check-certificate --header='Host: {host}' {url} 2>&1 || true",
    ).stdout


@pytest.fixture(scope="module")
def nginx(applied: FakeMailcow, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    certs = tmp_path_factory.mktemp("kit-certs")
    make_certificates(certs)
    name = f"{applied.project}-nginx"
    run("docker", "rm", "-f", name, check=False)
    run("docker", "create", "--name", name, "--network", applied.network, "nginx:1.27-alpine")
    run(
        "docker",
        "cp",
        str(applied.directory / "data/conf/nginx/mailcow-mcp.conf"),
        f"{name}:/etc/nginx/conf.d/mailcow-mcp.conf",
    )
    staging = certs / "mail"
    staging.mkdir()
    shutil.copy(certs / "server.crt", staging / "cert.pem")
    shutil.copy(certs / "server.key", staging / "key.pem")
    run("docker", "cp", str(staging), f"{name}:/etc/ssl/mail")
    run("docker", "start", name)
    try:
        yield name
    finally:
        run("docker", "rm", "-f", name, check=False)


def test_nginx_starts_while_mailcow_mcp_is_down(nginx: str) -> None:
    assert run("docker", "exec", nginx, "nginx", "-t").returncode == 0
    time.sleep(1)
    assert "502" in _curl(nginx, "https://127.0.0.1/healthz")


def test_containers_are_healthy_and_isolated(applied: FakeMailcow, nginx: str) -> None:
    env = applied.compose_env
    run("docker", "compose", "up", "-d", cwd=applied.kit, env=env)
    deadline = time.monotonic() + 90
    while True:
        ps = run(
            "docker",
            "compose",
            "ps",
            "--format",
            "{{.Service}} {{.Health}}",
            cwd=applied.kit,
            env=env,
        ).stdout
        if ps.count("healthy") >= 2 and "unhealthy" not in ps:
            break
        if time.monotonic() > deadline:
            logs = run("docker", "compose", "logs", cwd=applied.kit, env=env, check=False).stdout
            raise AssertionError(f"containers not healthy:\n{ps}\n{logs}")
        time.sleep(2)

    # Through mailcow's nginx: the app answers, and reaches the broker.
    health = _curl(nginx, "https://127.0.0.1/healthz")
    assert '"role":"app"' in health and '"broker":"ok"' in health
    # The broker isn't reachable from mailcow's network...
    broker_ip = next(
        line.split("=")[1]
        for line in (applied.kit / ".env").read_text().splitlines()
        if line.startswith("BROKER_IP=")
    )
    blocked = run(
        "docker",
        "exec",
        nginx,
        "sh",
        "-c",
        f"wget -q -T 3 -O - http://{broker_ip}:8091/healthz 2>&1 || echo refused",
    ).stdout
    assert "refused" in blocked
    # ...but is from the app, over the internal network.
    app = run("docker", "compose", "ps", "-q", "app", cwd=applied.kit, env=env).stdout.strip()
    reached = run(
        "docker",
        "exec",
        app,
        "python",
        "-c",
        "import urllib.request; print(urllib.request.urlopen('http://mcp-broker:8091/healthz', timeout=5).read().decode())",
    ).stdout
    assert '"role":"broker"' in reached
    # IPv4 only, so mailcow's allowlists (which name the fixed IPv4 addresses) apply.
    for service in ("app", "broker"):
        container = run(
            "docker", "compose", "ps", "-q", service, cwd=applied.kit, env=env
        ).stdout.strip()
        ipv6 = run("docker", "exec", container, "cat", "/proc/net/if_inet6").stdout.strip()
        assert ipv6 == "", f"{service} has IPv6 addresses: {ipv6}"
    # Hardening as configured.
    inspect = run(
        "docker",
        "inspect",
        app,
        "-f",
        "{{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.CapDrop}}",
    ).stdout
    assert inspect.split()[0] == "true" and inspect.split()[1] == "10001:10001" and "ALL" in inspect
    run("docker", "compose", "down", cwd=applied.kit, env=env)


FAKE_MAILCOW_COMPOSE = """
services:
  mysql-mailcow:
    image: mariadb:11
    environment:
      MARIADB_ROOT_PASSWORD: root
      MARIADB_DATABASE: mailcow
      MARIADB_USER: mailcow
      MARIADB_PASSWORD: dbpass
  redis-mailcow:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "redispass"]
"""


def test_setup_checks_mailcow_state(tmp_path: Path, image: str) -> None:
    """Steps 2-5 are read from mailcow (certificate, database, Redis); credentials filled in."""
    project = f"kitdb{uuid.uuid4().hex[:6]}"
    subnet = f"172.30.{200 + int(uuid.uuid4().hex[:2], 16) % 50}"
    directory = tmp_path / "mailcow-dockerized"
    (directory / "data" / "conf" / "nginx").mkdir(parents=True)
    ssl_dir = directory / "data" / "assets" / "ssl"
    ssl_dir.mkdir(parents=True)
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "30",
        "-subj",
        "/CN=mail.test",
        "-addext",
        "subjectAltName=DNS:mail.test,DNS:mcp.test",
        "-keyout",
        str(ssl_dir / "key.pem"),
        "-out",
        str(ssl_dir / "cert.pem"),
    )
    (directory / "mailcow.conf").write_text(
        f"MAILCOW_HOSTNAME=mail.test\nCOMPOSE_PROJECT_NAME={project}\nIPV4_NETWORK={subnet}\n"
        "HTTPS_PORT=443\nENABLE_IPV6=false\nADDITIONAL_SAN=mcp.test\n"
        "DBNAME=mailcow\nDBUSER=mailcow\nDBPASS=dbpass\nREDISPASS=redispass\n"
    )
    (directory / "docker-compose.yml").write_text(FAKE_MAILCOW_COMPOSE)
    (directory / ".env").symlink_to("mailcow.conf")  # as in mailcow-dockerized
    kit = tmp_path / "mailcow-mcp"
    kit.mkdir()
    for name in ("docker-compose.yml", "mailcow-mcp.conf.template", "setup-mailcow.sh"):
        shutil.copy2(KIT / name, kit / name)
    network = f"{project}_mailcow-network"
    compose = dict(os.environ)  # the project name comes from .env → mailcow.conf, as in mailcow
    run("docker", "network", "create", "--subnet", f"{subnet}.0/24", network)
    try:
        run("docker", "compose", "up", "-d", "--wait", cwd=directory, env=compose)
        seed = (
            "CREATE TABLE oauth_clients (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(80), "
            "client_secret VARCHAR(80), redirect_uri VARCHAR(2000), grant_types VARCHAR(80), scope VARCHAR(4000), "
            "user_id VARCHAR(80));"
            "INSERT INTO oauth_clients (client_id, client_secret, redirect_uri) VALUES "
            "('other0000000', 'x', 'https://cloud.test/apps/oauth'), "
            "('abcdef123456', 'secret0123456789abcdef01', 'https://mcp.test/oauth/mailcow/callback');"
            "CREATE TABLE api (api_key VARCHAR(255) PRIMARY KEY, allow_from VARCHAR(512), skip_ip_check TINYINT(1), "
            "access ENUM('ro','rw'), active TINYINT(1));"
            f"INSERT INTO api VALUES ('RO-KEY', '', 0, 'ro', 1), ('RW-KEY-FROM-DB', '10.0.0.5\\n{subnet}.0/24', 0, 'rw', 1);"
        )
        for _ in range(30):
            done = run(
                "docker",
                "compose",
                "exec",
                "-T",
                "-e",
                "MYSQL_PWD=dbpass",
                "mysql-mailcow",
                "mariadb",
                "-umailcow",
                "mailcow",
                "-e",
                seed,
                cwd=directory,
                env=compose,
                check=False,
            )
            if done.returncode == 0:
                break
            time.sleep(2)
        assert done.returncode == 0, done.stderr
        run(
            "docker",
            "compose",
            "exec",
            "-T",
            "-e",
            "REDISCLI_AUTH=redispass",
            "redis-mailcow",
            "redis-cli",
            "HSET",
            "F2B_WHITELIST",
            f"{subnet}.231",
            "1",
            cwd=directory,
            env=compose,
        )

        out = run(
            "bash",
            str(kit / "setup-mailcow.sh"),
            "--mailcow-dir",
            str(directory),
            "--hostname",
            "mcp.test",
            "--version",
            TAG,
            "--apply",
            env=compose,
        ).stdout
        for step in ("2", "4", "5", "6", "7"):
            assert f"✓ {step}." in out, out
        assert "OAuth2 Apps" not in out and "Fail2ban parameters" not in out
        app_env = (kit / "app.env").read_text()
        assert "MAILCOW_OAUTH_CLIENT_ID=abcdef123456" in app_env
        assert "MAILCOW_OAUTH_CLIENT_SECRET=secret0123456789abcdef01" in app_env
        assert "MAILCOW_API_KEY=RW-KEY-FROM-DB" in (kit / "broker.env").read_text()
    finally:
        run("docker", "compose", "down", "-v", cwd=directory, env=compose, check=False)
        run("docker", "network", "rm", network, check=False)


def _serve_releases(root: Path) -> Iterator[str]:
    import functools
    import http.server
    import threading

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _release(root: Path, version: str, *, extra_line: str = "", bad_checksum: bool = False) -> None:
    """A release like release.yml builds it, under <root>/download/v<version>/."""
    import hashlib
    import tarfile

    staging = root / f"staging-{version}"
    shutil.copytree(KIT, staging)
    (staging / "VERSION").write_text(f"{version}\n")
    if extra_line:
        compose = staging / "docker-compose.yml"
        compose.write_text(compose.read_text() + f"\n# {extra_line}\n")
    target = root / "download" / f"v{version}"
    target.mkdir(parents=True)
    archive = target / "mailcow-kit.tar.gz"

    def as_root(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    with tarfile.open(archive, "w:gz") as tar:
        for path in sorted(staging.iterdir()):
            tar.add(path, arcname=path.name, filter=as_root)  # no "./" entries, like release.yml
    digest = "0" * 64 if bad_checksum else hashlib.sha256(archive.read_bytes()).hexdigest()
    (target / "mailcow-kit.tar.gz.sha256").write_text(f"{digest}  mailcow-kit.tar.gz\n")


@pytest.fixture
def restored_kit(applied: FakeMailcow) -> Iterator[FakeMailcow]:
    """The shared kit, put back as it was after the test (update rewrites it)."""
    saved = {p: p.read_bytes() for p in applied.kit.iterdir() if p.is_file()}
    try:
        yield applied
    finally:
        for path in applied.kit.iterdir():
            if path.is_file() and path not in saved:
                path.unlink()
        for path, content in saved.items():
            path.write_bytes(content)


def test_update_installs_a_release_kit(restored_kit: FakeMailcow, tmp_path: Path) -> None:
    applied = restored_kit
    _release(tmp_path, "9.9.9", extra_line="new in 9.9.9")
    _release(tmp_path, "6.6.6", bad_checksum=True)
    app_env = (applied.kit / "app.env").read_text()
    broker_env = (applied.kit / "broker.env").read_text()
    for base in _serve_releases(tmp_path):
        env = {**applied.compose_env, "MCP_KIT_BASE_URL": base}
        bad = run(
            "bash",
            str(applied.kit / "setup-mailcow.sh"),
            "update",
            "6.6.6",
            "--no-restart",
            env=env,
            check=False,
        )
        assert bad.returncode != 0 and "checksum mismatch" in bad.stderr
        assert not (applied.kit / "VERSION").exists()

        out = run(
            "bash",
            str(applied.kit / "setup-mailcow.sh"),
            "update",
            "v9.9.9",
            "--no-restart",
            env=env,
        ).stdout
    assert "kit unknown → 9.9.9" in out
    assert "+# new in 9.9.9" in out  # the change is shown
    assert (applied.kit / "VERSION").read_text().strip() == "9.9.9"
    assert "# new in 9.9.9" in (applied.kit / "docker-compose.yml").read_text()
    dotenv = (applied.kit / ".env").read_text()
    assert "MCP_VERSION=9.9.9" in dotenv and f"MAILCOW_DIR={applied.directory}" in dotenv
    # Settings and keys are untouched; the setup ran again with the remembered hostname.
    assert (applied.kit / "app.env").read_text() == app_env
    assert (applied.kit / "broker.env").read_text() == broker_env
    assert "MCP URL:        https://mcp.test/mcp" in out
    assert "checks" in out
