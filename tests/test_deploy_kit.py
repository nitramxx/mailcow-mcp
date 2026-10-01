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
        pytest.skip("set MCP_KIT_TESTS=1 to run the deployment kit tests (work in progress)")
    if (
        shutil.which("docker") is None
        or run("docker", "compose", "version", check=False).returncode != 0
    ):
        pytest.skip("Docker with the compose plugin is not available")
    if run("docker", "image", "inspect", f"{IMAGE}:{TAG}", check=False).returncode != 0:
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
    run("docker", "network", "create", "--subnet", f"{subnet}.0/24", network)
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


def setup(fake: FakeMailcow, *extra: str) -> str:
    return run(
        "bash",
        str(fake.kit / "setup-mailcow.sh"),
        "--mailcow-dir",
        str(fake.directory),
        "--hostname",
        "mcp.test",
        "--version",
        TAG,
        *extra,
    ).stdout


def test_setup_is_read_only_by_default(fake_mailcow: FakeMailcow) -> None:
    out = setup(fake_mailcow)
    assert "Nothing was written" in out
    assert not (fake_mailcow.kit / "app.env").exists()
    assert not (fake_mailcow.directory / "data/conf/nginx/mailcow-mcp.conf").exists()
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

    # Through mailcow's nginx: the app answers.
    assert '"role":"app"' in _curl(nginx, "https://127.0.0.1/healthz")
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
        "import urllib.request; print(urllib.request.urlopen('http://broker:8091/healthz', timeout=5).read().decode())",
    ).stdout
    assert '"role":"broker"' in reached
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
