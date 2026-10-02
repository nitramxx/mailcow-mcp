"""A real Dovecot + Postfix server in Docker, for integration tests.

Tests that use the ``mailserver`` fixture are marked ``integration``; they're
skipped when Docker isn't available. The server certificate is issued by a test
CA for ``mail.test``, so tests also exercise TLS_SERVER_NAME and TLS_CA_FILE.
"""

from __future__ import annotations

import datetime
import imaplib
import os
import shutil
import smtplib
import ssl
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

IMAGE = "mailcow-mcp-test-mailserver"
SERVER_NAME = "mail.test"
CONTEXT_DIR = Path(__file__).parent / "mailserver"

ALICE = ("alice@example.test", "alice-password")
BOB = ("bob@example.test", "bob-password")
ALICE_ALIAS = "sales@example.test"


@dataclass(frozen=True)
class MailServer:
    container: str
    imaps_port: int
    imap_port: int
    submission_port: int
    submissions_port: int
    ca_file: Path
    _app_passwords: tuple[tuple[str, str], ...] = ()

    def env(self, **overrides: str) -> dict[str, str]:
        """App settings (generic mode) pointing at this server."""
        env = {
            "IMAP_HOST": "127.0.0.1",
            "IMAP_PORT": str(self.imaps_port),
            "IMAP_SECURITY": "ssl",
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": str(self.submission_port),
            "SMTP_SECURITY": "starttls",
            "TLS_SERVER_NAME": SERVER_NAME,
            "TLS_CA_FILE": str(self.ca_file),
        }
        env.update(overrides)
        return env

    def imap(self, user: tuple[str, str] = ALICE) -> imaplib.IMAP4_SSL:
        """A plain imaplib connection for checking results independently."""
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.check_hostname = False
        conn = imaplib.IMAP4_SSL("127.0.0.1", self.imaps_port, ssl_context=context)
        conn.login(*user)
        return conn

    def set_app_password(self, user: str, password: str | None) -> None:
        """Make an app password valid for IMAP/SMTP (None removes it)."""
        lines = dict(self._app_passwords)
        if password is None:
            lines.pop(user, None)
        else:
            lines[user] = password
        object.__setattr__(self, "_app_passwords", tuple(lines.items()))
        content = "".join(f"{u}:{{PLAIN}}{p}\n" for u, p in lines.items())
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                self.container,
                "sh",
                "-c",
                "cat > /etc/dovecot/app-passwords",
            ],
            input=content.encode(),
            check=True,
            capture_output=True,
        )
        # Dovecot notices passwd-file changes by mtime, at one-second resolution.
        time.sleep(1.1)

    def logs(self) -> str:
        return subprocess.run(
            ["docker", "logs", self.container], capture_output=True, text=True, check=False
        ).stdout


def make_certificates(directory: Path) -> Path:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mailcow-mcp test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (directory / "ca.crt").write_bytes(ca.public_bytes(pem))
    (directory / "server.crt").write_bytes(cert.public_bytes(pem))
    (directory / "server.key").write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    for path in directory.iterdir():
        path.chmod(0o644)
    return directory / "ca.crt"


def _smtp_ready(port: int, ca_file: Path, *, implicit_tls: bool) -> None:
    context = ssl.create_default_context(cafile=str(ca_file))
    context.check_hostname = False
    if implicit_tls:
        with smtplib.SMTP_SSL("127.0.0.1", port, timeout=5, context=context) as smtp:
            smtp.noop()
    else:
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            smtp.starttls(context=context)
            smtp.noop()


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


def _port(container: str, port: int) -> int:
    out = subprocess.run(
        ["docker", "port", container, f"{port}/tcp"], capture_output=True, text=True, check=True
    ).stdout
    return int(out.splitlines()[0].rsplit(":", 1)[1])


@pytest.fixture(scope="session")
def mailserver(tmp_path_factory: pytest.TempPathFactory) -> Iterator[MailServer]:
    if not _docker_available():
        if os.environ.get("CI"):
            pytest.fail("Docker is required for the integration tests in CI")
        pytest.skip("Docker is not available")
    certs = tmp_path_factory.mktemp("certs")
    ca_file = make_certificates(certs)
    subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, str(CONTEXT_DIR)], check=True, capture_output=True
    )
    name = f"mailcow-mcp-test-{uuid.uuid4().hex[:8]}"
    ports = [
        "-p",
        "127.0.0.1::143",
        "-p",
        "127.0.0.1::993",
        "-p",
        "127.0.0.1::587",
        "-p",
        "127.0.0.1::465",
    ]
    # Copied in rather than bind-mounted: Docker VMs (Colima, Docker Desktop)
    # don't share temporary directories.
    subprocess.run(
        ["docker", "create", "--rm", "--name", name, *ports, IMAGE], check=True, capture_output=True
    )
    try:
        subprocess.run(
            ["docker", "cp", f"{certs}/.", f"{name}:/certs"], check=True, capture_output=True
        )
        subprocess.run(["docker", "start", name], check=True, capture_output=True)
        server = MailServer(
            container=name,
            imaps_port=_port(name, 993),
            imap_port=_port(name, 143),
            submission_port=_port(name, 587),
            submissions_port=_port(name, 465),
            ca_file=ca_file,
        )
        deadline = time.monotonic() + 60
        while True:
            try:
                server.imap().logout()
                # Postfix starts after Dovecot: wait for submission too.
                _smtp_ready(server.submission_port, ca_file, implicit_tls=False)
                _smtp_ready(server.submissions_port, ca_file, implicit_tls=True)
                break
            except (OSError, imaplib.IMAP4.error, smtplib.SMTPException):
                if time.monotonic() > deadline:
                    raise RuntimeError(
                        "test mail server did not start:\n" + server.logs()
                    ) from None
                time.sleep(0.5)
        yield server
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
