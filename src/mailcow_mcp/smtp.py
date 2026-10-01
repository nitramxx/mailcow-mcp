"""SMTP submission. Always over TLS, always authenticated.

Inside mailcow, Postfix may trust the app container's network and accept mail
without authentication. We never rely on that: if the server doesn't offer AUTH
after TLS, nothing is sent.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Sequence
from dataclasses import dataclass

import aiosmtplib

from mailcow_mcp.config import AppConfig, Security
from mailcow_mcp.errors import CredentialsRejected, MailError, SendRejected, ServerUnavailable
from mailcow_mcp.tls import client_context

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class SendResult:
    accepted: list[str]
    refused: dict[str, str]  # recipient → server response


def _response(exc: aiosmtplib.SMTPResponseException) -> str:
    return f"{exc.code} {exc.message}".strip()


class SmtpSender:
    def __init__(self, config: AppConfig) -> None:
        self.host = config.smtp_host
        self.port = config.smtp_port
        self.security = config.smtp_security
        self.context = client_context(
            server_name=config.tls_server_name, verify=config.tls_verify, ca_file=config.tls_ca_file
        )

    async def send(
        self,
        username: str,
        password: str,
        *,
        envelope_from: str,
        recipients: Sequence[str],
        message: bytes,
    ) -> SendResult:
        smtp = aiosmtplib.SMTP(
            hostname=self.host,
            port=self.port,
            use_tls=self.security is Security.SSL,
            start_tls=self.security is Security.STARTTLS,
            tls_context=self.context,
            timeout=TIMEOUT_SECONDS,
        )
        try:
            await smtp.connect()
        except (aiosmtplib.SMTPException, OSError, ssl.SSLError) as exc:
            log.warning("SMTP connection to %s:%d failed: %s", self.host, self.port, exc)
            raise ServerUnavailable("The outgoing mail server") from exc
        try:
            # STARTTLS resets the server's extension list; ask again over TLS.
            await smtp.ehlo()
            if not smtp.supports_extension("auth"):
                raise MailError(
                    "The outgoing mail server doesn't offer authentication, so nothing was sent."
                )
            try:
                await smtp.login(username, password)
            except aiosmtplib.SMTPAuthenticationError as exc:
                raise CredentialsRejected() from exc
            except (aiosmtplib.SMTPNotSupported, aiosmtplib.SMTPException) as exc:
                if isinstance(exc, aiosmtplib.SMTPServerDisconnected):
                    raise
                raise MailError(
                    "The outgoing mail server offers no usable authentication method, so "
                    "nothing was sent."
                ) from exc
            try:
                refused, _ = await smtp.sendmail(envelope_from, list(recipients), message)
            except aiosmtplib.SMTPSenderRefused as exc:
                raise SendRejected(
                    f"The mail server refused to send from {envelope_from}: {_response(exc)}"
                ) from exc
            except aiosmtplib.SMTPRecipientsRefused as exc:
                responses = [_response(e) for e in exc.recipients]
                # Postfix applies the sender ACL at RCPT time (smtpd_delay_reject).
                if responses and all("sender address rejected" in r.lower() for r in responses):
                    raise SendRejected(
                        f"The mail server refused to send from {envelope_from}: {responses[0]}"
                    ) from exc
                details = "; ".join(f"{e.recipient}: {_response(e)}" for e in exc.recipients)
                raise SendRejected(f"The mail server refused every recipient: {details}") from exc
            except aiosmtplib.SMTPDataError as exc:
                raise SendRejected(
                    f"The mail server refused the message: {_response(exc)}"
                ) from exc
            except aiosmtplib.SMTPResponseException as exc:
                raise SendRejected(
                    f"The mail server refused the message: {_response(exc)}"
                ) from exc
        except (aiosmtplib.SMTPServerDisconnected, aiosmtplib.SMTPTimeoutError, OSError) as exc:
            raise ServerUnavailable("The outgoing mail server") from exc
        finally:
            try:
                await smtp.quit()
            except (aiosmtplib.SMTPException, OSError):
                smtp.close()
        refused_text = {rcpt: f"{resp.code} {resp.message}" for rcpt, resp in refused.items()}
        accepted = [r for r in recipients if r not in refused]
        return SendResult(accepted=accepted, refused=refused_text)
