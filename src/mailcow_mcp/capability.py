"""Capability tokens: the broker's proof of which mailbox a request is for.

Issued by the broker at provisioning, signed with BROKER_SIGNING_KEY (which only
the broker has). The app stores them encrypted and presents them for every
later operation; the broker acts only for the mailbox inside. A token is valid
only while the broker's own records say its app password is active.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

PREFIX = "cap1"


class InvalidCapability(Exception):
    pass


@dataclass(frozen=True)
class Capability:
    mailbox: str
    app_password_id: int
    issued_at: int


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class CapabilitySigner:
    def __init__(self, signing_key: str) -> None:
        # The key is a Fernet-format key: 32 random bytes, URL-safe base64.
        # Derive a dedicated HMAC key so the raw key is used for nothing else.
        self._key = hmac.new(
            base64.urlsafe_b64decode(signing_key), b"mailcow-mcp capability v1", hashlib.sha256
        ).digest()

    def _signature(self, payload: str) -> str:
        return _b64(hmac.new(self._key, f"{PREFIX}.{payload}".encode(), hashlib.sha256).digest())

    def issue(self, mailbox: str, app_password_id: int, now: float | None = None) -> str:
        payload = _b64(
            json.dumps(
                {"sub": mailbox, "apid": app_password_id, "iat": int(now or time.time())},
                separators=(",", ":"),
            ).encode()
        )
        return f"{PREFIX}.{payload}.{self._signature(payload)}"

    def verify(self, token: str) -> Capability:
        if not isinstance(token, str) or len(token) > 2048:
            raise InvalidCapability("malformed")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise InvalidCapability("malformed")
        _, payload, signature = parts
        if not signature.isascii() or not hmac.compare_digest(
            signature.encode(), self._signature(payload).encode()
        ):
            raise InvalidCapability("bad signature")
        try:
            data = json.loads(_unb64(payload))
            return Capability(
                mailbox=str(data["sub"]),
                app_password_id=int(data["apid"]),
                issued_at=int(data["iat"]),
            )
        except (binascii.Error, ValueError, KeyError, TypeError) as exc:
            raise InvalidCapability("malformed payload") from exc
