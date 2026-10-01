"""Encryption at rest and token helpers."""

from __future__ import annotations

import hashlib
import secrets

from cryptography.fernet import Fernet


class Box:
    """Encrypts short secrets (passwords, capability tokens) with ENC_KEY."""

    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")


def new_secret(prefix: str = "") -> str:
    """A random URL-safe secret with 256 bits of entropy."""
    return prefix + secrets.token_urlsafe(32)


def hash_secret(value: str) -> str:
    """Lookup hash for a high-entropy secret (tokens, codes); not for passwords."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
