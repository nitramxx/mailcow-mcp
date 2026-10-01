"""TLS client contexts.

Inside mailcow the app connects to container names (``dovecot-mailcow``), but the
certificate is issued for the mailcow hostname. ``client_context(server_name=...)``
verifies the certificate against that name whatever host is dialled.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any


class _FixedNameContext(ssl.SSLContext):
    """Always verifies the peer certificate against ``fixed_server_name``."""

    fixed_server_name: str

    def wrap_socket(self, sock: socket.socket, *args: Any, **kwargs: Any) -> ssl.SSLSocket:
        kwargs["server_hostname"] = self.fixed_server_name
        return super().wrap_socket(sock, *args, **kwargs)

    def wrap_bio(
        self, incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO, *args: Any, **kwargs: Any
    ) -> ssl.SSLObject:
        kwargs["server_hostname"] = self.fixed_server_name
        return super().wrap_bio(incoming, outgoing, *args, **kwargs)


def client_context(
    *, server_name: str | None, verify: bool = True, ca_file: Path | None = None
) -> ssl.SSLContext:
    """A TLS 1.2+ client context; ``server_name`` overrides the name verified.

    ``ca_file`` adds a private CA to the system trust store.
    """
    context: ssl.SSLContext
    if server_name:
        context = _FixedNameContext(ssl.PROTOCOL_TLS_CLIENT)
        context.fixed_server_name = server_name
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        context.load_default_certs()
        if ca_file is not None:
            context.load_verify_locations(cafile=str(ca_file))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
