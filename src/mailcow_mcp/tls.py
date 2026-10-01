"""TLS client contexts.

Inside mailcow the app connects to container names (``dovecot-mailcow``), but the
certificate is issued for the mailcow hostname. ``client_context(server_name=...)``
verifies the certificate against that name whatever host is dialled.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path


class _FixedNameContext(ssl.SSLContext):
    """Always verifies the peer certificate against ``fixed_server_name``."""

    fixed_server_name: str

    def wrap_socket(  # type: ignore[override]
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLSocket:
        return super().wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=self.fixed_server_name,
            session=session,
        )

    def wrap_bio(  # type: ignore[override]
        self,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLObject:
        return super().wrap_bio(
            incoming,
            outgoing,
            server_side=server_side,
            server_hostname=self.fixed_server_name,
            session=session,
        )


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
