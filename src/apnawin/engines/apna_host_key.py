"""SSH host-key fingerprint discovery through an APNA payload transport."""
from __future__ import annotations

import base64
import hashlib
from typing import Callable

import paramiko

from apnawin.engines.apna_payload_socket import ApnaPayloadSocketConnector
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig


class ApnaHostKeyProbeError(RuntimeError):
    """The selected APNA endpoint did not complete an SSH key exchange."""


def scan_apna_ssh_host_key(
    config: ApnaTunnelSessionConfig,
    *,
    connector: ApnaPayloadSocketConnector | None = None,
    transport_factory: Callable = paramiko.Transport,
) -> str:
    """Retrieve the server key without authenticating and return OpenSSH SHA-256 form.

    The fingerprint is untrusted until the user compares it with an independently
    published provider fingerprint. This helper never silently trusts or stores it.
    """
    if not isinstance(config, ApnaTunnelSessionConfig):
        raise TypeError("config must be an ApnaTunnelSessionConfig")
    if not callable(transport_factory):
        raise TypeError("transport_factory must be callable")
    active_connector = connector or ApnaPayloadSocketConnector()
    sock = None
    transport = None
    try:
        sock = active_connector.connect(config.payload)
        transport = transport_factory(sock)
        transport.start_client(timeout=config.ssh.connect_timeout)
        key = transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        fingerprint = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{fingerprint}"
    except Exception as exc:
        raise ApnaHostKeyProbeError(
            f"SSH host-key exchange failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        try:
            if transport is not None:
                transport.close()
        finally:
            if sock is not None:
                sock.close()
