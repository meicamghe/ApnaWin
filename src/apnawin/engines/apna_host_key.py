"""SSH host-key fingerprint discovery through an APNA payload transport."""
from __future__ import annotations

import base64
import hashlib
from typing import Callable

import paramiko

from apnawin.engines.apna_ssh_diagnostics import ApnaDiagnosticTransport, cipher_diagnostic_suffix

from apnawin.engines.apna_payload_socket import ApnaPayloadSocketConnector, PayloadTransportError
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig


class ApnaHostKeyProbeError(RuntimeError):
    """An SSH host-key probe failed during its SSH negotiation stage."""

    def __init__(self, message: str, *, stage: str = "ssh_key_exchange") -> None:
        super().__init__(message)
        self.stage = stage


class ApnaPayloadTransportProbeError(ApnaHostKeyProbeError):
    """DNS, TCP, TLS, HTTP proxy or WebSocket setup failed before SSH began."""

    def __init__(self, message: str) -> None:
        super().__init__(message, stage="payload_transport")


def scan_apna_ssh_host_key(
    config: ApnaTunnelSessionConfig,
    *,
    connector: ApnaPayloadSocketConnector | None = None,
    transport_factory: Callable | None = None,
) -> str:
    """Retrieve the server key without authenticating and return OpenSSH SHA-256 form.

    The fingerprint is untrusted until the user compares it with an independently
    published provider fingerprint. This helper never silently trusts or stores it.
    """
    if not isinstance(config, ApnaTunnelSessionConfig):
        raise TypeError("config must be an ApnaTunnelSessionConfig")
    if transport_factory is not None and not callable(transport_factory):
        raise TypeError("transport_factory must be callable")
    active_connector = connector or ApnaPayloadSocketConnector()
    sock = None
    transport = None
    try:
        sock = active_connector.connect(config.payload)
        transport = (transport_factory or ApnaDiagnosticTransport)(sock)
        transport.start_client(timeout=config.ssh.connect_timeout)
        key = transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        fingerprint = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{fingerprint}"
    except Exception as exc:
        raw_detail = " ".join(str(exc).split())
        # PayloadTransportError already contains bounded, redacted diagnostics
        # (HTTP status, safe response headers, request route, Host and SNI).
        # Preserve enough of it for CloudFront/DNS/TLS triage; other exception
        # text remains tightly capped because it may contain provider data.
        detail = raw_detail[:1600] if isinstance(exc, PayloadTransportError) else raw_detail[:240]
        if isinstance(exc, PayloadTransportError):
            message = f"Payload transport failed before SSH key exchange: {detail}"
        elif isinstance(exc, paramiko.SSHException) and "no acceptable ciphers" in detail.lower():
            message = (
                "SSH key exchange found no mutually supported encryption cipher. "
                "The endpoint sent SSH negotiation data, but its offered ciphers do not "
                "overlap with this client's secure cipher policy. No legacy cipher was "
                "enabled automatically; use another provider-approved SSH endpoint or "
                "review the server cipher offers below."
                + cipher_diagnostic_suffix(exc)
            )
        else:
            message = f"SSH host-key exchange failed: {type(exc).__name__}: {detail}"
        error_type = (
            ApnaPayloadTransportProbeError
            if isinstance(exc, PayloadTransportError)
            else ApnaHostKeyProbeError
        )
        raise error_type(message) from exc
    finally:
        try:
            if transport is not None:
                transport.close()
        finally:
            if sock is not None:
                sock.close()
