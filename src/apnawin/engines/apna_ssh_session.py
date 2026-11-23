"""Authenticated SSH session with a loopback-only SOCKS5 TCP forwarder.

This is a lower transport component. It does not create a TUN interface or
carry UDP; UDPGW is a separate protocol path.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import math
import re
import socket
import socketserver
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import paramiko

from apnawin.engines.apna_ssh_diagnostics import ApnaDiagnosticTransport, cipher_diagnostic_suffix

from apnawin.engines.apna_payload_socket import (
    ApnaPayloadSocketConnector,
    PayloadSocketConfig,
)


class ApnaSshError(ConnectionError):
    """SSH authentication, host-key verification, or forwarding failed."""


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept an otherwise unknown host key only when its SHA-256 pin matches."""

    def __init__(self, expected_fingerprint: str) -> None:
        self._expected = expected_fingerprint

    def missing_host_key(self, client, hostname, key) -> None:
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii")
        actual = "SHA256:" + digest.rstrip("=")
        if not hmac.compare_digest(actual, self._expected):
            raise paramiko.SSHException(
                f"SSH host key fingerprint mismatch for {hostname}"
            )


@dataclass(frozen=True, slots=True)
class ApnaSshConfig:
    ssh_host: str
    ssh_port: int
    username: str
    password: str | None = field(default=None, repr=False)
    key_filename: str | None = None
    known_hosts_files: tuple[str, ...] = ()
    host_key_sha256: str | None = None
    local_host: str = "127.0.0.1"
    local_port: int = 0
    connect_timeout: float = 10.0
    auth_timeout: float = 15.0
    banner_timeout: float = 15.0

    def __post_init__(self) -> None:
        if not isinstance(self.ssh_host, str) or not self.ssh_host or len(self.ssh_host) > 253:
            raise ValueError("ssh_host is invalid")
        try:
            ipaddress.ip_address(self.ssh_host)
        except ValueError:
            if any(c.isspace() or ord(c) < 0x21 or ord(c) > 0x7E for c in self.ssh_host):
                raise ValueError("ssh_host must be an IP address or ASCII DNS name")
        if isinstance(self.ssh_port, bool) or not isinstance(self.ssh_port, int):
            raise TypeError("ssh_port must be an integer")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("ssh_port must be between 1 and 65535")
        if not isinstance(self.username, str) or not self.username or len(self.username) > 256:
            raise ValueError("username is invalid")
        if self.password is not None and not isinstance(self.password, str):
            raise TypeError("password must be text or None")
        if not self.password and not self.key_filename:
            raise ValueError("SSH password or private-key file is required")
        if self.key_filename is not None and not isinstance(self.key_filename, str):
            raise TypeError("key_filename must be text or None")
        if not isinstance(self.known_hosts_files, tuple):
            raise TypeError("known_hosts_files must be a tuple")
        if any(not isinstance(path, str) or not path for path in self.known_hosts_files):
            raise ValueError("known_hosts_files contains an invalid path")
        if self.host_key_sha256 is not None and (
            not isinstance(self.host_key_sha256, str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", self.host_key_sha256)
        ):
            raise ValueError("host_key_sha256 must be an OpenSSH SHA256 fingerprint")
        try:
            local = ipaddress.ip_address(self.local_host)
        except ValueError as exc:
            raise ValueError("local_host must be a loopback IP literal") from exc
        if not local.is_loopback:
            raise ValueError("SOCKS listener must bind to a loopback address")
        if isinstance(self.local_port, bool) or not isinstance(self.local_port, int):
            raise TypeError("local_port must be an integer")
        if not 0 <= self.local_port <= 65535:
            raise ValueError("local_port must be between 0 and 65535")
        for name in ("connect_timeout", "auth_timeout", "banner_timeout"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be finite and positive")


class _SocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        session: ApnaSshSession = self.server.session
        client = self.request
        channel = None
        try:
            version, method_count = _recv_exact(client, 2)
            if version != 5 or method_count == 0:
                return
            methods = _recv_exact(client, method_count)
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            version, command, reserved, address_type = _recv_exact(client, 4)
            if version != 5 or reserved != 0:
                _socks_reply(client, 1)
                return
            if command != 1:
                _socks_reply(client, 7)
                return
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, _recv_exact(client, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
            elif address_type == 3:
                length = _recv_exact(client, 1)[0]
                try:
                    host = _recv_exact(client, length).decode("idna")
                except UnicodeError:
                    _socks_reply(client, 8)
                    return
            else:
                _socks_reply(client, 8)
                return
            port = int.from_bytes(_recv_exact(client, 2), "big")
            if not host or port == 0:
                _socks_reply(client, 8)
                return

            transport = session._ssh_client.get_transport()
            if transport is None or not transport.is_active() or not transport.is_authenticated():
                _socks_reply(client, 1)
                return
            channel = transport.open_channel(
                "direct-tcpip",
                (host, port),
                client.getsockname(),
                timeout=session._channel_timeout,
            )
            if channel is None:
                _socks_reply(client, 1)
                return
            _socks_reply(client, 0)
            _relay_tcp(client, channel)
        except (OSError, EOFError, paramiko.SSHException):
            try:
                _socks_reply(client, 1)
            except OSError:
                pass
        finally:
            if channel is not None:
                channel.close()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("SOCKS client closed during handshake")
        result.extend(chunk)
    return bytes(result)


def _socks_reply(sock: socket.socket, code: int) -> None:
    # The bound address is intentionally the loopback endpoint, not the remote.
    sock.sendall(b"\x05" + bytes((code, 0, 1)) + b"\x00\x00\x00\x00\x00\x00")


def _relay_tcp(client: socket.socket, channel) -> None:
    remote_done = threading.Event()

    def channel_to_client() -> None:
        try:
            # A client-side TCP half-close must not stop this direction: the
            # remote SSH channel may still have a response to send.
            while True:
                data = channel.recv(32768)
                if not data:
                    break
                client.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            remote_done.set()
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    worker = threading.Thread(target=channel_to_client, daemon=True)
    worker.start()
    client.settimeout(0.5)
    try:
        while not remote_done.is_set():
            try:
                data = client.recv(32768)
            except socket.timeout:
                continue
            if not data:
                # Propagate FIN to the SSH channel, but keep receiving until
                # the remote side closes its own write direction.
                break
            channel.sendall(data)
    finally:
        try:
            channel.shutdown_write()
        except (OSError, EOFError):
            pass
        worker.join(timeout=2)


class _ThreadingSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class ApnaSshSession:
    """Own an authenticated SSH transport and a loopback SOCKS5 TCP endpoint."""

    def __init__(
        self,
        config: ApnaSshConfig,
        payload_config: PayloadSocketConfig,
        *,
        connector: ApnaPayloadSocketConnector | None = None,
        ssh_client_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
        channel_timeout: float = 10.0,
    ) -> None:
        self.config = config
        self.payload_config = payload_config
        if (
            isinstance(channel_timeout, bool)
            or not isinstance(channel_timeout, (int, float))
            or not math.isfinite(channel_timeout)
            or channel_timeout <= 0
        ):
            raise ValueError("channel_timeout must be finite and positive")
        self._connector = connector or ApnaPayloadSocketConnector()
        self._ssh_client_factory = ssh_client_factory
        self._channel_timeout = channel_timeout
        self._ssh_client: paramiko.SSHClient | None = None
        self._payload_socket: socket.socket | None = None
        self._server: _ThreadingSocksServer | None = None
        self._server_thread: threading.Thread | None = None
        self._closed = False

    @property
    def socks_address(self) -> tuple[str, int] | None:
        if self._server is None:
            return None
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def is_authenticated(self) -> bool:
        if self._ssh_client is None:
            return False
        transport = self._ssh_client.get_transport()
        return bool(transport and transport.is_active() and transport.is_authenticated())

    def connect(self) -> tuple[str, int]:
        if self._ssh_client is not None or self._server is not None:
            raise ApnaSshError("SSH session is already initialized")
        # A closed session object may be deliberately reused for reconnects.
        # Reset the close guard before acquiring new sockets/client resources.
        self._closed = False
        if (
            self.payload_config.target_host != self.config.ssh_host
            or self.payload_config.target_port != self.config.ssh_port
        ):
            raise ValueError("Payload target must match the SSH host and port")
        client = self._ssh_client_factory()
        sock = None
        server = None
        thread = None
        try:
            client.load_system_host_keys()
            for known_hosts in self.config.known_hosts_files:
                client.load_host_keys(str(Path(known_hosts)))
            if self.config.host_key_sha256 is None:
                # Unknown hosts are rejected unless the user supplied a known_hosts
                # entry or an explicit SHA-256 pin through the profile.
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(
                    _PinnedHostKeyPolicy(self.config.host_key_sha256)
                )
            sock = self._connector.connect(self.payload_config)
            client.connect(
                hostname=self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.username,
                password=self.config.password,
                key_filename=self.config.key_filename,
                sock=sock,
                timeout=self.config.connect_timeout,
                auth_timeout=self.config.auth_timeout,
                banner_timeout=self.config.banner_timeout,
                allow_agent=False,
                look_for_keys=False,
                transport_factory=ApnaDiagnosticTransport,
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active() or not transport.is_authenticated():
                raise ApnaSshError("SSH authentication did not complete")
            # Bind the listener before publishing any session-owned state.
            # If bind/start fails, the caller must be able to retry this object
            # without retaining a closed SSH client or payload socket.
            server = _ThreadingSocksServer(
                (self.config.local_host, self.config.local_port),
                _SocksHandler,
            )
            server.session = self
            self._ssh_client = client
            self._payload_socket = sock
            self._server = server
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._server_thread = thread
            thread.start()
            return self.socks_address
        except Exception as exc:
            self._ssh_client = None
            self._payload_socket = None
            self._server = None
            self._server_thread = None
            if server is not None:
                try:
                    if thread is not None and thread.is_alive():
                        server.shutdown()
                    server.server_close()
                    if thread is not None and thread.is_alive():
                        thread.join(timeout=2)
                except Exception:
                    # Cleanup is best-effort here: preserve the connection
                    # failure that caused rollback instead of masking it with
                    # a secondary server-shutdown exception.
                    pass
            try:
                client.close()
            except Exception:
                # A broken SSHClient.close() must not hide the original
                # authentication, host-key, or negotiation failure.
                pass
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    # Preserve the primary failure if socket cleanup also fails.
                    pass
            if isinstance(exc, (ApnaSshError, ValueError, TypeError)):
                raise
            if isinstance(exc, paramiko.BadHostKeyException):
                raise ApnaSshError(
                    "SSH host key does not match the previously trusted known_hosts entry"
                ) from exc
            if isinstance(exc, paramiko.AuthenticationException):
                raise ApnaSshError(
                    "SSH authentication was rejected; verify the username and provider-issued credentials"
                ) from exc
            if isinstance(exc, paramiko.SSHException):
                detail = " ".join(str(exc).split())[:240]
                lowered = detail.lower()
                if "not found in known_hosts" in lowered or "host key" in lowered:
                    raise ApnaSshError(
                        "SSH host identity could not be verified against known_hosts or the configured SHA-256 pin"
                    ) from exc
                if "no acceptable ciphers" in lowered:
                    raise ApnaSshError(
                        "SSH key exchange found no mutually supported encryption cipher. "
                        "The endpoint sent SSH negotiation data, but its offered ciphers do not "
                        "overlap with this client's secure cipher policy. No legacy cipher was "
                        "enabled automatically; use another provider-approved SSH endpoint or "
                        "review the server cipher offers below."
                        + cipher_diagnostic_suffix(exc)
                    ) from exc
                if "banner" in lowered:
                    raise ApnaSshError(
                        "SSH protocol banner was not received. The endpoint may not be serving SSH "
                        "on this route, the payload may not have opened an SSH stream, or the "
                        "provider may have closed or delayed the connection."
                    ) from exc
                raise ApnaSshError(
                    f"SSH protocol negotiation failed: {detail or type(exc).__name__}"
                ) from exc
            if isinstance(exc, (socket.timeout, TimeoutError)):
                raise ApnaSshError(
                    "SSH protocol banner, key exchange, or authentication timed out; "
                    "check endpoint responsiveness and the configured stage timeouts."
                ) from exc
            raise ApnaSshError(
                "SSH transport or authentication failed; host-key verification is enforced"
            ) from exc

    def open_direct_channel(
        self,
        destination_host: str,
        destination_port: int,
        *,
        source_host: str = "127.0.0.1",
        source_port: int = 0,
    ):
        """Open an authenticated SSH direct-tcpip channel (e.g. remote UDPGW)."""
        if not isinstance(destination_host, str) or not destination_host:
            raise ValueError("destination_host is required")
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in destination_host):
            raise ValueError("destination_host contains whitespace or control characters")
        for name, value in (("destination_port", destination_port), ("source_port", source_port)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            minimum = 1 if name == "destination_port" else 0
            if not minimum <= value <= 65535:
                raise ValueError(f"{name} is outside the valid port range")
        try:
            ipaddress.ip_address(source_host)
        except ValueError as exc:
            raise ValueError("source_host must be an IP literal") from exc
        if self._ssh_client is None or not self.is_authenticated:
            raise ApnaSshError("SSH session is not authenticated")
        transport = self._ssh_client.get_transport()
        try:
            channel = transport.open_channel(
                "direct-tcpip",
                (destination_host, destination_port),
                (source_host, source_port),
                timeout=self._channel_timeout,
            )
        except (OSError, paramiko.SSHException) as exc:
            raise ApnaSshError("Could not open SSH direct-tcpip channel") from exc
        if channel is None:
            raise ApnaSshError("SSH server refused the direct-tcpip channel")
        return channel

    def close(self) -> None:
        if (
            self._closed
            and self._server is None
            and self._ssh_client is None
            and self._payload_socket is None
        ):
            return

        # Do not discard ownership until each resource has actually closed.
        # A failed shutdown/close must remain retryable by the session owner.
        server = self._server
        if server is not None:
            server.shutdown()
            server.server_close()
            thread = self._server_thread
            if thread is not None:
                thread.join(timeout=2)
                if thread.is_alive():
                    raise ApnaSshError(
                        "SSH SOCKS listener thread did not stop; resource ownership is retained"
                    )
            self._server = None
            self._server_thread = None

        client = self._ssh_client
        if client is not None:
            client.close()
            self._ssh_client = None

        payload_socket = self._payload_socket
        if payload_socket is not None:
            try:
                payload_socket.close()
            except OSError as exc:
                raise ApnaSshError(
                    "SSH payload socket cleanup failed; resource ownership is retained"
                ) from exc
            self._payload_socket = None

        self._closed = True

    def __enter__(self) -> ApnaSshSession:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
