"""APNA SSH + SOCKS5 + UDPGW session orchestration.

This is the user-mode transport layer. It exposes a loopback SOCKS5 endpoint
for a later Windows TUN adapter; it does not itself install routes or create a
TUN interface.
"""
from __future__ import annotations

import ipaddress
import math
import socket
from dataclasses import dataclass
from typing import Callable

from apnawin.engines.apna_payload_socket import PayloadSocketConfig
from apnawin.engines.apna_ssh_session import ApnaSshConfig, ApnaSshSession
from apnawin.engines.socks5_gateway import Socks5Gateway, Socks5GatewayConfig
from apnawin.engines.udpgw_stream import (
    Socks5ConnectConfig,
    open_socks5_connect,
)


class ApnaTunnelSessionError(ConnectionError):
    """APNA transport startup, preflight, or cleanup failed."""


@dataclass(frozen=True, slots=True)
class ApnaTunnelSessionConfig:
    ssh: ApnaSshConfig
    payload: PayloadSocketConfig
    udpgw_host: str | None = None
    udpgw_port: int | None = None
    transparent_dns: bool = False
    dns_resolver: str | None = None
    max_udp_flows: int = 256
    keepalive_interval: float = 25.0
    udp_idle_timeout: float = 120.0
    connect_timeout: float = 10.0

    def __post_init__(self) -> None:
        if not isinstance(self.ssh, ApnaSshConfig):
            raise TypeError("ssh must be an ApnaSshConfig")
        if not isinstance(self.payload, PayloadSocketConfig):
            raise TypeError("payload must be a PayloadSocketConfig")
        if (self.udpgw_host is None) != (self.udpgw_port is None):
            raise ValueError("udpgw_host and udpgw_port must be supplied together")
        if self.udpgw_host is not None:
            if (
                not isinstance(self.udpgw_host, str)
                or not self.udpgw_host
                or len(self.udpgw_host) > 253
                or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.udpgw_host)
            ):
                raise ValueError("udpgw_host is invalid")
            if (
                isinstance(self.udpgw_port, bool)
                or not isinstance(self.udpgw_port, int)
                or not 1 <= self.udpgw_port <= 65535
            ):
                raise ValueError("udpgw_port must be between 1 and 65535")
        if not isinstance(self.transparent_dns, bool):
            raise TypeError("transparent_dns must be a boolean")
        if self.dns_resolver is not None:
            try:
                ipaddress.ip_address(self.dns_resolver)
            except ValueError as exc:
                raise ValueError("dns_resolver must be an IPv4 or IPv6 literal") from exc
        if self.transparent_dns and self.udpgw_host is None:
            raise ValueError("transparent DNS requires a UDPGW endpoint")
        if isinstance(self.max_udp_flows, bool) or not isinstance(self.max_udp_flows, int):
            raise TypeError("max_udp_flows must be an integer")
        if not 1 <= self.max_udp_flows <= 65535:
            raise ValueError("max_udp_flows must be between 1 and 65535")
        for name in ("keepalive_interval", "udp_idle_timeout", "connect_timeout"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a finite positive number")


class ApnaTunnelSession:
    """Own SSH authentication, UDPGW preflight and the local SOCKS5 gateway."""

    def __init__(
        self,
        config: ApnaTunnelSessionConfig,
        *,
        ssh_session_factory: Callable[..., ApnaSshSession] = ApnaSshSession,
        gateway_factory: Callable[..., Socks5Gateway] = Socks5Gateway,
        preflight_connector: Callable[..., socket.socket] = open_socks5_connect,
    ) -> None:
        if not isinstance(config, ApnaTunnelSessionConfig):
            raise TypeError("config must be an ApnaTunnelSessionConfig")
        self.config = config
        self._ssh_session_factory = ssh_session_factory
        self._gateway_factory = gateway_factory
        self._preflight_connector = preflight_connector
        self._ssh_session: ApnaSshSession | None = None
        self._gateway: Socks5Gateway | None = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def local_socks_address(self) -> tuple[str, int] | None:
        if not self._connected or self._gateway is None:
            return None
        return self._gateway.address

    def connect(self) -> tuple[str, int]:
        if self._ssh_session is not None or self._gateway is not None:
            raise ApnaTunnelSessionError("APNA tunnel session is already initialized")

        ssh_session = self._ssh_session_factory(self.config.ssh, self.config.payload)
        self._ssh_session = ssh_session
        gateway = None
        try:
            ssh_host, ssh_port = ssh_session.connect()
            try:
                if not ipaddress.ip_address(ssh_host).is_loopback:
                    raise ApnaTunnelSessionError("SSH SOCKS endpoint is not loopback-only")
            except ValueError as exc:
                raise ApnaTunnelSessionError("SSH SOCKS endpoint is not an IP literal") from exc

            if self.config.udpgw_host is not None:
                probe = self._preflight_connector(
                    Socks5ConnectConfig(
                        proxy_host=ssh_host,
                        proxy_port=ssh_port,
                        target_host=self.config.udpgw_host,
                        target_port=self.config.udpgw_port,
                        timeout=self.config.connect_timeout,
                    )
                )
                probe.close()

            gateway_config = Socks5GatewayConfig(
                ssh_proxy_host=ssh_host,
                ssh_proxy_port=ssh_port,
                udpgw_host=self.config.udpgw_host,
                udpgw_port=self.config.udpgw_port,
                transparent_dns=self.config.transparent_dns,
                dns_resolver=self.config.dns_resolver,
                max_udp_flows=self.config.max_udp_flows,
                keepalive_interval=self.config.keepalive_interval,
                udp_idle_timeout=self.config.udp_idle_timeout,
                connect_timeout=self.config.connect_timeout,
            )
            gateway = self._gateway_factory(gateway_config)
            self._gateway = gateway
            gateway.start()
            address = gateway.address
            if not ipaddress.ip_address(address[0]).is_loopback or not 1 <= address[1] <= 65535:
                raise ApnaTunnelSessionError("Local SOCKS5 gateway did not bind to loopback")
            self._connected = True
            return address
        except Exception as exc:
            cleanup_errors = []
            if gateway is not None:
                try:
                    gateway.close()
                    self._gateway = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            # Keep SSH alive if the gateway could not be closed; a listener
            # that remains bound may still depend on its upstream transport.
            if self._gateway is None and self._ssh_session is not None:
                try:
                    ssh_session.close()
                    self._ssh_session = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            self._connected = False
            if cleanup_errors:
                raise ApnaTunnelSessionError(
                    f"APNA transport startup failed: {exc}; cleanup also failed: "
                    + "; ".join(str(item) for item in cleanup_errors)
                ) from exc
            if isinstance(exc, (ValueError, TypeError, ApnaTunnelSessionError)):
                raise
            raise ApnaTunnelSessionError(f"APNA transport startup failed: {exc}") from exc

    def disconnect(self) -> None:
        # Retain the owner of any resource whose close operation failed so the
        # caller can retry cleanup instead of silently losing the handle.
        gateway = self._gateway
        if gateway is not None:
            try:
                gateway.close()
            except Exception as exc:
                self._connected = False
                raise ApnaTunnelSessionError(
                    f"APNA SOCKS5 gateway cleanup failed; SSH ownership is retained: {exc}"
                ) from exc
            self._gateway = None

        ssh_session = self._ssh_session
        if ssh_session is not None:
            try:
                ssh_session.close()
            except Exception as exc:
                self._connected = False
                raise ApnaTunnelSessionError(
                    f"APNA SSH cleanup failed; SSH ownership is retained: {exc}"
                ) from exc
            self._ssh_session = None

        self._connected = False

    def __enter__(self) -> ApnaTunnelSession:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.disconnect()
