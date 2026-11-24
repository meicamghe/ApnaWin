"""Experimental UDPQ sidecar composed with the existing Xray/Wintun TUN engine.

This engine is deliberately not registered by the desktop composition root yet.
The caller must provide an explicit, validated UDPQ profile configuration.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Callable, Iterable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.apna_xray_config import build_apna_xray_tun_config
from apnawin.services.udpq_sidecar import UdpqClientConfig, UdpqSidecarSupervisor


def _xray_config_key(profile_name: str) -> str:
    digest = hashlib.sha256(profile_name.encode("utf-8")).hexdigest()[:32]
    return f"udpq-{digest}"


def _host_identity(host: str) -> str:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate.rstrip(".").casefold()


class UdpqTunnelEngine:
    """Compose the UDPQ SOCKS5 sidecar with the verified Xray/Wintun TUN path."""

    def __init__(
        self,
        sidecar: UdpqSidecarSupervisor,
        xray_engine,
        xray_config_store,
        config_resolver: Callable[[str], UdpqClientConfig],
        *,
        dns_servers: Iterable[str] = ("1.1.1.1", "2606:4700:4700::1111"),
        adapter_name: str = "ApnaWin UDPQ",
    ) -> None:
        if not callable(config_resolver):
            raise TypeError("config_resolver must be callable")
        self.sidecar = sidecar
        self.xray_engine = xray_engine
        self.xray_config_store = xray_config_store
        self.config_resolver = config_resolver
        self.dns_servers = tuple(dns_servers)
        self.adapter_name = adapter_name
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None
        self._xray_profile: ConnectionProfile | None = None
        self._candidate_profile: ConnectionProfile | None = None
        self._candidate_config: UdpqClientConfig | None = None
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "UDPQ / Hysteria-v1 sidecar + Xray TUN (experimental)"

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        return self._profile

    def _resolve_config(self, profile: ConnectionProfile) -> UdpqClientConfig:
        config = self.config_resolver(profile.name)
        if not isinstance(config, UdpqClientConfig):
            raise TypeError("UDPQ config resolver must return UdpqClientConfig")
        if (
            _host_identity(config.server_host) != _host_identity(profile.endpoint_host)
            or config.server_port != profile.endpoint_port
        ):
            raise ValueError("UDPQ config endpoint does not match the selected profile")
        return config

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.UDPQ:
            raise ValueError("UDPQ tunnel engine accepts UDPQ profiles only")
        if self._state is not ConnectionState.DISCONNECTED:
            raise RuntimeError("UDPQ tunnel engine is already active")
        if self.xray_engine.state is not ConnectionState.DISCONNECTED:
            raise RuntimeError("Xray/Wintun engine must be disconnected before UDPQ starts")
        config = self._resolve_config(profile)
        self._candidate_profile = profile
        self._candidate_config = config

    def connect(self, profile: ConnectionProfile) -> None:
        if self._state is not ConnectionState.DISCONNECTED:
            raise RuntimeError(
                f"Cannot start UDPQ while state is {self._state.value}; disconnect first"
            )
        if self._candidate_profile != profile or self._candidate_config is None:
            self.validate_profile(profile)
        config = self._candidate_config
        if config is None:
            raise RuntimeError("Validated UDPQ configuration is missing")

        self._state = ConnectionState.CONNECTING
        self.last_error = None
        self._profile = profile
        socks_address = (config.socks_host, config.socks_port)
        xray_profile = ConnectionProfile(
            name=_xray_config_key(profile.name),
            transport=Transport.XRAY,
            endpoint_host=config.socks_host,
            endpoint_port=config.socks_port,
        )
        self._xray_profile = xray_profile
        config_saved = False
        try:
            xray_config = build_apna_xray_tun_config(
                socks_address,
                dns_servers=self.dns_servers,
                adapter_name=self.adapter_name,
                description="ApnaWin UDPQ tunnel",
                outbound_tag="udpq-socks",
            )
            self.xray_config_store.save(xray_profile.name, xray_config)
            config_saved = True
            self.xray_engine.validate_profile(xray_profile)
            observed_socks = self.sidecar.start(config)
            if observed_socks != socks_address:
                raise RuntimeError("UDPQ sidecar exposed an unexpected SOCKS5 endpoint")
            self.xray_engine.connect(xray_profile)
            if self.xray_engine.state is not ConnectionState.CONNECTED:
                raise RuntimeError("Xray/Wintun did not confirm CONNECTED for UDPQ")
        except Exception as exc:
            cleanup_errors = []
            try:
                if self.xray_engine.state is not ConnectionState.DISCONNECTED:
                    self.xray_engine.disconnect()
            except Exception as cleanup_exc:
                cleanup_errors.append(f"Xray cleanup: {cleanup_exc}")
            if not cleanup_errors:
                try:
                    self.sidecar.stop()
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"UDPQ sidecar cleanup: {cleanup_exc}")
            if not cleanup_errors and config_saved:
                try:
                    self.xray_config_store.remove(xray_profile.name)
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"Xray config cleanup: {cleanup_exc}")
            self._state = ConnectionState.ERROR
            detail = f"{type(exc).__name__}: {exc}"
            if cleanup_errors:
                detail += "; " + "; ".join(cleanup_errors)
            self.last_error = detail
            if cleanup_errors:
                raise RuntimeError(
                    "UDPQ startup failed and cleanup is unconfirmed: " + detail
                ) from exc
            self._profile = None
            self._xray_profile = None
            self._candidate_profile = None
            self._candidate_config = None
            raise

        self._state = ConnectionState.CONNECTED
        self._candidate_profile = None
        self._candidate_config = None

    def refresh(self) -> ConnectionState:
        if self._state is not ConnectionState.CONNECTED:
            return self._state
        try:
            xray_state = self.xray_engine.refresh()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"Xray/Wintun health check failed: {exc}"
            return self._state
        if xray_state is not ConnectionState.CONNECTED:
            self._state = ConnectionState.ERROR
            self.last_error = f"Xray/Wintun tunnel state changed to {xray_state.value}"
        elif not self.sidecar.is_running:
            self._state = ConnectionState.ERROR
            self.last_error = "UDPQ sidecar exited while the TUN route was active"
        return self._state

    def disconnect(self) -> None:
        if self._state is ConnectionState.DISCONNECTED:
            self._candidate_profile = None
            self._candidate_config = None
            return
        self._state = ConnectionState.DISCONNECTING
        profile = self._profile or self._candidate_profile
        try:
            if self.xray_engine.state is not ConnectionState.DISCONNECTED:
                self.xray_engine.disconnect()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"Xray/Wintun cleanup failed; UDPQ sidecar retained: {exc}"
            raise RuntimeError(self.last_error) from exc
        try:
            self.sidecar.stop()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"UDPQ sidecar cleanup failed: {exc}"
            raise RuntimeError(self.last_error) from exc
        if profile is not None and self._xray_profile is not None:
            try:
                self.xray_config_store.remove(self._xray_profile.name)
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"UDPQ Xray config cleanup failed: {exc}"
                raise RuntimeError(self.last_error) from exc
        self._profile = None
        self._xray_profile = None
        self._candidate_profile = None
        self._candidate_config = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error = None
