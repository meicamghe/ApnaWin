"""Compose the APNA SSH/UDPGW user-mode transport with Xray's Wintun TUN.

Xray owns Windows routes, DNS and WFP leak protection. The only Xray outbound
is the loopback SOCKS5 gateway, so a failed APNA proxy cannot fall back to
direct internet access.
"""
from __future__ import annotations

import os
import uuid
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.apna_tunnel_session import (
    ApnaTunnelSession,
    ApnaTunnelSessionConfig,
)
from apnawin.engines.apna_xray_config import (
    ApnaXrayTunConfig,
    build_apna_xray_tun_config,
)


class ApnaWindowsTunnelError(RuntimeError):
    """APNA Windows tunnel startup, supervision or cleanup failed."""


class ApnaWindowsTunnelEngine:
    """A real composite engine: SSH + UDPGW + loopback SOCKS5 + Xray/Wintun."""

    def __init__(
        self,
        *,
        session_config_provider: Callable[[ConnectionProfile], ApnaTunnelSessionConfig],
        config_store,
        xray_engine,
        session_factory: Callable[..., ApnaTunnelSession] = ApnaTunnelSession,
        tun_config_provider: Callable[
            [ConnectionProfile, ApnaTunnelSessionConfig], ApnaXrayTunConfig
        ] | None = None,
        platform_name: str | None = None,
    ) -> None:
        if not callable(session_config_provider):
            raise TypeError("session_config_provider must be callable")
        if config_store is None or not callable(getattr(config_store, "save", None)):
            raise TypeError("config_store must provide save/remove/has_config")
        if xray_engine is None:
            raise TypeError("xray_engine is required")
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")
        if tun_config_provider is not None and not callable(tun_config_provider):
            raise TypeError("tun_config_provider must be callable")
        self._session_config_provider = session_config_provider
        self._config_store = config_store
        self._xray_engine = xray_engine
        self._session_factory = session_factory
        self._tun_config_provider = tun_config_provider
        self._platform_name = os.name if platform_name is None else platform_name
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None
        self._session_config: ApnaTunnelSessionConfig | None = None
        self._session: ApnaTunnelSession | None = None
        self._xray_profile: ConnectionProfile | None = None
        self._config_name: str | None = None
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "APNA SSH + UDPGW over Xray/Wintun"

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        return self._profile

    @property
    def local_socks_address(self) -> tuple[str, int] | None:
        if self._session is None:
            return None
        return self._session.local_socks_address

    def _load_session_config(self, profile: ConnectionProfile) -> ApnaTunnelSessionConfig:
        config = self._session_config_provider(profile)
        if not isinstance(config, ApnaTunnelSessionConfig):
            raise TypeError("session_config_provider must return ApnaTunnelSessionConfig")
        if (
            config.ssh.ssh_host.casefold() != profile.endpoint_host.casefold()
            or config.ssh.ssh_port != profile.endpoint_port
        ):
            raise ValueError("APNA profile endpoint does not match its SSH session configuration")
        if config.udpgw_host is None or config.udpgw_port is None:
            raise ValueError(
                "Full-tunnel APNA mode requires a verified UDPGW endpoint; TCP-only mode is not enabled"
            )
        return config

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.APNA_SSH:
            raise ValueError("APNA Windows engine accepts APNA_SSH profiles only")
        if self._platform_name != "nt":
            raise OSError("APNA Xray/Wintun engine is available only on Windows")
        if self._state not in {ConnectionState.DISCONNECTED, ConnectionState.ERROR}:
            raise RuntimeError(f"Cannot validate APNA profile while state is {self._state.value}")
        self._session_config = self._load_session_config(profile)

    def _make_tun_config(
        self,
        profile: ConnectionProfile,
        session_config: ApnaTunnelSessionConfig,
    ) -> ApnaXrayTunConfig:
        if self._tun_config_provider is not None:
            tun = self._tun_config_provider(profile, session_config)
            if not isinstance(tun, ApnaXrayTunConfig):
                raise TypeError("tun_config_provider must return ApnaXrayTunConfig")
            return tun
        dns = (
            (session_config.dns_resolver,)
            if session_config.dns_resolver is not None
            else ("1.1.1.1",)
        )
        return ApnaXrayTunConfig(dns_servers=dns)

    def connect(self, profile: ConnectionProfile) -> None:
        if self._state not in {ConnectionState.DISCONNECTED}:
            raise RuntimeError(f"Cannot start APNA tunnel while state is {self._state.value}")
        self._state = ConnectionState.CONNECTING
        self._profile = profile
        self.last_error = None
        session = None
        xray_started = False
        try:
            session_config = self._session_config or self._load_session_config(profile)
            self._session_config = None
            session = self._session_factory(session_config)
            self._session = session
            socks_address = session.connect()
            tun_config = self._make_tun_config(profile, session_config)
            config_bytes = build_apna_xray_tun_config(socks_address, tun=tun_config)

            internal_name = f"__apnawin_apna_{uuid.uuid4().hex}"
            self._config_store.save(internal_name, config_bytes)
            self._config_name = internal_name
            xray_profile = ConnectionProfile(
                name=internal_name,
                transport=Transport.XRAY,
                endpoint_host=socks_address[0],
                endpoint_port=socks_address[1],
            )
            self._xray_profile = xray_profile
            self._xray_engine.validate_profile(xray_profile)
            self._xray_engine.connect(xray_profile)
            xray_started = self._xray_engine.state is not ConnectionState.DISCONNECTED
            if self._xray_engine.state is not ConnectionState.CONNECTED:
                raise ApnaWindowsTunnelError(
                    "Xray/Wintun did not confirm a connected full-tunnel state"
                )
            self._state = ConnectionState.CONNECTED
        except Exception as exc:
            cleanup_errors = []
            if self._xray_profile is not None:
                try:
                    self._xray_engine.disconnect()
                    xray_started = False
                    self._xray_profile = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not xray_started and self._xray_profile is None and self._config_name is not None:
                try:
                    self._config_store.remove(self._config_name)
                    self._config_name = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not xray_started and self._xray_profile is None and self._session is not None:
                try:
                    self._session.disconnect()
                    self._session = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            self._state = ConnectionState.ERROR
            self.last_error = f"{type(exc).__name__}: {exc}"
            if cleanup_errors:
                raise ApnaWindowsTunnelError(
                    f"APNA tunnel startup failed: {exc}; cleanup also failed: "
                    + "; ".join(str(item) for item in cleanup_errors)
                ) from exc
            raise

    def refresh(self) -> ConnectionState:
        if self._state is ConnectionState.CONNECTED:
            try:
                observed = self._xray_engine.refresh()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"Xray/Wintun supervision failed: {exc}"
                raise ApnaWindowsTunnelError(self.last_error) from exc
            if observed is not ConnectionState.CONNECTED:
                self._state = ConnectionState.ERROR
                self.last_error = getattr(
                    self._xray_engine,
                    "last_error",
                    "Xray/Wintun stopped unexpectedly; APNA transport ownership is retained",
                )
        return self._state

    def disconnect(self) -> None:
        self._state = ConnectionState.DISCONNECTING
        if self._xray_profile is not None:
            try:
                self._xray_engine.disconnect()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = (
                    "Xray/Wintun cleanup failed; APNA SOCKS/SSH resources are retained: "
                    f"{exc}"
                )
                raise ApnaWindowsTunnelError(self.last_error) from exc
            self._xray_profile = None

        cleanup_errors = []
        if self._config_name is not None:
            try:
                self._config_store.remove(self._config_name)
                self._config_name = None
            except Exception as exc:
                cleanup_errors.append(exc)

        if self._session is not None:
            try:
                self._session.disconnect()
                self._session = None
            except Exception as exc:
                cleanup_errors.append(exc)

        if cleanup_errors:
            self._state = ConnectionState.ERROR
            self.last_error = "APNA cleanup incomplete: " + "; ".join(
                str(item) for item in cleanup_errors
            )
            raise ApnaWindowsTunnelError(self.last_error)

        self._profile = None
        self._session_config = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error = None
