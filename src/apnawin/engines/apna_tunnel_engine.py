"""APNA SSH transport connected to the existing elevated Xray/Wintun TUN runtime."""
from __future__ import annotations

import json
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.apna_tunnel_session import (
    ApnaTunnelSession,
    ApnaTunnelSessionConfig,
)
from apnawin.engines.apna_xray_config import build_apna_xray_tun_config
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor
from apnawin.storage.xray_config_store import XrayConfigStore


class ApnaTunnelEngineError(RuntimeError):
    """APNA SSH/TUN engine startup, health or cleanup failure."""


class ApnaTunnelEngine:
    """A real engine adapter: APNA SSH -> SOCKS/UDPGW -> Xray native TUN.

    Profile credentials/configuration are supplied by an injected secure loader;
    this class never persists SSH passwords or private keys itself. Xray's
    generated TUN config is stored using the existing current-user DPAPI store.
    """

    def __init__(
        self,
        session_config_loader: Callable[[ConnectionProfile], ApnaTunnelSessionConfig],
        config_store: XrayConfigStore,
        xray_supervisor: XrayTunnelSupervisor,
        *,
        session_factory: Callable[..., ApnaTunnelSession] = ApnaTunnelSession,
        config_builder: Callable[..., bytes] = build_apna_xray_tun_config,
    ) -> None:
        if not callable(session_config_loader):
            raise TypeError("session_config_loader must be callable")
        if not isinstance(config_store, XrayConfigStore):
            raise TypeError("config_store must be an XrayConfigStore")
        if xray_supervisor is None:
            raise TypeError("xray_supervisor is required")
        self._session_config_loader = session_config_loader
        self._config_store = config_store
        self._xray_supervisor = xray_supervisor
        self._session_factory = session_factory
        self._config_builder = config_builder
        self._session: ApnaTunnelSession | None = None
        self._profile: ConnectionProfile | None = None
        self._xray_started = False
        self._config_saved = False
        self._state = ConnectionState.DISCONNECTED

    @property
    def name(self) -> str:
        return "APNA SSH + Xray/Wintun"

    @property
    def state(self) -> ConnectionState:
        return self._state

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.APNA_SSH:
            raise ValueError("APNA tunnel engine requires an APNA_SSH profile")

    def connect(self, profile: ConnectionProfile) -> None:
        self.validate_profile(profile)
        if self._state is not ConnectionState.DISCONNECTED or self._session is not None:
            raise ApnaTunnelEngineError("APNA tunnel engine already owns a session")

        self._state = ConnectionState.CONNECTING
        self._profile = profile
        try:
            session_config = self._session_config_loader(profile)
            if not isinstance(session_config, ApnaTunnelSessionConfig):
                raise TypeError("Secure profile loader returned an invalid APNA session config")
            if (
                session_config.ssh.ssh_host != profile.endpoint_host
                or session_config.ssh.ssh_port != profile.endpoint_port
            ):
                raise ValueError("APNA SSH endpoint does not match the selected profile")

            session = self._session_factory(session_config)
            self._session = session
            local_socks = session.connect()
            dns_servers = (
                (session_config.dns_resolver,)
                if session_config.dns_resolver is not None
                else ("1.1.1.1", "2606:4700:4700::1111")
            )
            raw_config = self._config_builder(
                local_socks,
                dns_servers=dns_servers,
            )
            self._config_store.save(profile.name, raw_config)
            self._config_saved = True

            # The supervisor is transport-agnostic at runtime and currently
            # validates only XRAY. This internal profile represents the local
            # generated Xray TUN config; the public profile remains APNA_SSH.
            xray_profile = ConnectionProfile(
                profile.name,
                Transport.XRAY,
                local_socks[0],
                local_socks[1],
            )
            self._xray_supervisor.start(xray_profile)
            self._xray_started = True
            if self._xray_supervisor.poll() is not None:
                raise ApnaTunnelEngineError("Xray helper exited before tunnel readiness")
            self._state = ConnectionState.CONNECTED
        except Exception as exc:
            cleanup_errors = []
            if self._xray_started:
                try:
                    self._xray_supervisor.stop()
                    self._xray_started = False
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not self._xray_started and self._session is not None:
                try:
                    self._session.disconnect()
                    self._session = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not self._xray_started and self._session is None and self._config_saved:
                try:
                    self._config_store.remove(profile.name)
                    self._config_saved = False
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            self._state = (
                ConnectionState.ERROR if cleanup_errors or self._session is not None
                else ConnectionState.DISCONNECTED
            )
            if cleanup_errors:
                raise ApnaTunnelEngineError(
                    f"APNA tunnel startup failed: {exc}; cleanup also failed: "
                    + "; ".join(str(item) for item in cleanup_errors)
                ) from exc
            if isinstance(exc, (ValueError, TypeError, ApnaTunnelEngineError)):
                raise
            raise ApnaTunnelEngineError(f"APNA tunnel startup failed: {exc}") from exc

    def refresh(self) -> ConnectionState:
        if self._state is not ConnectionState.CONNECTED:
            return self._state
        try:
            exit_code = self._xray_supervisor.poll()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            raise ApnaTunnelEngineError(f"Could not inspect Xray helper health: {exc}") from exc
        if exit_code is not None:
            self._state = ConnectionState.ERROR
        return self._state

    def disconnect(self) -> None:
        if (
            self._state is ConnectionState.DISCONNECTED
            and self._session is None
            and not self._xray_started
            and not self._config_saved
        ):
            return

        self._state = ConnectionState.DISCONNECTING
        if self._xray_started:
            try:
                self._xray_supervisor.stop()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                raise ApnaTunnelEngineError(
                    f"Xray TUN cleanup failed; APNA SSH is retained: {exc}"
                ) from exc
            self._xray_started = False

        if self._session is not None:
            try:
                self._session.disconnect()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                raise ApnaTunnelEngineError(
                    f"APNA SSH/SOCKS cleanup failed; ownership is retained: {exc}"
                ) from exc
            self._session = None

        if self._config_saved and self._profile is not None:
            try:
                self._config_store.remove(self._profile.name)
            except Exception as exc:
                self._state = ConnectionState.ERROR
                raise ApnaTunnelEngineError(
                    f"Network resources are stopped but encrypted config cleanup failed: {exc}"
                ) from exc
            self._config_saved = False

        self._profile = None
        self._state = ConnectionState.DISCONNECTED
