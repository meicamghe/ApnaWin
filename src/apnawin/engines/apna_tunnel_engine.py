"""APNA SSH + UDPGW transport connected to the elevated Xray/Wintun TUN runtime."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
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
    """APNA SSH -> loopback SOCKS5/UDPGW -> Xray native Wintun TUN.

    APNA credentials are supplied by an encrypted profile loader. The generated
    Xray config uses a unique temporary profile key and has only the loopback
    SOCKS outbound; it cannot silently fall back to direct internet access.
    """

    def __init__(
        self,
        session_config_loader: Callable[[ConnectionProfile], ApnaTunnelSessionConfig],
        config_store: XrayConfigStore,
        xray_supervisor: XrayTunnelSupervisor,
        *,
        session_factory: Callable[..., ApnaTunnelSession] = ApnaTunnelSession,
        config_builder: Callable[..., bytes] = build_apna_xray_tun_config,
        platform_name: str | None = None,
    ) -> None:
        if not callable(session_config_loader):
            raise TypeError("session_config_loader must be callable")
        if (
            config_store is None
            or not callable(getattr(config_store, "save", None))
            or not callable(getattr(config_store, "remove", None))
        ):
            raise TypeError("config_store must provide save() and remove() operations")
        if xray_supervisor is None:
            raise TypeError("xray_supervisor is required")
        if not callable(session_factory) or not callable(config_builder):
            raise TypeError("session_factory and config_builder must be callable")

        self._session_config_loader = session_config_loader
        self._config_store = config_store
        self._xray_supervisor = xray_supervisor
        self._session_factory = session_factory
        self._config_builder = config_builder
        self._platform_name = os.name if platform_name is None else platform_name
        self._session: ApnaTunnelSession | None = None
        self._profile: ConnectionProfile | None = None
        self._validated_profile: ConnectionProfile | None = None
        self._validated_config: ApnaTunnelSessionConfig | None = None
        self._xray_profile: ConnectionProfile | None = None
        self._config_name: str | None = None
        self._xray_started = False
        self._state = ConnectionState.DISCONNECTED
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "APNA SSH + UDPGW + Xray/Wintun"

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

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.APNA_SSH:
            raise ValueError("APNA tunnel engine requires an APNA_SSH profile")
        if self._platform_name != "nt":
            raise OSError("APNA Xray/Wintun engine is available only on Windows")
        if self._state is not ConnectionState.DISCONNECTED or self._session is not None:
            raise ApnaTunnelEngineError("APNA tunnel engine already owns a session")

        config = self._session_config_loader(profile)
        if not isinstance(config, ApnaTunnelSessionConfig):
            raise TypeError("Secure profile loader returned an invalid APNA session config")
        if (
            config.ssh.ssh_host.casefold() != profile.endpoint_host.casefold()
            or config.ssh.ssh_port != profile.endpoint_port
        ):
            raise ValueError("APNA SSH endpoint does not match the selected profile")
        if config.udpgw_host is None or config.udpgw_port is None:
            raise ValueError(
                "Full-tunnel APNA requires a configured UDPGW endpoint; TCP-only mode is disabled"
            )
        default_known_hosts = Path.home() / ".ssh" / "known_hosts"
        if (
            config.ssh.host_key_sha256 is None
            and not config.ssh.known_hosts_files
            and not default_known_hosts.is_file()
        ):
            raise ValueError(
                "SSH host identity must be verified with a SHA-256 pin or known_hosts file"
            )
        self._validated_profile = profile
        self._validated_config = config

    def connect(self, profile: ConnectionProfile) -> None:
        if self._state is not ConnectionState.DISCONNECTED or self._session is not None:
            raise ApnaTunnelEngineError("APNA tunnel engine already owns a session")
        if self._validated_profile != profile or self._validated_config is None:
            self.validate_profile(profile)

        self._state = ConnectionState.CONNECTING
        self._profile = profile
        self.last_error = None
        session_config = self._validated_config
        self._validated_profile = None
        self._validated_config = None
        if session_config is None:
            self._state = ConnectionState.ERROR
            raise ApnaTunnelEngineError("APNA profile validation did not produce session settings")

        try:
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
            internal_name = f"__apnawin_apna_{uuid.uuid4().hex}"
            self._config_store.save(internal_name, raw_config)
            self._config_name = internal_name

            xray_profile = ConnectionProfile(
                internal_name,
                Transport.XRAY,
                local_socks[0],
                local_socks[1],
            )
            self._xray_profile = xray_profile
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
                    self._xray_profile = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not self._xray_started:
                self._xray_profile = None
            if not self._xray_started and self._session is not None:
                try:
                    self._session.disconnect()
                    self._session = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)
            if not self._xray_started and self._session is None and self._config_name is not None:
                try:
                    self._config_store.remove(self._config_name)
                    self._config_name = None
                except Exception as cleanup_exc:
                    cleanup_errors.append(cleanup_exc)

            resources_retained = (
                self._xray_started
                or self._session is not None
                or self._config_name is not None
            )
            self._state = ConnectionState.ERROR if cleanup_errors or resources_retained else ConnectionState.DISCONNECTED
            self.last_error = f"{type(exc).__name__}: {exc}"
            if self._state is ConnectionState.DISCONNECTED:
                self._profile = None
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
            self.last_error = f"Could not inspect Xray helper health: {exc}"
            raise ApnaTunnelEngineError(self.last_error) from exc
        if exit_code is not None:
            self._state = ConnectionState.ERROR
            self.last_error = f"Xray helper exited unexpectedly with code {exit_code}"
        return self._state

    def disconnect(self) -> None:
        if (
            self._state is ConnectionState.DISCONNECTED
            and self._session is None
            and not self._xray_started
            and self._config_name is None
        ):
            return

        self._state = ConnectionState.DISCONNECTING
        if self._xray_started:
            try:
                self._xray_supervisor.stop()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"Xray TUN cleanup failed; APNA SSH is retained: {exc}"
                raise ApnaTunnelEngineError(self.last_error) from exc
            self._xray_started = False
            self._xray_profile = None

        if self._session is not None:
            try:
                self._session.disconnect()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"APNA SSH/SOCKS cleanup failed; ownership is retained: {exc}"
                raise ApnaTunnelEngineError(self.last_error) from exc
            self._session = None

        if self._config_name is not None:
            try:
                self._config_store.remove(self._config_name)
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = (
                    f"Network resources are stopped but encrypted config cleanup failed: {exc}"
                )
                raise ApnaTunnelEngineError(self.last_error) from exc
            self._config_name = None

        self._profile = None
        self._validated_profile = None
        self._validated_config = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error = None
