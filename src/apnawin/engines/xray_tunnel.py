"""Real Xray/Wintun adapter for the desktop connection lifecycle."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.services.vpn_runtime import verify_vpn_runtime
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor


class XrayTunnelEngine:
    """Drive the elevated helper; CONNECTED means its TUN and egress checks passed."""

    def __init__(
        self,
        supervisor: XrayTunnelSupervisor,
        helper_path: str | Path,
        config_store,
        *,
        runtime_dir: str | Path | None = None,
        runtime_verifier: Callable[[str | Path], dict] = verify_vpn_runtime,
        platform_name: str | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.helper_path = Path(helper_path)
        self.config_store = config_store
        self.runtime_dir = Path(runtime_dir) if runtime_dir else self.helper_path.parent / "engine"
        self._runtime_verifier = runtime_verifier
        self._platform_name = os.name if platform_name is None else platform_name
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "Xray TUN (Wintun)"

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        return self._profile

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.XRAY:
            raise ValueError("The Windows TUN engine accepts XRAY profiles only")
        if self._platform_name != "nt":
            raise OSError("The Xray TUN engine is available only on Windows")
        if self.helper_path.is_symlink() or not self.helper_path.is_file():
            raise FileNotFoundError("The installed ApnaWin elevated helper is missing or unsafe")
        self._runtime_verifier(self.runtime_dir)
        if not self.config_store.has_config(profile.name):
            raise ValueError("Import a validated Xray TUN config for this profile first")

    def connect(self, profile: ConnectionProfile) -> None:
        if self._state not in {ConnectionState.DISCONNECTED, ConnectionState.ERROR}:
            raise RuntimeError(f"Cannot start Xray while state is {self._state.value}")
        self._state = ConnectionState.CONNECTING
        self.last_error = None
        self._profile = profile
        try:
            self.supervisor.start(profile)
            if not self.supervisor.is_running:
                raise RuntimeError("Elevated Xray helper did not remain alive after readiness")
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"{type(exc).__name__}: {exc}"
            raise
        self._state = ConnectionState.CONNECTED

    def refresh(self) -> ConnectionState:
        """Observe helper exit without treating a stale UI status as connectivity."""
        if self._state is ConnectionState.CONNECTED:
            try:
                exit_code = self.supervisor.poll()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"Could not inspect elevated helper: {exc}"
            else:
                if exit_code is not None:
                    self._state = ConnectionState.ERROR
                    self.last_error = (
                        "The VPN helper exited unexpectedly"
                        if exit_code != 0
                        else "The VPN helper stopped outside the desktop disconnect flow"
                    )
        return self._state

    def disconnect(self) -> None:
        if self._state is ConnectionState.DISCONNECTED:
            return
        self._state = ConnectionState.DISCONNECTING
        try:
            self.supervisor.stop()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"VPN cleanup failed: {type(exc).__name__}: {exc}"
            raise
        self._profile = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error = None
