"""Desktop-side lifecycle wrapper for the fixed-path elevated Xray helper."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.elevated_xray import ElevatedXrayProcess
from apnawin.storage.xray_config_store import XrayConfigStore


class XrayTunnelSupervisor:
    """Starts, polls and stops the UAC helper for one selected XRAY profile."""

    def __init__(
        self,
        helper_path: str | Path,
        config_store: XrayConfigStore,
        *,
        readiness_timeout: float = 45.0,
        stop_timeout: float = 15.0,
        process_factory: Callable[..., ElevatedXrayProcess] | None = None,
    ) -> None:
        self.helper_path = Path(helper_path)
        self.config_store = config_store
        self._validate_timeout(readiness_timeout, "readiness_timeout")
        self._validate_timeout(stop_timeout, "stop_timeout")
        self.readiness_timeout = float(readiness_timeout)
        self.stop_timeout = float(stop_timeout)
        self._process_factory = process_factory or ElevatedXrayProcess.launch
        self._process: ElevatedXrayProcess | None = None

    @staticmethod
    def _validate_timeout(value: float, name: str) -> None:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{name} must be a positive finite number")

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self, profile: ConnectionProfile) -> int:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport != Transport.XRAY:
            raise ValueError("The elevated TUN supervisor accepts XRAY profiles only")
        if self._process is not None:
            exit_code = self._process.poll()
            if exit_code is None:
                raise RuntimeError("An elevated Xray session is already running")
            if exit_code != 0:
                raise RuntimeError(
                    "The previous VPN helper exited abnormally; network cleanup is unverified. "
                    "A new tunnel will not be started over uncertain network state."
                )
            self._process.close()
            self._process = None
        if not self.config_store.has_config(profile.name):
            raise ValueError("Import a validated Xray TUN config for this profile first")
        process = self._process_factory(
            self.helper_path,
            self.config_store.path,
            profile.name,
            readiness_timeout=self.readiness_timeout,
        )
        self._process = process
        return process.pid

    def poll(self) -> int | None:
        """Observe helper exit but retain ownership until cleanup is acknowledged."""
        if self._process is None:
            return None
        return self._process.poll()

    def stop(self) -> None:
        if self._process is None:
            return
        process = self._process
        exit_code = process.poll()
        if exit_code is not None and exit_code != 0:
            raise RuntimeError(
                "VPN helper exited abnormally; route/DNS cleanup cannot be confirmed. "
                "The session is retained as ERROR instead of reporting a false disconnect."
            )
        if exit_code is None:
            process.terminate(timeout=self.stop_timeout)
        process.close()
        self._process = None

    def close(self) -> None:
        self.stop()
