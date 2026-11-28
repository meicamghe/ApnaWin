"""Background Qt worker for a verified Xray TUN session.

The helper's adapter/routes/DNS readiness event is necessary but insufficient.
This worker only emits connected after a real TLS/HTTP probe succeeds and the
selected Windows route to that probe target belongs to the ApnaWin adapter.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThread, Signal

from apnawin.domain.profile import ConnectionProfile
from apnawin.services.windows_tunnel_traffic_probe import WindowsTunnelTrafficProbe
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor
from apnawin.storage.xray_config_store import XrayConfigStore


class XrayConnectionWorker(QThread):
    """Own one helper lifecycle off the GUI thread; connected means traffic verified."""

    connected = Signal(int)
    failed = Signal(str)
    disconnected = Signal()
    lost = Signal(int)

    def __init__(
        self,
        profile: ConnectionProfile,
        helper_path: str | Path,
        config_store: XrayConfigStore,
        *,
        supervisor_factory: Callable[..., XrayTunnelSupervisor] = XrayTunnelSupervisor,
        traffic_probe: Callable[[], object] | None = None,
        poll_interval: float = 0.25,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if not isinstance(poll_interval, (int, float)) or isinstance(poll_interval, bool) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.profile = profile
        self.helper_path = Path(helper_path)
        self.config_store = config_store
        self._supervisor_factory = supervisor_factory
        self._traffic_probe = traffic_probe or WindowsTunnelTrafficProbe().verify
        self._poll_interval = float(poll_interval)
        self._stop_requested = threading.Event()
        self._supervisor: XrayTunnelSupervisor | None = None

    def request_stop(self) -> None:
        """Request graceful helper shutdown; safe to call from the GUI thread."""
        self._stop_requested.set()

    def run(self) -> None:
        supervisor = self._supervisor_factory(self.helper_path, self.config_store)
        self._supervisor = supervisor
        try:
            pid = supervisor.start(self.profile)
            if self._stop_requested.is_set():
                supervisor.stop()
                self.disconnected.emit()
                return

            # Do not publish CONNECTED on adapter/routes/DNS readiness alone.
            self._traffic_probe()
            if self._stop_requested.is_set():
                supervisor.stop()
                self.disconnected.emit()
                return

            self.connected.emit(pid)
            while not self._stop_requested.wait(self._poll_interval):
                exit_code = supervisor.poll()
                if exit_code is not None:
                    self.lost.emit(exit_code)
                    return

            supervisor.stop()
            self.disconnected.emit()
        except Exception as exc:
            cleanup_error = None
            try:
                supervisor.stop()
            except Exception as cleanup_exc:
                cleanup_error = cleanup_exc
            message = f"{type(exc).__name__}: {exc}"
            if cleanup_error is not None:
                message += (
                    f"; cleanup also failed ({type(cleanup_error).__name__}). "
                    "Network state may require administrator recovery."
                )
            self.failed.emit(message)
        finally:
            self._supervisor = None
