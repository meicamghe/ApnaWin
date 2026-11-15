"""Transport-neutral, fail-closed connection lifecycle orchestration."""

from __future__ import annotations

from threading import Lock

from apnawin.domain.profile import ConnectionProfile
from apnawin.domain.state import ConnectionState
from apnawin.engines.base import TunnelEngine


class ConnectionLifecycleError(RuntimeError):
    """A lifecycle operation failed; cleanup failure is retained when present."""

    def __init__(self, message: str, *, cleanup_error: Exception | None = None) -> None:
        super().__init__(message)
        self.cleanup_error = cleanup_error


class ConnectionController:
    """Serialize engine operations and never infer connection health.

    Profile validation is performed exactly once by the controller before the
    engine enters CONNECTING. Engine adapters must treat connect() as operating
    on an already-validated profile and independently verify their readiness
    before reporting CONNECTED.
    """

    def __init__(self, engine: TunnelEngine) -> None:
        if engine is None:
            raise TypeError("engine is required")
        self._engine = engine
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None
        self._lock = Lock()

    @property
    def state(self) -> ConnectionState:
        with self._lock:
            return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        with self._lock:
            return self._profile

    def connect(self, profile: ConnectionProfile) -> None:
        with self._lock:
            if self._state is not ConnectionState.DISCONNECTED:
                raise ConnectionLifecycleError(
                    f"Cannot connect while state is {self._state.value}"
                )

            # Validation failure must not mutate lifecycle state or request cleanup.
            self._engine.validate_profile(profile)
            self._state = ConnectionState.CONNECTING
            self._profile = profile
            try:
                self._engine.connect(profile)
                if self._engine.state is not ConnectionState.CONNECTED:
                    raise ConnectionLifecycleError(
                        "Engine returned without confirming CONNECTED state"
                    )
            except Exception as exc:
                cleanup_error = None
                try:
                    self._engine.disconnect()
                except Exception as cleanup_exc:
                    cleanup_error = cleanup_exc

                self._state = ConnectionState.ERROR
                # Retain ownership information if cleanup did not complete. This
                # allows diagnostics and a later disconnect retry to target it.
                if cleanup_error is None:
                    self._profile = None
                message = f"{exc}; engine cleanup was requested"
                if cleanup_error is not None:
                    message += f"; cleanup also failed: {cleanup_error}"
                raise ConnectionLifecycleError(
                    message, cleanup_error=cleanup_error
                ) from exc

            self._state = ConnectionState.CONNECTED

    def disconnect(self) -> None:
        with self._lock:
            if self._state is ConnectionState.DISCONNECTED:
                return
            self._state = ConnectionState.DISCONNECTING
            try:
                self._engine.disconnect()
            except Exception as exc:
                self._state = ConnectionState.ERROR
                raise ConnectionLifecycleError(
                    "Disconnect failed; engine resources may still be active"
                ) from exc
            self._profile = None
            self._state = ConnectionState.DISCONNECTED
