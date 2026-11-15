"""Transport-neutral, fail-closed connection lifecycle orchestration."""

from __future__ import annotations

from apnawin.domain.profile import ConnectionProfile
from apnawin.domain.state import ConnectionState
from apnawin.engines.base import TunnelEngine


class ConnectionLifecycleError(RuntimeError):
    """A lifecycle operation failed; cleanup failure is retained when present."""

    def __init__(self, message: str, *, cleanup_error: Exception | None = None) -> None:
        super().__init__(message)
        self.cleanup_error = cleanup_error


class ConnectionController:
    """Serialize synchronous engine operations and never infer connection health.

    The controller is intentionally not wired to the desktop Connect action.
    A production engine must independently verify its required readiness before
    reporting CONNECTED; this coordinator only enforces lifecycle transitions.
    """

    def __init__(self, engine: TunnelEngine) -> None:
        if engine is None:
            raise TypeError("engine is required")
        self._engine = engine
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        return self._profile

    def connect(self, profile: ConnectionProfile) -> None:
        if self._state is not ConnectionState.DISCONNECTED:
            raise ConnectionLifecycleError(
                f"Cannot connect while state is {self._state.value}"
            )
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
            except Exception as cleanup_exc:  # retain failed cleanup for retry/diagnostics
                cleanup_error = cleanup_exc
            self._state = ConnectionState.ERROR
            self._profile = None
            raise ConnectionLifecycleError(
                "Connection attempt failed; engine cleanup was requested",
                cleanup_error=cleanup_error,
            ) from exc
        self._state = ConnectionState.CONNECTED

    def disconnect(self) -> None:
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
