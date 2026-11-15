"""Platform-neutral ownership wrapper for a future Wintun API adapter.

No DLL is loaded here and no packets or Windows network settings are changed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


_MIN_RING_CAPACITY = 0x20000
_MAX_RING_CAPACITY = 0x4000000
_MAX_LUID = (1 << 64) - 1


class WintunSessionError(RuntimeError):
    """A Wintun resource could not be created or safely released."""

    def __init__(
        self,
        message: str,
        *,
        cause: Exception | None = None,
        cleanup_errors: tuple[Exception, ...] = (),
    ) -> None:
        super().__init__(message)
        self.cause = cause
        self.cleanup_errors = cleanup_errors


class WintunBackend(Protocol):
    """Narrow API adapter; a production implementation must pin and verify its DLL."""

    def create_adapter(self, name: str, tunnel_type: str, requested_guid: str) -> object: ...

    def get_adapter_luid(self, adapter: object) -> int: ...

    def start_session(self, adapter: object, ring_capacity: int) -> object: ...

    def end_session(self, session: object) -> None: ...

    def close_adapter(self, adapter: object) -> None: ...


class WintunSessionState(str, Enum):
    CLOSED = "closed"
    ADAPTER_OPEN = "adapter_open"
    SESSION_STARTED = "session_started"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WintunSessionInfo:
    """Identity returned after the adapter and ring session are fully initialized."""

    interface_luid: int
    adapter_name: str
    requested_guid: str
    ring_capacity: int


class WintunSessionOwner:
    """Own one adapter/session pair and release them in strict reverse order.

    This class deliberately stops at resource ownership. Packet receive/send,
    IP configuration, route/DNS mutation and privilege elevation are separate
    integration gates and are not implied by SESSION_STARTED.
    """

    def __init__(
        self,
        backend: WintunBackend,
        *,
        adapter_name: str,
        tunnel_type: str,
        requested_guid: str,
        ring_capacity: int = 0x200000,
    ) -> None:
        if backend is None:
            raise TypeError("backend is required")
        for value, field_name in (
            (adapter_name, "adapter_name"),
            (tunnel_type, "tunnel_type"),
            (requested_guid, "requested_guid"),
        ):
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"{field_name} must be a non-empty trimmed string")
            if len(value) > 128 or any(ord(char) < 32 for char in value):
                raise ValueError(f"{field_name} is not a bounded printable string")
        if (
            isinstance(ring_capacity, bool)
            or not isinstance(ring_capacity, int)
            or not _MIN_RING_CAPACITY <= ring_capacity <= _MAX_RING_CAPACITY
            or ring_capacity & (ring_capacity - 1)
        ):
            raise ValueError(
                "ring_capacity must be a power of two between 128 KiB and 64 MiB"
            )
        self._backend = backend
        self._adapter_name = adapter_name
        self._tunnel_type = tunnel_type
        self._requested_guid = requested_guid
        self._ring_capacity = ring_capacity
        self._adapter: object | None = None
        self._session: object | None = None
        self._info: WintunSessionInfo | None = None
        self._state = WintunSessionState.CLOSED

    @property
    def state(self) -> WintunSessionState:
        return self._state

    @property
    def info(self) -> WintunSessionInfo | None:
        return self._info

    def start(self) -> WintunSessionInfo:
        if self._state is not WintunSessionState.CLOSED:
            raise WintunSessionError(f"cannot start while state is {self._state.value}")
        try:
            adapter = self._backend.create_adapter(
                self._adapter_name, self._tunnel_type, self._requested_guid
            )
            if adapter is None:
                raise WintunSessionError("Wintun backend returned no adapter handle")
            self._adapter = adapter
            self._state = WintunSessionState.ADAPTER_OPEN

            luid = self._backend.get_adapter_luid(adapter)
            if (
                isinstance(luid, bool)
                or not isinstance(luid, int)
                or not 1 <= luid <= _MAX_LUID
            ):
                raise WintunSessionError("Wintun backend returned an invalid interface LUID")

            session = self._backend.start_session(adapter, self._ring_capacity)
            if session is None:
                raise WintunSessionError("Wintun backend returned no session handle")
            self._session = session
            self._state = WintunSessionState.SESSION_STARTED
            self._info = WintunSessionInfo(
                luid, self._adapter_name, self._requested_guid, self._ring_capacity
            )
            return self._info
        except Exception as exc:
            cleanup_errors = self._release_resources()
            if cleanup_errors:
                self._state = WintunSessionState.FAILED
            else:
                self._state = WintunSessionState.CLOSED
            raise WintunSessionError(
                "Wintun session initialization failed",
                cause=exc,
                cleanup_errors=cleanup_errors,
            ) from exc

    def stop(self) -> None:
        if self._state is WintunSessionState.CLOSED:
            return
        errors = self._release_resources()
        if errors:
            self._state = WintunSessionState.FAILED
            raise WintunSessionError(
                "Wintun resources could not all be released; ownership was retained",
                cleanup_errors=errors,
            )
        self._state = WintunSessionState.CLOSED
        self._info = None

    def _release_resources(self) -> tuple[Exception, ...]:
        errors: list[Exception] = []
        # A live session depends on its adapter. Never close the adapter if
        # EndSession fails; retain both handles so a later stop() can retry.
        if self._session is not None:
            try:
                self._backend.end_session(self._session)
            except Exception as exc:
                errors.append(exc)
                return tuple(errors)
            self._session = None

        if self._adapter is not None:
            try:
                self._backend.close_adapter(self._adapter)
            except Exception as exc:
                errors.append(exc)
            else:
                self._adapter = None
        if self._adapter is None and self._session is None:
            self._info = None
        return tuple(errors)

    def __enter__(self) -> "WintunSessionOwner":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()
