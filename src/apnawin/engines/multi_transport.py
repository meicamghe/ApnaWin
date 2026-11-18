"""Dispatch one serialized connection controller across supported transports."""
from __future__ import annotations

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.base import TunnelEngine


class MultiTransportTunnelEngine:
    """Select an engine by profile transport and retain ownership through cleanup."""

    def __init__(self, engines: dict[Transport, TunnelEngine]) -> None:
        if not isinstance(engines, dict) or not engines:
            raise ValueError("engines must be a non-empty transport mapping")
        if any(not isinstance(key, Transport) or value is None for key, value in engines.items()):
            raise TypeError("engine registry keys must be Transport values with valid engines")
        self._engines = dict(engines)
        self._candidate: TunnelEngine | None = None
        self._active: TunnelEngine | None = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "ApnaWin multi-transport engine"

    @property
    def state(self) -> ConnectionState:
        if self._active is not None:
            return self._active.state
        return self._state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        if self._active is None:
            return None
        return getattr(self._active, "active_profile", None)

    def _engine_for(self, profile: ConnectionProfile) -> TunnelEngine:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        try:
            return self._engines[profile.transport]
        except KeyError as exc:
            raise ValueError(
                f"No connection engine is registered for {profile.transport.value}"
            ) from exc

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if self._active is not None or self.state is not ConnectionState.DISCONNECTED:
            raise RuntimeError("A transport engine is already active")
        engine = self._engine_for(profile)
        engine.validate_profile(profile)
        self._candidate = engine

    def connect(self, profile: ConnectionProfile) -> None:
        if self._active is not None:
            raise RuntimeError("A transport engine is already active")
        engine = self._candidate or self._engine_for(profile)
        if engine is not self._engine_for(profile):
            raise RuntimeError("Validated engine does not match selected profile transport")
        self._active = engine
        self._candidate = None
        self._state = ConnectionState.CONNECTING
        self.last_error = None
        try:
            engine.connect(profile)
            if engine.state is not ConnectionState.CONNECTED:
                raise RuntimeError("Selected transport engine did not confirm CONNECTED")
        except Exception as exc:
            self._state = engine.state
            self.last_error = f"{type(exc).__name__}: {exc}"
            raise
        self._state = ConnectionState.CONNECTED

    def refresh(self) -> ConnectionState:
        if self._active is None:
            return self._state
        refresh = getattr(self._active, "refresh", None)
        if callable(refresh):
            try:
                observed = refresh()
                if not isinstance(observed, ConnectionState):
                    raise TypeError("engine refresh() must return a ConnectionState")
                self._state = observed
            except Exception as exc:
                self._state = ConnectionState.ERROR
                self.last_error = f"{type(exc).__name__}: {exc}"
                raise
        else:
            self._state = self._active.state
        if self._state is ConnectionState.DISCONNECTED:
            self._active = None
            self._candidate = None
        return self._state

    def disconnect(self) -> None:
        engine = self._active or self._candidate
        if engine is None:
            self._state = ConnectionState.DISCONNECTED
            return
        try:
            engine.disconnect()
        except Exception as exc:
            self._state = ConnectionState.ERROR
            self.last_error = f"{type(exc).__name__}: {exc}"
            raise
        self._active = None
        self._candidate = None
        self._state = ConnectionState.DISCONNECTED
        self.last_error = None
