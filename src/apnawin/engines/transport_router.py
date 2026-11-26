"""Route the connection controller to the engine matching each profile transport."""
from __future__ import annotations

from threading import RLock
from typing import Mapping

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState


class TransportEngineRouter:
    """A single-owner router for the currently selected transport engine."""

    def __init__(self, engines: Mapping[Transport, object]) -> None:
        if not isinstance(engines, Mapping) or not engines:
            raise ValueError("engines must be a non-empty transport-to-engine mapping")
        normalized = {}
        for transport, engine in engines.items():
            if not isinstance(transport, Transport):
                raise TypeError("engine mapping keys must be Transport values")
            if engine is None:
                raise TypeError(f"engine for {transport.value} is required")
            for attribute in ("state", "validate_profile", "connect", "disconnect"):
                if not hasattr(engine, attribute):
                    raise TypeError(f"engine for {transport.value} must provide {attribute}")
            normalized[transport] = engine
        self._engines = normalized
        self._active_engine = None
        self._active_profile: ConnectionProfile | None = None
        self._lock = RLock()

    @property
    def name(self) -> str:
        with self._lock:
            if self._active_engine is None:
                return "Transport engine router"
            return str(getattr(self._active_engine, "name", "Transport engine"))

    @property
    def state(self) -> ConnectionState:
        with self._lock:
            if self._active_engine is None:
                return ConnectionState.DISCONNECTED
            return self._active_engine.state

    @property
    def active_profile(self) -> ConnectionProfile | None:
        with self._lock:
            return self._active_profile

    @property
    def active_engine(self):
        with self._lock:
            return self._active_engine

    def supports(self, transport: Transport) -> bool:
        return transport in self._engines

    def _engine_for(self, profile: ConnectionProfile):
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        try:
            return self._engines[profile.transport]
        except KeyError as exc:
            raise ValueError(
                f"No connection engine is installed for {profile.transport.value}"
            ) from exc

    def validate_profile(self, profile: ConnectionProfile) -> None:
        with self._lock:
            if self._active_engine is not None and self._active_engine.state is not ConnectionState.DISCONNECTED:
                raise RuntimeError("Another transport engine still owns the connection")
            self._engine_for(profile).validate_profile(profile)

    def connect(self, profile: ConnectionProfile) -> None:
        with self._lock:
            if self._active_engine is not None and self._active_engine.state is not ConnectionState.DISCONNECTED:
                raise RuntimeError("Another transport engine still owns the connection")
            engine = self._engine_for(profile)
            self._active_engine = engine
            self._active_profile = profile
            try:
                engine.connect(profile)
            except Exception:
                if engine.state is ConnectionState.DISCONNECTED:
                    self._active_engine = None
                    self._active_profile = None
                raise

    def refresh(self) -> ConnectionState:
        with self._lock:
            if self._active_engine is None:
                return ConnectionState.DISCONNECTED
            refresh = getattr(self._active_engine, "refresh", None)
            if not callable(refresh):
                return self._active_engine.state
            state = refresh()
            if not isinstance(state, ConnectionState):
                raise TypeError("engine refresh() must return a ConnectionState")
            if state is ConnectionState.DISCONNECTED:
                self._active_engine = None
                self._active_profile = None
            return state

    def disconnect(self) -> None:
        with self._lock:
            if self._active_engine is None:
                return
            engine = self._active_engine
            engine.disconnect()
            if engine.state is ConnectionState.DISCONNECTED:
                self._active_engine = None
                self._active_profile = None
