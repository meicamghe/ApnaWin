"""Deterministic in-memory engine for UI and lifecycle tests only.

This adapter creates no network tunnel and must never be presented as a real VPN.
"""

from apnawin.domain.profile import ConnectionProfile
from apnawin.domain.state import ConnectionState


class MockTunnelEngine:
    """Simulate a successful lifecycle without changing system networking."""

    def __init__(self) -> None:
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None

    @property
    def name(self) -> str:
        return "Mock (no network)"

    @property
    def state(self) -> ConnectionState:
        return self._state

    def validate_profile(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")

    def connect(self, profile: ConnectionProfile) -> None:
        self.validate_profile(profile)
        if self._state is not ConnectionState.DISCONNECTED:
            raise RuntimeError(f"Cannot connect while state is {self._state.value}")
        self._state = ConnectionState.CONNECTING
        self._profile = profile
        self._state = ConnectionState.CONNECTED

    def disconnect(self) -> None:
        if self._state is ConnectionState.DISCONNECTED:
            return
        self._state = ConnectionState.DISCONNECTING
        self._profile = None
        self._state = ConnectionState.DISCONNECTED
