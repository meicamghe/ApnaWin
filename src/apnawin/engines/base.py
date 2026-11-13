"""Contract shared by real and test-only tunnel engine adapters."""

from typing import Protocol

from apnawin.domain.profile import ConnectionProfile
from apnawin.domain.state import ConnectionState


class TunnelEngine(Protocol):
    """A backend adapter. Implementations must not silently fake connectivity."""

    @property
    def name(self) -> str: ...

    @property
    def state(self) -> ConnectionState: ...

    def validate_profile(self, profile: ConnectionProfile) -> None: ...

    def connect(self, profile: ConnectionProfile) -> None:
        """Start a connection or raise an actionable exception."""

    def disconnect(self) -> None:
        """Stop the connection and restore any resources owned by the backend."""
