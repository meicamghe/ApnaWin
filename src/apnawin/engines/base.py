"""Engine contract; implementations must manage their own child processes safely."""

from typing import Protocol

from apnawin.domain.profile import ConnectionProfile


class TunnelEngine(Protocol):
    @property
    def name(self) -> str: ...

    def validate_profile(self, profile: ConnectionProfile) -> None: ...
