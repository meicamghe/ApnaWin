"""Provider-neutral remote catalog refresh orchestration.

No network client or APNA-specific endpoint is implemented here. A verified
provider can be injected later without changing cache and retry semantics.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import Condition
from typing import Callable, Protocol

from apnawin.domain.remote_catalog import RemoteCatalog, parse_remote_catalog
from apnawin.storage.remote_catalog_store import RemoteCatalogStore


class RemoteConfigProvider(Protocol):
    """Minimal provider contract; implementations must enforce their own timeouts."""

    def fetch_catalog(self) -> str | bytes:
        """Return a normalized catalog document obtained from a trusted source."""
        ...


class RefreshStatus(str, Enum):
    UPDATED = "updated"
    BACKOFF = "backoff"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class RefreshResult:
    """Outcome of one refresh attempt; failure details intentionally omit messages."""

    status: RefreshStatus
    catalog: RemoteCatalog | None
    error_type: str | None = None
    retry_after_seconds: float | None = None


class RemoteCatalogRefreshCoordinator:
    """Serialize refreshes, enforce freshness, back off and retain the last good cache."""

    def __init__(
        self,
        provider: RemoteConfigProvider,
        store: RemoteCatalogStore,
        *,
        base_backoff_seconds: float = 5.0,
        max_backoff_seconds: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        for name, value in (
            ("base_backoff_seconds", base_backoff_seconds),
            ("max_backoff_seconds", max_backoff_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite positive number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        if max_backoff_seconds < base_backoff_seconds:
            raise ValueError("max_backoff_seconds must be >= base_backoff_seconds")
        if not callable(monotonic) or not callable(wall_clock):
            raise ValueError("clock providers must be callable")

        self._provider = provider
        self._store = store
        self._base_backoff = float(base_backoff_seconds)
        self._max_backoff = float(max_backoff_seconds)
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._condition = Condition()
        self._refreshing = False
        self._generation = 0
        # Results are retained only while callers are waiting for that exact
        # generation. A later refresh can therefore never overwrite their result.
        self._waiters_by_generation: dict[int, int] = {}
        self._completed_by_generation: dict[int, RefreshResult] = {}
        self._failure_count = 0
        self._next_retry_at = 0.0

    def _cached_catalog(self) -> RemoteCatalog | None:
        try:
            return self._store.load()
        except (OSError, ValueError):
            return None

    def refresh(self, *, force: bool = False) -> RefreshResult:
        """Refresh once; concurrent callers share the exact in-flight result."""
        if not isinstance(force, bool):
            raise TypeError("force must be a boolean")

        with self._condition:
            if self._refreshing:
                generation = self._generation
                self._waiters_by_generation[generation] = (
                    self._waiters_by_generation.get(generation, 0) + 1
                )
                try:
                    self._condition.wait_for(
                        lambda: generation in self._completed_by_generation
                    )
                    return self._completed_by_generation[generation]
                finally:
                    remaining = self._waiters_by_generation[generation] - 1
                    if remaining:
                        self._waiters_by_generation[generation] = remaining
                    else:
                        self._waiters_by_generation.pop(generation, None)
                        self._completed_by_generation.pop(generation, None)

            now = self._monotonic()
            if not force and now < self._next_retry_at:
                return RefreshResult(
                    status=RefreshStatus.BACKOFF,
                    catalog=self._cached_catalog(),
                    retry_after_seconds=max(0.0, self._next_retry_at - now),
                )

            self._refreshing = True
            self._generation += 1
            generation = self._generation

        result: RefreshResult
        try:
            document = self._provider.fetch_catalog()
            # Validate the freshness window before writing. An expired or
            # not-yet-valid response must never replace the last-known-good cache.
            catalog = parse_remote_catalog(document)
            if not catalog.is_fresh(now=self._wall_clock()):
                raise ValueError("Remote catalog is outside its validity window")
            self._store.save(document)
            result = RefreshResult(status=RefreshStatus.UPDATED, catalog=catalog)
            with self._condition:
                self._failure_count = 0
                self._next_retry_at = 0.0
        except Exception as exc:
            with self._condition:
                self._failure_count += 1
                exponent = min(self._failure_count - 1, 30)
                delay = min(self._base_backoff * (2**exponent), self._max_backoff)
                self._next_retry_at = self._monotonic() + delay
            result = RefreshResult(
                status=RefreshStatus.FAILED,
                catalog=self._cached_catalog(),
                error_type=type(exc).__name__,
            )
        finally:
            with self._condition:
                if "result" not in locals():
                    # Wake waiters even if this thread is interrupted by a
                    # BaseException; the initiating caller still receives it.
                    result = RefreshResult(
                        status=RefreshStatus.FAILED,
                        catalog=self._cached_catalog(),
                        error_type="RefreshAborted",
                    )
                if self._waiters_by_generation.get(generation, 0):
                    self._completed_by_generation[generation] = result
                self._refreshing = False
                self._condition.notify_all()

        return result

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive failed refresh attempts."""
        with self._condition:
            return self._failure_count
