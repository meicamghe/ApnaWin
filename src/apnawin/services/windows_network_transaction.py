"""Fail-closed orchestration for journaled Windows network mutations.

The adapter is injected: this module never calls Windows APIs or elevates privileges.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from threading import Lock, RLock
from typing import Any, Protocol

from apnawin.services.windows_named_mutex import WindowsNamedMutex
from apnawin.services.windows_network_journal import (
    JournalMutation,
    JournalPhase,
    ResourceKind,
    WindowsNetworkJournal,
    WindowsNetworkJournalStore,
)


class NetworkResourceAdapter(Protocol):
    """Narrow adapter for reading and applying one exact route/DNS resource."""

    def read(self, kind: ResourceKind, resource_key: str) -> dict[str, Any]:
        """Return the current exact resource state; absent resources use {}."""

    def apply(
        self, kind: ResourceKind, resource_key: str, state: dict[str, Any]
    ) -> None:
        """Set the exact resource state; {} represents absence."""


class NetworkTransactionError(RuntimeError):
    """A network transaction failed or could not be safely compensated."""

    def __init__(
        self,
        message: str,
        *,
        cause: Exception | None = None,
        rollback_errors: tuple[Exception, ...] = (),
    ) -> None:
        super().__init__(message)
        self.cause = cause
        self.rollback_errors = rollback_errors


def _canonical_state(state: dict[str, Any]) -> str:
    if not isinstance(state, dict):
        raise NetworkTransactionError("adapter returned a non-object resource state")
    try:
        return json.dumps(
            state, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise NetworkTransactionError("adapter returned an invalid resource state") from exc


def _snapshot(mutation: JournalMutation, *, after: bool) -> dict[str, Any]:
    return json.loads(mutation.after_json if after else mutation.before_json)


_PATH_LOCKS_GUARD = Lock()
_PATH_LOCKS: dict[str, RLock] = {}


def _lock_for_store(store: WindowsNetworkJournalStore) -> RLock:
    """Return the process-local lock shared by a canonical journal path."""
    key = os.path.normcase(str(store.path.resolve()))
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = RLock()
            _PATH_LOCKS[key] = lock
        return lock


@dataclass(slots=True)
class WindowsNetworkTransaction:
    """Apply, recover and compensate journaled resources.

    Instances in the same process that target the same canonical journal path
    share a lock. The production helper must additionally enforce an OS-level
    mutex because separate processes do not share Python locks.
    """

    store: WindowsNetworkJournalStore
    adapter: NetworkResourceAdapter
    mutex: WindowsNamedMutex | None = None
    mutex_timeout_ms: int = 5000
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.mutex_timeout_ms, bool)
            or not isinstance(self.mutex_timeout_ms, int)
            or not 0 <= self.mutex_timeout_ms <= 0xFFFFFFFE
        ):
            raise ValueError("mutex_timeout_ms must be a finite non-negative DWORD")
        self._lock = _lock_for_store(self.store)

    def _with_mutex(self, operation):
        if self.mutex is None:
            return operation()
        with self.mutex.acquire(
            self.mutex_timeout_ms,
            recover_abandoned=self._recover_locked,
        ):
            return operation()

    def execute(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        with self._lock:
            return self._with_mutex(lambda: self._execute(journal))

    def _execute(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        if not isinstance(journal, WindowsNetworkJournal):
            raise TypeError("journal must be a WindowsNetworkJournal")
        if journal.phase is not JournalPhase.PREPARED:
            raise NetworkTransactionError("new transaction must start in PREPARED phase")
        if any(item.applied for item in journal.mutations):
            raise NetworkTransactionError("PREPARED transaction cannot contain applied mutations")

        # A durable non-terminal journal owns the single transaction slot. Never
        # overwrite it; a corrupt existing record also fails closed via load().
        if self.store.path.exists():
            persisted = self.store.load()
            if persisted.phase is not JournalPhase.ROLLED_BACK:
                raise NetworkTransactionError(
                    "an existing non-terminal journal must be recovered before a new transaction"
                )

        current = journal
        # No OS mutation is permitted unless the complete PREPARED snapshot is durable.
        self.store.save(current)
        try:
            for index, mutation in enumerate(current.mutations):
                # Optimistic precondition: never overwrite a route/DNS resource that
                # changed after the transaction's before-snapshot was collected.
                observed_before = self.adapter.read(mutation.kind, mutation.resource_key)
                if _canonical_state(observed_before) != mutation.before_json:
                    raise NetworkTransactionError(
                        f"resource no longer matches its before-snapshot: "
                        f"{mutation.resource_key}"
                    )

                marked = list(current.mutations)
                marked[index] = JournalMutation(
                    mutation.kind,
                    mutation.resource_key,
                    mutation.before_json,
                    mutation.after_json,
                    applied=True,
                )
                current = self._next(current, JournalPhase.APPLYING, tuple(marked))
                # Persist possibly-applied intent before the external side effect.
                self.store.save(current)
                self.adapter.apply(
                    mutation.kind, mutation.resource_key, _snapshot(mutation, after=True)
                )
                observed = self.adapter.read(mutation.kind, mutation.resource_key)
                if _canonical_state(observed) != mutation.after_json:
                    raise NetworkTransactionError(
                        f"resource verification failed: {mutation.resource_key}"
                    )
            current = self._next(current, JournalPhase.COMMITTED, current.mutations)
            self.store.save(current)
            return current
        except Exception as exc:
            rollback_errors = self._rollback(current)
            raise NetworkTransactionError(
                "network transaction failed; compensation was attempted",
                cause=exc,
                rollback_errors=rollback_errors,
            ) from exc

    def recover(self) -> WindowsNetworkJournal:
        """Recover under the process lock and optional service-owned OS mutex."""
        with self._lock:
            return self._with_mutex(self._recover_locked)

    def _recover_locked(self) -> WindowsNetworkJournal:
        """Reconcile the journal while the caller owns the serialization lock."""
        journal = self.store.load()
        if journal.phase is JournalPhase.ROLLED_BACK:
            return journal
        if journal.phase not in {
            JournalPhase.PREPARED,
            JournalPhase.APPLYING,
            JournalPhase.COMMITTED,
            JournalPhase.ROLLING_BACK,
            JournalPhase.ROLLBACK_FAILED,
        }:
            raise NetworkTransactionError(
                f"journal phase cannot be recovered: {journal.phase.value}"
            )
        errors = self._rollback(journal)
        if errors:
            raise NetworkTransactionError(
                "startup recovery was incomplete; journal must be retained",
                rollback_errors=errors,
            )
        return self.store.load()

    def rollback(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        """Restore only resources still matching this transaction's after-state."""
        with self._lock:
            return self._with_mutex(lambda: self._rollback_public_locked(journal))

    def _rollback_public_locked(
        self, journal: WindowsNetworkJournal
    ) -> WindowsNetworkJournal:
        if not self.store.path.exists():
            raise NetworkTransactionError("cannot roll back without a persisted journal")
        persisted = self.store.load()
        if persisted != journal:
            raise NetworkTransactionError(
                "stale journal revision; refusing to overwrite newer persisted state"
            )
        if journal.phase is JournalPhase.ROLLED_BACK:
            return journal
        if journal.phase not in {
            JournalPhase.APPLYING,
            JournalPhase.COMMITTED,
            JournalPhase.ROLLING_BACK,
            JournalPhase.ROLLBACK_FAILED,
            JournalPhase.PREPARED,
        }:
            raise NetworkTransactionError(
                f"journal phase cannot be rolled back: {journal.phase.value}"
            )
        errors = self._rollback(journal)
        if errors:
            raise NetworkTransactionError(
                "network rollback was incomplete; journal must be retained",
                rollback_errors=errors,
            )
        return self.store.load()

    def _rollback(self, journal: WindowsNetworkJournal) -> tuple[Exception, ...]:
        errors: list[Exception] = []
        try:
            current = self._next(journal, JournalPhase.ROLLING_BACK, journal.mutations)
            self.store.save(current)
        except Exception as exc:
            # Existing record still contains the possibly-applied set. Continue
            # conservative compensation, but never report successful recovery.
            current = journal
            errors.append(exc)

        for mutation in reversed(current.mutations):
            if not mutation.applied:
                continue
            try:
                observed = self.adapter.read(mutation.kind, mutation.resource_key)
                observed_json = _canonical_state(observed)
                if observed_json == mutation.before_json:
                    continue
                if observed_json != mutation.after_json:
                    raise NetworkTransactionError(
                        f"resource changed outside transaction; refusing restore: "
                        f"{mutation.resource_key}"
                    )
                self.adapter.apply(
                    mutation.kind,
                    mutation.resource_key,
                    _snapshot(mutation, after=False),
                )
                restored = self.adapter.read(mutation.kind, mutation.resource_key)
                if _canonical_state(restored) != mutation.before_json:
                    raise NetworkTransactionError(
                        f"restore verification failed: {mutation.resource_key}"
                    )
            except Exception as exc:
                errors.append(exc)

        phase = JournalPhase.ROLLBACK_FAILED if errors else JournalPhase.ROLLED_BACK
        try:
            terminal = self._next(current, phase, current.mutations)
            self.store.save(terminal)
        except Exception as exc:
            errors.append(exc)
        return tuple(errors)

    @staticmethod
    def _next(
        journal: WindowsNetworkJournal,
        phase: JournalPhase,
        mutations: tuple[JournalMutation, ...],
    ) -> WindowsNetworkJournal:
        return WindowsNetworkJournal(
            transaction_id=journal.transaction_id,
            revision=journal.revision + 1,
            phase=phase,
            mutations=mutations,
        )
