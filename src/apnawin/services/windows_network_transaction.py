"""Fail-closed orchestration for journaled Windows network mutations.

The adapter is injected: this module never calls Windows APIs or elevates privileges.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Protocol

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


@dataclass(slots=True)
class WindowsNetworkTransaction:
    """Apply, recover and compensate journaled resources.

    The instance lock serializes calls made through this executor instance. The
    production helper must additionally enforce a process-wide single transaction
    owner because multiple processes can instantiate separate executors.
    """

    store: WindowsNetworkJournalStore
    adapter: NetworkResourceAdapter
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def execute(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        with self._lock:
            return self._execute(journal)

    def _execute(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        if not isinstance(journal, WindowsNetworkJournal):
            raise TypeError("journal must be a WindowsNetworkJournal")
        if journal.phase is not JournalPhase.PREPARED:
            raise NetworkTransactionError("new transaction must start in PREPARED phase")
        if any(item.applied for item in journal.mutations):
            raise NetworkTransactionError("PREPARED transaction cannot contain applied mutations")

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
        """Conservatively reconcile the persisted journal after process restart.

        PREPARED means no mutation was authorized to run. APPLYING,
        ROLLING_BACK, ROLLBACK_FAILED and COMMITTED are reconciled against fresh
        adapter reads and compensated in reverse order. A corrupt/missing journal
        raises from the store and is never silently replaced.
        """
        with self._lock:
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
