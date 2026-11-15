"""Fail-closed orchestration for journaled Windows network mutations.

The adapter is deliberately injected: this module never calls Windows APIs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
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
    """Apply and compensate journaled resources with compare-before-restore.

    A mutation is durably marked as possibly applied before calling the adapter.
    This closes the crash window between an OS change and the next journal write:
    recovery always reconciles live state against exact before/after snapshots.
    """

    store: WindowsNetworkJournalStore
    adapter: NetworkResourceAdapter

    def execute(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
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
                marked = list(current.mutations)
                marked[index] = JournalMutation(
                    mutation.kind,
                    mutation.resource_key,
                    mutation.before_json,
                    mutation.after_json,
                    applied=True,
                )
                current = self._next(current, JournalPhase.APPLYING, tuple(marked))
                # Persist intent before the external side effect. On recovery, compare
                # live state: it may still be before, may be after, or be a conflict.
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

    def rollback(self, journal: WindowsNetworkJournal) -> WindowsNetworkJournal:
        """Restore only resources still matching this transaction's after-state."""
        if journal.phase is JournalPhase.ROLLED_BACK:
            return journal
        errors = self._rollback(journal)
        if errors:
            raise NetworkTransactionError(
                "network rollback was incomplete; journal must be retained",
                rollback_errors=errors,
            )
        # _rollback persists ROLLED_BACK before returning.
        return self.store.load()

    def _rollback(self, journal: WindowsNetworkJournal) -> tuple[Exception, ...]:
        errors: list[Exception] = []
        try:
            current = self._next(journal, JournalPhase.ROLLING_BACK, journal.mutations)
            self.store.save(current)
        except Exception as exc:
            # Existing APPLYING/COMMITTED record still contains the possibly-applied
            # set. Continue conservative compensation; never discard that record.
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
