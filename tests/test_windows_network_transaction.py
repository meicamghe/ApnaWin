from uuid import uuid4

import pytest

from apnawin.services.windows_network_journal import (
    JournalMutation,
    JournalPhase,
    ResourceKind,
    WindowsNetworkJournal,
    WindowsNetworkJournalStore,
)
from apnawin.services.windows_network_transaction import (
    NetworkTransactionError,
    WindowsNetworkTransaction,
)


class MemoryAdapter:
    def __init__(self):
        self.resources = {}
        self.fail_apply_for = set()
        self.external_change_for = set()
        self.calls = []

    def read(self, kind, resource_key):
        return dict(self.resources.get((kind, resource_key), {}))

    def apply(self, kind, resource_key, state):
        key = (kind, resource_key)
        self.calls.append((kind, resource_key, dict(state)))
        if key in self.fail_apply_for:
            self.fail_apply_for.remove(key)
            raise OSError("simulated apply failure")
        self.resources[key] = dict(state)
        if key in self.external_change_for:
            self.resources[key] = {"external": True}


def make_journal(*, count=2):
    mutations = tuple(
        JournalMutation.from_states(
            ResourceKind.ROUTE,
            f"route-{index}",
            {},
            {"present": True, "metric": index + 1},
        )
        for index in range(count)
    )
    return WindowsNetworkJournal(
        str(uuid4()), 1, JournalPhase.PREPARED, mutations
    )


def test_execute_persists_and_verifies_all_mutations(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    result = WindowsNetworkTransaction(store, adapter).execute(make_journal())
    assert result.phase is JournalPhase.COMMITTED
    assert result.revision == 4
    assert all(item.applied for item in result.mutations)
    assert store.load() == result
    assert len(adapter.calls) == 2


def test_execute_does_not_mutate_when_prepared_save_fails(tmp_path, monkeypatch):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")

    def fail_save(_journal):
        raise OSError("disk unavailable")

    monkeypatch.setattr(store, "save", fail_save)
    with pytest.raises(OSError, match="disk unavailable"):
        WindowsNetworkTransaction(store, adapter).execute(make_journal())
    assert adapter.calls == []


def test_apply_failure_compensates_previously_applied_resource(tmp_path):
    adapter = MemoryAdapter()
    adapter.fail_apply_for.add((ResourceKind.ROUTE, "route-1"))
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    with pytest.raises(NetworkTransactionError) as caught:
        WindowsNetworkTransaction(store, adapter).execute(make_journal())
    assert isinstance(caught.value.cause, OSError)
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {}
    assert store.load().phase is JournalPhase.ROLLED_BACK


def test_partial_apply_exception_is_compensated_from_live_state(tmp_path):
    class PartialAdapter(MemoryAdapter):
        def apply(self, kind, resource_key, state):
            if resource_key == "route-0" and state:
                self.resources[(kind, resource_key)] = dict(state)
                raise OSError("failed after OS mutation")
            super().apply(kind, resource_key, state)

    adapter = PartialAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    with pytest.raises(NetworkTransactionError):
        WindowsNetworkTransaction(store, adapter).execute(make_journal(count=1))
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {}
    assert store.load().phase is JournalPhase.ROLLED_BACK


def test_rollback_refuses_to_overwrite_external_change(tmp_path):
    adapter = MemoryAdapter()
    adapter.external_change_for.add((ResourceKind.ROUTE, "route-0"))
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    with pytest.raises(NetworkTransactionError) as caught:
        WindowsNetworkTransaction(store, adapter).execute(make_journal(count=1))
    assert caught.value.rollback_errors
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {"external": True}
    assert store.load().phase is JournalPhase.ROLLBACK_FAILED


def test_rollback_is_reverse_order(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter)
    committed = tx.execute(make_journal())
    tx.rollback(committed)
    restore_calls = [call[1] for call in adapter.calls if call[2] == {}]
    assert restore_calls == ["route-1", "route-0"]
    assert store.load().phase is JournalPhase.ROLLED_BACK


def test_rollback_is_idempotent_for_terminal_rolled_back_record(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter)
    committed = tx.execute(make_journal(count=1))
    rolled_back = tx.rollback(committed)
    call_count = len(adapter.calls)
    assert tx.rollback(rolled_back) == rolled_back
    assert len(adapter.calls) == call_count


def test_rejects_non_prepared_or_pre_marked_journal(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter)
    prepared = make_journal(count=1)
    committed = WindowsNetworkJournal(
        prepared.transaction_id, 2, JournalPhase.COMMITTED, prepared.mutations
    )
    with pytest.raises(NetworkTransactionError, match="PREPARED"):
        tx.execute(committed)
    marked = WindowsNetworkJournal(
        str(uuid4()), 1, JournalPhase.PREPARED,
        (JournalMutation.from_states(
            ResourceKind.DNS, "dns-1", {}, {"servers": ["1.1.1.1"]}, applied=True
        ),),
    )
    with pytest.raises(NetworkTransactionError, match="applied mutations"):
        tx.execute(marked)
    assert adapter.calls == []
