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
    return WindowsNetworkJournal(str(uuid4()), 1, JournalPhase.PREPARED, mutations)


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


def test_execute_refuses_stale_before_snapshot_without_overwriting_it(tmp_path):
    adapter = MemoryAdapter()
    adapter.resources[(ResourceKind.ROUTE, "route-0")] = {"external": "newer"}
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    with pytest.raises(NetworkTransactionError) as caught:
        WindowsNetworkTransaction(store, adapter).execute(make_journal(count=1))
    assert "before-snapshot" in str(caught.value.cause)
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {"external": "newer"}
    assert adapter.calls == []
    assert store.load().phase is JournalPhase.ROLLED_BACK


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


def test_recovery_after_crash_between_apply_and_commit(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    prepared = make_journal(count=1)
    possibly_applied = WindowsNetworkJournal(
        prepared.transaction_id,
        2,
        JournalPhase.APPLYING,
        (JournalMutation(
            ResourceKind.ROUTE,
            "route-0",
            prepared.mutations[0].before_json,
            prepared.mutations[0].after_json,
            applied=True,
        ),),
    )
    store.save(possibly_applied)
    # Simulate the OS mutation having happened just before process death.
    adapter.resources[(ResourceKind.ROUTE, "route-0")] = {"present": True, "metric": 1}

    recovered = WindowsNetworkTransaction(store, adapter).recover()
    assert recovered.phase is JournalPhase.ROLLED_BACK
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {}


def test_recovery_when_intent_was_saved_but_os_mutation_did_not_happen(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    prepared = make_journal(count=1)
    applying = WindowsNetworkJournal(
        prepared.transaction_id,
        2,
        JournalPhase.APPLYING,
        (JournalMutation(
            ResourceKind.ROUTE,
            "route-0",
            prepared.mutations[0].before_json,
            prepared.mutations[0].after_json,
            applied=True,
        ),),
    )
    store.save(applying)
    recovered = WindowsNetworkTransaction(store, adapter).recover()
    assert recovered.phase is JournalPhase.ROLLED_BACK
    assert adapter.calls == []


def test_recovery_refuses_external_state_and_keeps_failed_journal(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    prepared = make_journal(count=1)
    applying = WindowsNetworkJournal(
        prepared.transaction_id,
        2,
        JournalPhase.APPLYING,
        (JournalMutation(
            ResourceKind.ROUTE,
            "route-0",
            prepared.mutations[0].before_json,
            prepared.mutations[0].after_json,
            applied=True,
        ),),
    )
    store.save(applying)
    adapter.resources[(ResourceKind.ROUTE, "route-0")] = {"external": True}
    with pytest.raises(NetworkTransactionError, match="startup recovery"):
        WindowsNetworkTransaction(store, adapter).recover()
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {"external": True}
    assert store.load().phase is JournalPhase.ROLLBACK_FAILED


def test_recovery_of_prepared_journal_performs_no_os_mutations(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    store.save(make_journal(count=1))
    recovered = WindowsNetworkTransaction(store, adapter).recover()
    assert recovered.phase is JournalPhase.ROLLED_BACK
    assert adapter.calls == []


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


def test_execute_refuses_to_overwrite_nonterminal_persisted_journal(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    existing = make_journal(count=1)
    store.save(existing)
    with pytest.raises(NetworkTransactionError, match="existing non-terminal"):
        WindowsNetworkTransaction(store, adapter).execute(make_journal(count=1))
    assert store.load() == existing
    assert adapter.calls == []


def test_execute_fails_closed_on_corrupt_existing_journal(tmp_path):
    adapter = MemoryAdapter()
    path = tmp_path / "journal.json"
    path.write_text("{broken", encoding="utf-8")
    store = WindowsNetworkJournalStore(path)
    with pytest.raises(Exception):
        WindowsNetworkTransaction(store, adapter).execute(make_journal(count=1))
    assert path.read_text(encoding="utf-8") == "{broken"
    assert adapter.calls == []


def test_rollback_refuses_stale_persisted_revision(tmp_path):
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter)
    committed = tx.execute(make_journal(count=1))
    newer = WindowsNetworkJournal(
        committed.transaction_id,
        committed.revision + 1,
        JournalPhase.COMMITTED,
        committed.mutations,
    )
    store.save(newer)
    with pytest.raises(NetworkTransactionError, match="stale journal revision"):
        tx.rollback(committed)
    assert store.load() == newer
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {
        "present": True, "metric": 1
    }


def test_executor_instances_share_lock_and_prevent_same_process_journal_race(tmp_path):
    import threading
    import time

    path = tmp_path / "shared-journal.json"
    store_one = WindowsNetworkJournalStore(path)
    store_two = WindowsNetworkJournalStore(path)
    entered_adapter = threading.Event()
    release_adapter = threading.Event()

    class BlockingAdapter(MemoryAdapter):
        def read(self, kind, resource_key):
            entered_adapter.set()
            assert release_adapter.wait(2)
            return super().read(kind, resource_key)

    adapter_one = BlockingAdapter()
    adapter_two = MemoryAdapter()
    first = WindowsNetworkTransaction(store_one, adapter_one)
    second = WindowsNetworkTransaction(store_two, adapter_two)
    first_result = []
    second_errors = []

    def run_first():
        first_result.append(first.execute(make_journal(count=1)))

    def run_second():
        try:
            second.execute(make_journal(count=1))
        except Exception as exc:
            second_errors.append(exc)

    thread_one = threading.Thread(target=run_first)
    thread_one.start()
    assert entered_adapter.wait(1)
    thread_two = threading.Thread(target=run_second)
    thread_two.start()
    time.sleep(0.03)
    assert thread_two.is_alive()
    release_adapter.set()
    thread_one.join(2)
    thread_two.join(2)

    assert not thread_one.is_alive()
    assert not thread_two.is_alive()
    assert len(first_result) == 1
    assert len(second_errors) == 1
    assert isinstance(second_errors[0], NetworkTransactionError)
    assert "existing non-terminal journal" in str(second_errors[0])
    assert adapter_two.calls == []


def test_executor_instances_share_lock_for_equivalent_resolved_paths(tmp_path):
    first_path = tmp_path / "journal.json"
    second_path = tmp_path / "." / "journal.json"
    first = WindowsNetworkTransaction(
        WindowsNetworkJournalStore(first_path), MemoryAdapter()
    )
    second = WindowsNetworkTransaction(
        WindowsNetworkJournalStore(second_path), MemoryAdapter()
    )
    assert first._lock is second._lock


def test_abandoned_mutex_recovers_existing_journal_before_new_execute(tmp_path):
    from contextlib import contextmanager

    class FakeMutex:
        def __init__(self):
            self.events = []
            self.abandoned = True

        @contextmanager
        def acquire(self, timeout_ms, *, recover_abandoned=None):
            self.events.append(("acquire", timeout_ms))
            if self.abandoned:
                self.abandoned = False
                assert callable(recover_abandoned)
                recover_abandoned()
                self.events.append(("recovered", None))
            try:
                yield
            finally:
                self.events.append(("release", None))

    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    prior = make_journal(count=1)
    applying = WindowsNetworkJournal(
        prior.transaction_id,
        2,
        JournalPhase.APPLYING,
        (JournalMutation(
            prior.mutations[0].kind,
            prior.mutations[0].resource_key,
            prior.mutations[0].before_json,
            prior.mutations[0].after_json,
            applied=True,
        ),),
    )
    store.save(applying)
    adapter.resources[(ResourceKind.ROUTE, "route-0")] = {"present": True, "metric": 1}
    mutex = FakeMutex()
    tx = WindowsNetworkTransaction(store, adapter, mutex=mutex)
    result = tx.execute(make_journal(count=1))
    assert result.phase is JournalPhase.COMMITTED
    assert mutex.events == [("acquire", 5000), ("recovered", None), ("release", None)]
    assert adapter.resources[(ResourceKind.ROUTE, "route-0")] == {
        "present": True, "metric": 1
    }


def test_transaction_mutex_timeout_configuration_is_validated(tmp_path):
    for value in (-1, 0xFFFFFFFF, True, 1.5):
        with pytest.raises(ValueError, match="mutex_timeout_ms"):
            WindowsNetworkTransaction(
                WindowsNetworkJournalStore(tmp_path / "journal.json"),
                MemoryAdapter(),
                mutex_timeout_ms=value,
            )


def test_execute_rollback_and_recover_acquire_optional_mutex(tmp_path):
    from contextlib import contextmanager

    class FakeMutex:
        def __init__(self):
            self.calls = []

        @contextmanager
        def acquire(self, timeout_ms, *, recover_abandoned=None):
            self.calls.append(timeout_ms)
            yield

    mutex = FakeMutex()
    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter, mutex=mutex, mutex_timeout_ms=250)
    committed = tx.execute(make_journal(count=1))
    assert mutex.calls == [250]
    tx.rollback(committed)
    assert mutex.calls == [250, 250]
    tx.recover()
    assert mutex.calls == [250, 250, 250]


def test_mutex_timeout_prevents_all_network_mutations(tmp_path):
    from contextlib import contextmanager

    class TimeoutMutex:
        @contextmanager
        def acquire(self, timeout_ms, *, recover_abandoned=None):
            raise TimeoutError("mutex acquisition timed out")
            yield

    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    tx = WindowsNetworkTransaction(store, adapter, mutex=TimeoutMutex())
    with pytest.raises(TimeoutError, match="timed out"):
        tx.execute(make_journal(count=1))
    assert adapter.calls == []
    assert not store.path.exists()


def test_abandoned_recovery_failure_prevents_new_transaction(tmp_path):
    from contextlib import contextmanager

    class FailedRecoveryMutex:
        @contextmanager
        def acquire(self, timeout_ms, *, recover_abandoned=None):
            assert callable(recover_abandoned)
            recover_abandoned()
            yield

    adapter = MemoryAdapter()
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    store.path.write_text("{corrupt", encoding="utf-8")
    tx = WindowsNetworkTransaction(store, adapter, mutex=FailedRecoveryMutex())
    with pytest.raises(Exception):
        tx.execute(make_journal(count=1))
    assert adapter.calls == []
    assert store.path.read_text(encoding="utf-8") == "{corrupt"
