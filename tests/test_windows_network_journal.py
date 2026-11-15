import json
from uuid import uuid4

import pytest

from apnawin.services.windows_network_journal import (
    JournalError,
    JournalMutation,
    JournalPhase,
    ResourceKind,
    WindowsNetworkJournal,
    WindowsNetworkJournalStore,
    _parse_document,
)


def sample_journal(*, applied=False):
    mutation = JournalMutation.from_states(
        ResourceKind.ROUTE,
        "10.20.30.40/32@if-luid:42",
        {"present": False},
        {"present": True, "metric": 5},
        applied=applied,
    )
    return WindowsNetworkJournal(str(uuid4()), 1, JournalPhase.PREPARED, (mutation,))


def test_journal_round_trip_and_atomic_replacement(tmp_path):
    store = WindowsNetworkJournalStore(tmp_path / "network.json")
    first = sample_journal()
    store.save(first)
    assert store.load() == first

    second = WindowsNetworkJournal(
        first.transaction_id,
        2,
        JournalPhase.APPLYING,
        (JournalMutation.from_states(
            ResourceKind.ROUTE, "10.20.30.40/32@if-luid:42",
            {"present": False}, {"present": True, "metric": 5}, applied=True,
        ),),
    )
    store.save(second)
    assert store.load() == second
    assert not list(tmp_path.glob("*.tmp"))


def test_journal_rejects_duplicate_resource_identity():
    item = JournalMutation.from_states(ResourceKind.DNS, "if-luid:42", {}, {"servers": ["1.1.1.1"]})
    with pytest.raises(JournalError, match="identities must be unique"):
        WindowsNetworkJournal(str(uuid4()), 1, JournalPhase.PREPARED, (item, item))


@pytest.mark.parametrize("bad", ["[]", "null", '{"x":1,"x":2}', '{"x":NaN}'])
def test_mutation_rejects_non_object_or_ambiguous_snapshots(bad):
    with pytest.raises(JournalError):
        JournalMutation(ResourceKind.ROUTE, "route-a", bad, "{}")


def test_journal_rejects_noncanonical_or_invalid_uuid():
    with pytest.raises(JournalError, match="UUID"):
        WindowsNetworkJournal("not-a-uuid", 1, JournalPhase.PREPARED, (
            JournalMutation.from_states(ResourceKind.ROUTE, "r", {}, {}),
        ))


def test_load_rejects_duplicate_document_keys(tmp_path):
    path = tmp_path / "journal.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(JournalError, match="duplicate JSON key"):
        WindowsNetworkJournalStore(path).load()


def test_load_rejects_oversized_file(tmp_path):
    path = tmp_path / "journal.json"
    path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(JournalError, match="size limit"):
        WindowsNetworkJournalStore(path).load()


def test_store_delete_is_idempotent(tmp_path):
    store = WindowsNetworkJournalStore(tmp_path / "journal.json")
    store.delete()
    store.save(sample_journal())
    store.delete()
    store.delete()
    with pytest.raises(JournalError, match="could not be read"):
        store.load()


def test_parse_rejects_unknown_fields():
    payload = json.dumps({
        "schema_version": 1, "transaction_id": str(uuid4()), "revision": 1,
        "phase": "prepared", "mutations": [], "unexpected": True,
    }).encode()
    with pytest.raises(JournalError, match="unexpected schema"):
        _parse_document(payload)


def test_parse_rejects_unknown_mutation_kind():
    payload = json.dumps({
        "schema_version": 1,
        "transaction_id": str(uuid4()),
        "revision": 1,
        "phase": "prepared",
        "mutations": [{
            "kind": "process",
            "resource_key": "arbitrary",
            "before": {},
            "after": {},
            "applied": False,
        }],
    }).encode()
    with pytest.raises(JournalError, match="kind is invalid"):
        _parse_document(payload)
