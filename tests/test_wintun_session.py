import pytest

from apnawin.engines.wintun_session import (
    WintunSessionError,
    WintunSessionOwner,
    WintunSessionState,
)


class FakeWintunBackend:
    def __init__(self):
        self.calls = []
        self.fail = set()

    def _call(self, name, *args):
        self.calls.append((name, *args))
        if name in self.fail:
            self.fail.remove(name)
            raise OSError(f"{name} failed")

    def create_adapter(self, name, tunnel_type, requested_guid):
        self._call("create_adapter", name, tunnel_type, requested_guid)
        return "adapter-handle"

    def get_adapter_luid(self, adapter):
        self._call("get_adapter_luid", adapter)
        return 123

    def start_session(self, adapter, ring_capacity):
        self._call("start_session", adapter, ring_capacity)
        return "session-handle"

    def end_session(self, session):
        self._call("end_session", session)

    def close_adapter(self, adapter):
        self._call("close_adapter", adapter)


def owner(backend, **kwargs):
    return WintunSessionOwner(
        backend,
        adapter_name="ApnaWin",
        tunnel_type="ApnaWin",
        requested_guid="{00000000-0000-0000-0000-000000000001}",
        **kwargs,
    )


def test_start_and_stop_release_resources_in_reverse_order():
    backend = FakeWintunBackend()
    session = owner(backend)
    info = session.start()
    assert info.interface_luid == 123
    assert session.state is WintunSessionState.SESSION_STARTED
    session.stop()
    assert session.state is WintunSessionState.CLOSED
    assert [call[0] for call in backend.calls] == [
        "create_adapter", "get_adapter_luid", "start_session",
        "end_session", "close_adapter",
    ]


def test_stop_is_idempotent_after_success():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    session.stop()
    count = len(backend.calls)
    session.stop()
    assert len(backend.calls) == count


def test_start_failure_closes_adapter():
    backend = FakeWintunBackend()
    backend.fail.add("start_session")
    session = owner(backend)
    with pytest.raises(WintunSessionError) as caught:
        session.start()
    assert isinstance(caught.value.cause, OSError)
    assert session.state is WintunSessionState.CLOSED
    assert [call[0] for call in backend.calls][-1] == "close_adapter"


def test_luid_validation_failure_closes_adapter():
    class InvalidLuidBackend(FakeWintunBackend):
        def get_adapter_luid(self, adapter):
            self._call("get_adapter_luid", adapter)
            return 0

    backend = InvalidLuidBackend()
    with pytest.raises(WintunSessionError):
        owner(backend).start()
    assert backend.calls[-1][0] == "close_adapter"


def test_failed_end_session_retains_adapter_and_session_for_retry():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    backend.fail.add("end_session")
    with pytest.raises(WintunSessionError):
        session.stop()
    assert session.state is WintunSessionState.FAILED
    assert [call[0] for call in backend.calls][-1] == "end_session"
    session.stop()
    assert session.state is WintunSessionState.CLOSED
    assert [call[0] for call in backend.calls][-2:] == ["end_session", "close_adapter"]


def test_failed_adapter_close_retains_adapter_for_retry():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    backend.fail.add("close_adapter")
    with pytest.raises(WintunSessionError):
        session.stop()
    assert session.state is WintunSessionState.FAILED
    session.stop()
    assert session.state is WintunSessionState.CLOSED
    assert [call[0] for call in backend.calls][-2:] == ["close_adapter", "close_adapter"]


@pytest.mark.parametrize("capacity", [0, 1, 65536, 131073, 0x8000000, True])
def test_rejects_invalid_ring_capacity(capacity):
    with pytest.raises(ValueError, match="ring_capacity"):
        owner(FakeWintunBackend(), ring_capacity=capacity)


def test_context_manager_releases_resources():
    backend = FakeWintunBackend()
    with owner(backend) as session:
        assert session.state is WintunSessionState.SESSION_STARTED
    assert session.state is WintunSessionState.CLOSED


def test_rejects_reentrant_start():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    with pytest.raises(WintunSessionError, match="cannot start"):
        session.start()
    session.stop()


def test_concurrent_start_calls_are_serialized():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    backend = FakeWintunBackend()
    session = owner(backend)
    barrier = Barrier(3)

    def start():
        barrier.wait()
        try:
            return session.start()
        except WintunSessionError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(start) for _ in range(2)]
        barrier.wait()
        results = [future.result() for future in futures]

    assert sum(result is not None for result in results) == 1
    assert [call[0] for call in backend.calls].count("create_adapter") == 1
    session.stop()


def test_state_and_info_reads_are_safe_during_lifecycle():
    from concurrent.futures import ThreadPoolExecutor

    backend = FakeWintunBackend()
    session = owner(backend)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(lambda: (session.state, session.info)) for _ in range(20)]
        session.start()
        snapshots = [future.result() for future in futures]
    assert all(state in WintunSessionState for state, _ in snapshots)
    session.stop()


def test_receive_lease_exposes_read_only_view_and_releases_once():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    released = []
    lease = session.lease_received_packet(bytearray(b"packet-data"), lambda: released.append(True))
    assert session.outstanding_receive_leases == 1
    assert lease.data.readonly
    assert bytes(lease.data) == b"packet-data"
    lease.release()
    lease.release()
    assert released == [True]
    assert session.outstanding_receive_leases == 0
    assert lease.released
    session.stop()


def test_session_stop_refuses_while_receive_lease_is_outstanding():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    lease = session.lease_received_packet(b"payload", lambda: None)
    with pytest.raises(WintunSessionError, match="leases are outstanding"):
        session.stop()
    assert session.state is WintunSessionState.SESSION_STARTED
    assert "end_session" not in [call[0] for call in backend.calls]
    lease.release()
    session.stop()


def test_receive_release_failure_retains_lease_for_retry():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    calls = []

    def flaky_release():
        calls.append("release")
        if len(calls) == 1:
            raise OSError("release failed")

    lease = session.lease_received_packet(b"payload", flaky_release)
    with pytest.raises(OSError, match="release failed"):
        lease.release()
    assert not lease.released
    assert session.outstanding_receive_leases == 1
    lease.release()
    assert lease.released
    assert calls == ["release", "release"]
    session.stop()


def test_receive_lease_context_manager_releases_on_exception():
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    released = []
    with pytest.raises(RuntimeError):
        with session.lease_received_packet(b"payload", lambda: released.append(True)):
            raise RuntimeError("consumer failed")
    assert released == [True]
    assert session.outstanding_receive_leases == 0
    session.stop()


def test_cannot_create_receive_lease_without_active_session():
    session = owner(FakeWintunBackend())
    with pytest.raises(WintunSessionError, match="started session"):
        session.lease_received_packet(b"payload", lambda: None)


@pytest.mark.parametrize("packet", [b"", memoryview(b"")])
def test_receive_lease_rejects_empty_packet(packet):
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    with pytest.raises(ValueError, match="non-empty"):
        session.lease_received_packet(packet, lambda: None)
    session.stop()


def test_receive_lease_normalizes_non_byte_buffer_to_bytes():
    from array import array

    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    packet = array("I", [0x01020304, 0x05060708])
    lease = session.lease_received_packet(packet, lambda: None)
    assert lease.data.format == "B"
    assert lease.data.itemsize == 1
    assert len(lease.data) == memoryview(packet).nbytes
    assert bytes(lease.data) == memoryview(packet).tobytes()
    lease.release()
    session.stop()


@pytest.mark.parametrize(
    "packet",
    [
        memoryview(bytearray(b"1234")).cast("B", shape=(2, 2)),
        memoryview(bytearray(b"1234"))[::2],
    ],
)
def test_receive_lease_rejects_non_one_dimensional_or_noncontiguous_views(packet):
    backend = FakeWintunBackend()
    session = owner(backend)
    session.start()
    with pytest.raises(ValueError, match="one-dimensional"):
        session.lease_received_packet(packet, lambda: None)
    session.stop()
