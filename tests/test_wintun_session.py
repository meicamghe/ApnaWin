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
