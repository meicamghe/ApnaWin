import pytest

from apnawin.services.windows_named_mutex import (
    WAIT_ABANDONED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WindowsMutexError,
    WindowsNamedMutex,
)


class FakeBackend:
    def __init__(self, result=WAIT_OBJECT_0):
        self.result = result
        self.events = []
        self.fail_release = False

    def create(self, name, security_sddl):
        self.events.append(("create", name, security_sddl))
        return "handle", True

    def wait(self, handle, timeout_ms):
        self.events.append(("wait", timeout_ms))
        return self.result

    def release(self, handle):
        self.events.append(("release", handle))
        if self.fail_release:
            raise OSError("release failed")

    def close(self, handle):
        self.events.append(("close", handle))


SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"


def test_mutex_acquires_and_releases_owned_handle():
    backend = FakeBackend()
    mutex = WindowsNamedMutex(r"Global\\ApnaWin-Test", SDDL, backend)
    with mutex.acquire(1500):
        assert backend.events[-1] == ("wait", 1500)
    assert [event[0] for event in backend.events] == [
        "create", "wait", "release", "close"
    ]


def test_mutex_timeout_does_not_release_unowned_mutex():
    backend = FakeBackend(WAIT_TIMEOUT)
    mutex = WindowsNamedMutex("Local\\ApnaWin-Test", SDDL, backend)
    with pytest.raises(TimeoutError, match="timed out"):
        with mutex.acquire(25):
            pytest.fail("timeout must not enter critical section")
    assert [event[0] for event in backend.events] == ["create", "wait", "close"]


def test_abandoned_mutex_runs_recovery_before_entering_critical_section():
    backend = FakeBackend(WAIT_ABANDONED)
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, backend)
    recovered = []
    with mutex.acquire(100, recover_abandoned=lambda: recovered.append(True)):
        assert recovered == [True]
        assert backend.events[-1][0] == "wait"
    assert [event[0] for event in backend.events] == [
        "create", "wait", "release", "close"
    ]


def test_abandoned_mutex_without_recovery_fails_closed_and_releases():
    backend = FakeBackend(WAIT_ABANDONED)
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, backend)
    with pytest.raises(WindowsMutexError, match="recovery callback"):
        with mutex.acquire(100):
            pytest.fail("must not enter without recovery")
    assert [event[0] for event in backend.events] == [
        "create", "wait", "release", "close"
    ]


def test_failed_abandoned_recovery_fails_closed_and_releases():
    backend = FakeBackend(WAIT_ABANDONED)
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, backend)

    def fail_recovery():
        raise OSError("journal corrupt")

    with pytest.raises(WindowsMutexError, match="recovery failed"):
        with mutex.acquire(100, recover_abandoned=fail_recovery):
            pytest.fail("must not enter after failed recovery")
    assert backend.events[-2:] == [("release", "handle"), ("close", "handle")]


def test_wait_failure_closes_handle_without_releasing_unowned_mutex():
    class FailedWaitBackend(FakeBackend):
        def wait(self, handle, timeout_ms):
            self.events.append(("wait", timeout_ms))
            raise OSError("wait failed")

    backend = FailedWaitBackend()
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, backend)
    with pytest.raises(OSError, match="wait failed"):
        with mutex.acquire(100):
            pytest.fail("wait failure must not enter")
    assert [event[0] for event in backend.events] == ["create", "wait", "close"]


@pytest.mark.parametrize("timeout", [-1, 0xFFFFFFFF, True, 1.5, "10"])
def test_rejects_invalid_timeout(timeout):
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, FakeBackend())
    with pytest.raises(ValueError):
        with mutex.acquire(timeout):
            pytest.fail("invalid timeout must not enter")


def test_requires_explicit_security_descriptor():
    with pytest.raises(ValueError, match="security descriptor"):
        WindowsNamedMutex("Global\\ApnaWin-Test", " ", FakeBackend())


def test_release_failure_is_reported_after_handle_close():
    backend = FakeBackend()
    backend.fail_release = True
    mutex = WindowsNamedMutex("Global\\ApnaWin-Test", SDDL, backend)
    with pytest.raises(WindowsMutexError, match="release or close"):
        with mutex.acquire(100):
            pass
    assert backend.events[-1] == ("close", "handle")


# Native cross-process checks run only on Windows CI. The Owner Rights ACE keeps
# the test object accessible to processes running under the same test identity.
def _hold_mutex_in_child(name, sddl, acquired, release):
    from apnawin.services.windows_named_mutex import WindowsNamedMutex

    mutex = WindowsNamedMutex(name, sddl)
    with mutex.acquire(5000):
        acquired.set()
        if not release.wait(10):
            raise RuntimeError("parent did not release child test mutex")




@pytest.mark.skipif(__import__("os").name != "nt", reason="native named mutex requires Windows")
def test_native_mutex_serializes_two_processes():
    import multiprocessing
    from uuid import uuid4

    ctx = multiprocessing.get_context("spawn")
    name = "Local\\ApnaWin-" + uuid4().hex
    sddl = "D:P(A;;GA;;;OW)"
    acquired = ctx.Event()
    release = ctx.Event()
    child = ctx.Process(target=_hold_mutex_in_child, args=(name, sddl, acquired, release))
    child.start()
    try:
        assert acquired.wait(5)
        mutex = WindowsNamedMutex(name, sddl)
        with pytest.raises(TimeoutError):
            with mutex.acquire(100):
                pytest.fail("second process entered while first owns mutex")
    finally:
        release.set()
        child.join(10)
        if child.is_alive():
            child.terminate()
            child.join(5)
    assert child.exitcode == 0


@pytest.mark.skipif(__import__("os").name != "nt", reason="native named mutex requires Windows")
def test_native_abandoned_mutex_requires_and_runs_recovery():
    import multiprocessing
    from uuid import uuid4

    ctx = multiprocessing.get_context("spawn")
    name = "Local\\ApnaWin-" + uuid4().hex
    sddl = "D:P(A;;GA;;;OW)"
    acquired = ctx.Event()
    release = ctx.Event()

    # Keep an open handle in this process. Otherwise the named kernel object
    # can be destroyed after the owner exits, and a later CreateMutex creates
    # a fresh object instead of observing WAIT_ABANDONED.
    mutex = WindowsNamedMutex(name, sddl)
    assert mutex.backend is not None
    anchor_handle, _created = mutex.backend.create(name, sddl)
    child = ctx.Process(target=_hold_mutex_in_child, args=(name, sddl, acquired, release))
    child.start()
    try:
        assert acquired.wait(5)
        # TerminateProcess the owning process while its thread holds the mutex.
        child.terminate()
        child.join(10)
        assert child.exitcode is not None

        recovered = []
        with mutex.acquire(1000, recover_abandoned=lambda: recovered.append(True)):
            assert recovered == [True]
        assert recovered == [True]
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
        mutex.backend.close(anchor_handle)
