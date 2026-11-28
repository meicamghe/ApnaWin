import threading

from PySide6.QtCore import Qt

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.xray_connection_worker import XrayConnectionWorker


class FakeSupervisor:
    def __init__(self, *_args, **_kwargs):
        self.started = False
        self.stopped = False
        self.poll_result = None
        self.start_gate = None

    def start(self, _profile):
        if self.start_gate is not None:
            self.start_gate.wait(2)
        self.started = True
        return 4242

    def poll(self):
        return self.poll_result

    def stop(self):
        self.stopped = True


class FakeStore:
    pass


def profile():
    return ConnectionProfile("Office", Transport.XRAY, "vpn.example", 443)


def test_worker_emits_connected_only_after_traffic_probe_succeeds():
    events = []
    supervisor = FakeSupervisor()
    supervisor.poll_result = 0

    worker = XrayConnectionWorker(
        profile(), "helper.exe", FakeStore(),
        supervisor_factory=lambda *_args, **_kwargs: supervisor,
        traffic_probe=lambda: events.append("probe"),
        poll_interval=0.01,
    )
    worker.connected.connect(lambda pid: events.append(("connected", pid)), Qt.ConnectionType.DirectConnection)
    worker.lost.connect(lambda code: events.append(("lost", code)), Qt.ConnectionType.DirectConnection)
    worker.start()
    assert worker.wait(2000)

    assert events == ["probe", ("connected", 4242), ("lost", 0)]
    assert supervisor.started
    assert supervisor.stopped is False


def test_worker_stops_if_traffic_probe_fails_and_never_emits_connected():
    events = []
    supervisor = FakeSupervisor()

    worker = XrayConnectionWorker(
        profile(), "helper.exe", FakeStore(),
        supervisor_factory=lambda *_args, **_kwargs: supervisor,
        traffic_probe=lambda: (_ for _ in ()).throw(RuntimeError("route mismatch")),
    )
    worker.connected.connect(lambda _pid: events.append("connected"), Qt.ConnectionType.DirectConnection)
    worker.failed.connect(events.append, Qt.ConnectionType.DirectConnection)
    worker.start()
    assert worker.wait(2000)

    assert supervisor.stopped
    assert events == ["RuntimeError: route mismatch"]


def test_worker_honors_stop_requested_during_helper_startup():
    gate = threading.Event()
    supervisor = FakeSupervisor()
    supervisor.start_gate = gate
    events = []

    worker = XrayConnectionWorker(
        profile(), "helper.exe", FakeStore(),
        supervisor_factory=lambda *_args, **_kwargs: supervisor,
        traffic_probe=lambda: events.append("probe"),
    )
    worker.disconnected.connect(lambda: events.append("disconnected"), Qt.ConnectionType.DirectConnection)
    worker.start()
    worker.request_stop()
    gate.set()
    assert worker.wait(2000)

    assert supervisor.stopped
    assert events == ["disconnected"]


def test_worker_reports_unexpected_helper_exit_after_verified_connect():
    supervisor = FakeSupervisor()
    supervisor.poll_result = 17
    events = []

    worker = XrayConnectionWorker(
        profile(), "helper.exe", FakeStore(),
        supervisor_factory=lambda *_args, **_kwargs: supervisor,
        traffic_probe=lambda: None,
        poll_interval=0.001,
    )
    worker.connected.connect(lambda pid: events.append(("connected", pid)), Qt.ConnectionType.DirectConnection)
    worker.lost.connect(lambda code: events.append(("lost", code)), Qt.ConnectionType.DirectConnection)
    worker.start()
    assert worker.wait(2000)

    assert events == [("connected", 4242), ("lost", 17)]


def test_worker_retains_supervisor_when_cleanup_fails():
    events = []

    class FailingStopSupervisor(FakeSupervisor):
        def stop(self):
            raise OSError("stop event failed")

    supervisor = FailingStopSupervisor()
    worker = XrayConnectionWorker(
        profile(), "helper.exe", FakeStore(),
        supervisor_factory=lambda *_args, **_kwargs: supervisor,
        traffic_probe=lambda: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    worker.failed.connect(events.append, Qt.ConnectionType.DirectConnection)
    worker.start()
    assert worker.wait(2000)

    assert worker.cleanup_failed is True
    assert worker._supervisor is supervisor
    assert "Do not reconnect" in events[0]
