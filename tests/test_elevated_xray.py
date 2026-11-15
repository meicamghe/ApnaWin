import ctypes
from pathlib import Path
from types import SimpleNamespace

import pytest

from apnawin.services import elevated_xray


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class FakeKernel32:
    def __init__(self, *, ready=True, process_exits=False, parent_exits=False):
        self.ready = ready
        self.process_exits = process_exits
        self.parent_exits = parent_exits
        self.closed = []
        self.set_events = []
        self.terminated = []
        self._wait_calls = {}
        self._create_count = 0

    def CreateEventW(self, _security, _manual, _initial, _name):
        self._create_count += 1
        return 100 + self._create_count

    def WaitForSingleObject(self, handle, timeout):
        if handle == 101:
            return elevated_xray._WAIT_OBJECT_0 if self.ready else elevated_xray._WAIT_TIMEOUT
        if handle == 200:
            return elevated_xray._WAIT_OBJECT_0 if self.process_exits else elevated_xray._WAIT_TIMEOUT
        if handle == 31 and self.parent_exits and timeout == 0:
            count = self._wait_calls.get(handle, 0)
            self._wait_calls[handle] = count + 1
            return elevated_xray._WAIT_TIMEOUT if count == 0 else elevated_xray._WAIT_OBJECT_0
        if handle == 33 and timeout == 100:
            return elevated_xray._WAIT_TIMEOUT
        if handle == 31 and timeout == 0:
            return elevated_xray._WAIT_TIMEOUT
        return elevated_xray._WAIT_OBJECT_0

    def GetExitCodeProcess(self, _handle, pointer):
        ctypes.cast(pointer, ctypes.POINTER(elevated_xray.wintypes.DWORD)).contents.value = 0
        return True

    def GetProcessId(self, _handle):
        return 1234

    def TerminateProcess(self, handle, code):
        self.terminated.append((handle, code))
        self.process_exits = True
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True

    def SetEvent(self, handle):
        self.set_events.append(handle)
        if handle == 102:
            self.process_exits = True
        return True

    def OpenProcess(self, _access, _inherit, _pid):
        return 31

    def OpenEventW(self, _access, _inherit, name):
        return 32 if "Ready-" in name else 33


class FakeShell32:
    def __init__(self, *, success=True, handle=200):
        self.success = success
        self.handle = handle
        self.info = None
        self.ShellExecuteExW = FakeFunction(self._shell_execute)

    def _shell_execute(self, pointer):
        info = ctypes.cast(
            pointer, ctypes.POINTER(elevated_xray._ShellExecuteInfo)
        ).contents
        self.info = SimpleNamespace(
            lpVerb=info.lpVerb,
            lpFile=info.lpFile,
            lpParameters=info.lpParameters,
            lpDirectory=info.lpDirectory,
            nShow=info.nShow,
        )
        info.hProcess = self.handle
        return self.success


class FakeApi:
    def __init__(self, *, shell_success=True, ready=True, process_exits=False):
        self.kernel32 = FakeKernel32(ready=ready, process_exits=process_exits)
        self.shell32 = FakeShell32(success=shell_success)
        self.error = 1223 if not shell_success else 0

    def last_error(self):
        return self.error


def setup_install_paths(tmp_path, monkeypatch):
    program_files = tmp_path / "Program Files"
    appdata = tmp_path / "AppData"
    helper = program_files / "ApnaWin" / "ApnaWinElevator.exe"
    store = appdata / "ApnaWin" / "xray-configs.json"
    helper.parent.mkdir(parents=True)
    store.parent.mkdir(parents=True)
    helper.write_bytes(b"helper")
    store.write_bytes(b"encrypted store")
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.setenv("APPDATA", str(appdata))
    return helper, store


def test_elevated_launcher_uses_runas_and_returns_supervisor_handle(tmp_path, monkeypatch):
    helper, store = setup_install_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    api = FakeApi()
    process = elevated_xray.ElevatedXrayProcess.launch(
        helper, store, "Office", api=api
    )
    assert api.shell32.info.lpVerb == "runas"
    assert api.shell32.info.lpFile == str(helper)
    assert "--profile-name Office" in api.shell32.info.lpParameters
    assert "--stop-event" in api.shell32.info.lpParameters
    assert process.pid == 1234
    assert process.poll() is None
    process.terminate()
    assert api.kernel32.set_events == [102]
    assert process.returncode == 0
    process.close()
    assert 200 in api.kernel32.closed
    assert 102 in api.kernel32.closed


def test_ensure_tun_adapter_available_refuses_existing_adapter():
    from types import SimpleNamespace

    class Diagnostics:
        def __init__(self, **kwargs):
            assert kwargs["adapter_name"] == "ApnaWin"
        def snapshot(self):
            return SimpleNamespace(adapter_present=True)

    inbound = SimpleNamespace(name="ApnaWin")
    with pytest.raises(elevated_xray.ElevatedXrayError, match="refusing to reuse"):
        elevated_xray._ensure_tun_adapter_available(
            inbound, diagnostics_factory=Diagnostics
        )


def test_ensure_tun_adapter_available_accepts_absent_adapter():
    from types import SimpleNamespace

    class Diagnostics:
        def __init__(self, **kwargs):
            pass
        def snapshot(self):
            return SimpleNamespace(adapter_present=False)

    inbound = SimpleNamespace(name="ApnaWin")
    snapshot = elevated_xray._ensure_tun_adapter_available(
        inbound, diagnostics_factory=Diagnostics
    )
    assert snapshot.adapter_present is False


def test_tun_snapshot_matches_requires_every_configured_dns_server():
    from types import SimpleNamespace

    inbound = SimpleNamespace(dns=("1.1.1.1", "9.9.9.9"))
    snapshot = SimpleNamespace(
        routing_ready=True,
        dns_servers=("1.1.1.1",),
    )
    assert not elevated_xray._tun_snapshot_matches(snapshot, inbound)
    snapshot.dns_servers = ("1.1.1.1", "9.9.9.9", "8.8.8.8")
    assert elevated_xray._tun_snapshot_matches(snapshot, inbound)


def test_wait_for_tun_network_ready_requires_stable_routes_and_dns():
    from types import SimpleNamespace

    class Clock:
        now = 0.0
        def monotonic(self):
            return self.now
        def sleep(self, seconds):
            self.now += seconds

    class Kernel:
        def WaitForSingleObject(self, _handle, _timeout):
            return elevated_xray._WAIT_TIMEOUT

    class Api:
        kernel32 = Kernel()

    class Runner:
        is_running = True

    class Diagnostics:
        def __init__(self, **kwargs):
            assert kwargs["adapter_name"] == "ApnaWin"
        def snapshot(self):
            return SimpleNamespace(
                routing_ready=True,
                dns_servers=("1.1.1.1", "2606:4700:4700::1111"),
            )

    clock = Clock()
    inbound = SimpleNamespace(
        name="ApnaWin",
        dns=("1.1.1.1", "2606:4700:4700::1111"),
    )
    snapshot = elevated_xray._wait_for_tun_network_ready(
        Runner(), inbound,
        stop_handle=11, parent_handle=12, api=Api(),
        timeout=3, poll_interval=0.25, stable_for=0.5,
        diagnostics_factory=Diagnostics,
        monotonic=clock.monotonic, sleep=clock.sleep,
    )
    assert snapshot.routing_ready


def test_wait_for_tun_network_ready_rejects_missing_configured_dns():
    from types import SimpleNamespace

    class Clock:
        now = 0.0
        def monotonic(self):
            return self.now
        def sleep(self, seconds):
            self.now += seconds

    class Kernel:
        def WaitForSingleObject(self, _handle, _timeout):
            return elevated_xray._WAIT_TIMEOUT

    class Api:
        kernel32 = Kernel()

    class Runner:
        is_running = True

    class Diagnostics:
        def __init__(self, **kwargs):
            pass
        def snapshot(self):
            return SimpleNamespace(
                routing_ready=True,
                dns_servers=("1.1.1.1",),
            )

    clock = Clock()
    inbound = SimpleNamespace(name="ApnaWin", dns=("9.9.9.9",))
    with pytest.raises(TimeoutError, match="configured DNS"):
        elevated_xray._wait_for_tun_network_ready(
            Runner(), inbound,
            stop_handle=11, parent_handle=12, api=Api(),
            timeout=0.5, poll_interval=0.25, stable_for=0.25,
            diagnostics_factory=Diagnostics,
            monotonic=clock.monotonic, sleep=clock.sleep,
        )


def test_wait_for_tun_network_ready_aborts_when_desktop_exits():
    class Kernel:
        def WaitForSingleObject(self, handle, _timeout):
            return (
                elevated_xray._WAIT_OBJECT_0
                if handle == 12 else elevated_xray._WAIT_TIMEOUT
            )

    class Api:
        kernel32 = Kernel()

    class Runner:
        is_running = True

    class Diagnostics:
        def __init__(self, **kwargs):
            pytest.fail("diagnostics must not run after desktop exit")

    inbound = type("Inbound", (), {"name": "ApnaWin", "dns": ("1.1.1.1",)})()
    with pytest.raises(InterruptedError, match="Desktop process exited"):
        elevated_xray._wait_for_tun_network_ready(
            Runner(), inbound,
            stop_handle=11, parent_handle=12, api=Api(),
            diagnostics_factory=Diagnostics,
        )


def test_elevated_launcher_requests_graceful_stop_after_readiness_timeout(
    tmp_path, monkeypatch
):
    helper, store = setup_install_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    api = FakeApi(ready=False)

    with pytest.raises(TimeoutError, match="did not become ready"):
        elevated_xray.ElevatedXrayProcess.launch(
            helper, store, "Office", readiness_timeout=0.001, api=api
        )

    assert api.kernel32.set_events == [102]
    assert api.kernel32.terminated == []
    assert 200 in api.kernel32.closed
    assert 102 in api.kernel32.closed


def test_elevated_launcher_reports_cancelled_uac_consent(tmp_path, monkeypatch):
    helper, store = setup_install_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    api = FakeApi(shell_success=False)
    with pytest.raises(elevated_xray.ElevatedXrayError, match="consent was cancelled"):
        elevated_xray.ElevatedXrayProcess.launch(helper, store, "Office", api=api)


def test_elevated_launcher_rejects_helper_outside_program_files(tmp_path, monkeypatch):
    _helper, store = setup_install_paths(tmp_path, monkeypatch)
    outside = tmp_path / "Downloads" / "ApnaWinElevator.exe"
    outside.parent.mkdir()
    outside.write_bytes(b"untrusted helper")
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    with pytest.raises(PermissionError, match="Program Files"):
        elevated_xray.ElevatedXrayProcess.launch(outside, store, "Office", api=FakeApi())


def test_elevated_launcher_rejects_config_store_outside_appdata(tmp_path, monkeypatch):
    helper, _store = setup_install_paths(tmp_path, monkeypatch)
    outside = tmp_path / "Downloads" / "xray-configs.json"
    outside.parent.mkdir()
    outside.write_bytes(b"not encrypted")
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    with pytest.raises(PermissionError, match="AppData"):
        elevated_xray.ElevatedXrayProcess.launch(helper, outside, "Office", api=FakeApi())


def test_elevated_launcher_rejects_symlinked_helper_or_store(tmp_path, monkeypatch):
    helper, store = setup_install_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    helper_link = helper.parent / "helper-link.exe"
    store_link = store.parent / "store-link.json"
    try:
        helper_link.symlink_to(helper)
        store_link.symlink_to(store)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(PermissionError, match="symbolic link"):
        elevated_xray.ElevatedXrayProcess.launch(helper_link, store, "Office", api=FakeApi())
    with pytest.raises(PermissionError, match="symbolic link"):
        elevated_xray.ElevatedXrayProcess.launch(helper, store_link, "Office", api=FakeApi())


def test_helper_supervises_xray_until_parent_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated_xray.os, "name", "nt")
    monkeypatch.setattr(elevated_xray, "_open_helper_install_root", lambda: tmp_path)
    verified_runtime = []
    monkeypatch.setattr(elevated_xray, "verify_vpn_runtime", lambda path: verified_runtime.append(Path(path)))
    monkeypatch.setattr(elevated_xray, "_validate_config_store_path", lambda path: Path(path))
    monkeypatch.setattr(elevated_xray, "is_windows_elevated", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    (tmp_path / "LocalAppData").mkdir()

    class FakeStore:
        def __init__(self, _path):
            pass

        def load(self, _profile_name):
            return b'{"inbounds":[],"outbounds":[]}'

    class FakeRunner:
        instance = None

        def __init__(self, executable, config, *, new_console=False):
            self.executable = executable
            self.config = config
            self.new_console = new_console
            self.running = False
            self._process = SimpleNamespace(returncode=0)
            FakeRunner.instance = self

        @property
        def is_running(self):
            return self.running

        def _read_config(self):
            return {
                "inbounds": [{
                    "protocol": "tun",
                    "settings": {
                        "name": "ApnaWin",
                        "gateway": ["10.0.0.1/30", "fd00::1/126"],
                        "dns": ["1.1.1.1"],
                        "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                        "autoOutboundsInterface": "auto",
                        "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
                    },
                }],
                "outbounds": [{"protocol": "freedom"}],
            }

        def start(self, _profile):
            self.running = True

        def stop(self):
            self.running = False

    api = FakeApi()
    api.kernel32 = FakeKernel32(parent_exits=True)
    monkeypatch.setattr(elevated_xray, "_WinApi", lambda: api)
    monkeypatch.setattr(elevated_xray, "XrayConfigStore", FakeStore)
    monkeypatch.setattr(elevated_xray, "XrayProcessRunner", FakeRunner)
    monkeypatch.setattr(
        elevated_xray, "_wait_for_tun_network_ready",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        elevated_xray, "_ensure_tun_adapter_available",
        lambda *_args, **_kwargs: None,
    )
    egress_probes = []
    monkeypatch.setattr(
        elevated_xray, "probe_tun_egress",
        lambda: egress_probes.append(True),
    )

    ready_name = "Local\\ApnaWinReady-" + "a" * 32
    stop_name = "Local\\ApnaWinStop-" + "b" * 32
    result = elevated_xray.elevated_helper_main([
        "--parent-pid", "55",
        "--ready-event", ready_name,
        "--stop-event", stop_name,
        "--config-store", str(tmp_path / "xray-configs.json"),
        "--profile-name", "Office",
    ])
    assert result == 0
    assert FakeRunner.instance is not None
    assert verified_runtime == [tmp_path / "engine"]
    assert egress_probes == [True]
    assert FakeRunner.instance.running is False
    assert FakeRunner.instance.new_console is True
    assert api.kernel32.set_events == [32]
    assert not list((tmp_path / "LocalAppData" / "ApnaWin" / "runtime").glob("xray-*.json"))
