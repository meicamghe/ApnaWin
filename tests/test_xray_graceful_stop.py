import ctypes

import pytest

from apnawin.engines import windows_job
from apnawin.engines.xray_process import XrayProcessRunner


class GracefulStopKernel32:
    def __init__(self, *, send_ok=True, graceful_exit=True):
        self.send_ok = send_ok
        self.graceful_exit = graceful_exit
        self.root_exit_code = windows_job._STILL_ACTIVE
        self.active_processes = 1
        self.ctrl_events = []
        self.terminate_process_calls = []
        self.terminate_job_calls = []
        self.closed = []
        self.free_console_calls = 0

    def FreeConsole(self):
        self.free_console_calls += 1
        return True

    def AttachConsole(self, pid):
        self.attached_pid = pid
        return True

    def GenerateConsoleCtrlEvent(self, event, group_id):
        self.ctrl_events.append((event, group_id))
        if self.send_ok and self.graceful_exit:
            self.root_exit_code = 0
            self.active_processes = 0
        return self.send_ok

    def GetExitCodeProcess(self, _handle, pointer):
        ctypes.cast(
            pointer, ctypes.POINTER(windows_job.wintypes.DWORD)
        ).contents.value = self.root_exit_code
        return True

    def QueryInformationJobObject(self, _job, _class, pointer, _size, _returned):
        info = ctypes.cast(
            pointer,
            ctypes.POINTER(windows_job._BASIC_ACCOUNTING_INFORMATION),
        ).contents
        info.ActiveProcesses = self.active_processes
        return True

    def TerminateProcess(self, handle, exit_code):
        self.terminate_process_calls.append((handle, exit_code))
        self.root_exit_code = exit_code
        self.active_processes = 0
        return True

    def TerminateJobObject(self, handle, exit_code):
        self.terminate_job_calls.append((handle, exit_code))
        self.root_exit_code = exit_code
        self.active_processes = 0
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


def make_runner(tmp_path, kernel, *, stop_timeout=0.2):
    executable = tmp_path / "xray.exe"
    config = tmp_path / "config.json"
    runner = XrayProcessRunner(executable, config, stop_timeout=stop_timeout)
    process = windows_job.WindowsJobProcess(
        windows_job._Win32(kernel),
        process_handle=10,
        job_handle=20,
        pid=123,
        console_group_id=123,
    )
    runner._process = process
    return runner, process


def test_runner_prefers_graceful_ctrl_break_before_closing_job(tmp_path):
    kernel = GracefulStopKernel32(send_ok=True, graceful_exit=True)
    runner, process = make_runner(tmp_path, kernel)

    runner.stop()

    assert kernel.ctrl_events == [(windows_job._CTRL_BREAK_EVENT, 123)]
    assert kernel.terminate_process_calls == []
    assert kernel.terminate_job_calls == []
    assert runner._process is None
    assert process._job_handle is None


def test_runner_falls_back_to_root_termination_if_ctrl_break_cannot_be_sent(tmp_path):
    kernel = GracefulStopKernel32(send_ok=False)
    runner, _process = make_runner(tmp_path, kernel)

    runner.stop()

    assert kernel.ctrl_events == [(windows_job._CTRL_BREAK_EVENT, 123)]
    assert kernel.terminate_process_calls == [(10, 1)]
    assert kernel.terminate_job_calls == []
    assert runner._process is None


def test_runner_kills_job_if_graceful_ctrl_break_does_not_finish(tmp_path):
    kernel = GracefulStopKernel32(send_ok=True, graceful_exit=False)
    runner, _process = make_runner(tmp_path, kernel, stop_timeout=0.02)

    runner.stop()

    assert kernel.ctrl_events == [(windows_job._CTRL_BREAK_EVENT, 123)]
    assert kernel.terminate_process_calls == []
    assert kernel.terminate_job_calls == [(20, 1)]
    assert runner._process is None


@pytest.mark.parametrize("value", [1, None, "true"])
def test_runner_rejects_non_boolean_new_console_option(tmp_path, value):
    with pytest.raises(ValueError, match="new_console"):
        XrayProcessRunner(tmp_path / "xray.exe", tmp_path / "config.json", new_console=value)
