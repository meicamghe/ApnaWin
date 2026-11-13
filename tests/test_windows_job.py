"""Platform-independent checks for the Windows Job Object boundary."""

import pytest

from apnawin.engines import windows_job


def test_windows_job_module_imports_without_windows_apis():
    assert windows_job.WindowsJobProcess is not None
    assert windows_job._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0x00002000
    assert windows_job._PROC_THREAD_ATTRIBUTE_JOB_LIST == 0x0002000D


def test_windows_api_loader_fails_clearly_off_windows(monkeypatch):
    monkeypatch.setattr(windows_job.os, "name", "posix")
    with pytest.raises(windows_job.WindowsJobError, match="only on Windows"):
        windows_job._Win32.load()


def test_job_limit_structure_sets_only_kill_on_close():
    limits = windows_job._EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = (
        windows_job._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    assert limits.BasicLimitInformation.LimitFlags == 0x00002000
    assert windows_job.ctypes.sizeof(limits) > windows_job.ctypes.sizeof(
        windows_job._BASIC_LIMIT_INFORMATION
    )


def test_windows_process_command_line_uses_windows_argument_quoting():
    import subprocess

    command = subprocess.list2cmdline(
        [r"C:\Program Files\ApnaWin\xray.exe", "run", "-c", r"C:\configs\one file.json"]
    )
    assert '"C:\\Program Files\\ApnaWin\\xray.exe"' in command
    assert '"C:\\configs\\one file.json"' in command



class FakeKernel32:
    def __init__(self, *, fail_at=None):
        self.fail_at = fail_at
        self.closed = []
        self.deleted_attribute_lists = []

    def CreateJobObjectW(self, *_args):
        return 100 if self.fail_at != "create_job" else None

    def SetInformationJobObject(self, *_args):
        return self.fail_at != "set_job_info"

    def InitializeProcThreadAttributeList(
        self, attribute_list, _count, _flags, size_pointer
    ):
        import ctypes

        ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_size_t)).contents.value = 128
        if attribute_list is None:
            return False
        return self.fail_at != "initialize_attributes"

    def UpdateProcThreadAttribute(self, *_args):
        return self.fail_at != "update_attribute"

    def CreateProcessW(self, *_args):
        return self.fail_at != "create_process"

    def DeleteProcThreadAttributeList(self, attribute_list):
        self.deleted_attribute_lists.append(attribute_list)

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


@pytest.mark.parametrize(
    "failure, expected_deleted",
    [
        ("set_job_info", 0),
        ("initialize_attributes", 0),
        ("update_attribute", 1),
        ("create_process", 1),
    ],
)
def test_launch_failure_cleans_job_and_attribute_resources(
    monkeypatch, failure, expected_deleted
):
    fake_kernel = FakeKernel32(fail_at=failure)
    monkeypatch.setattr(
        windows_job._Win32, "load",
        classmethod(lambda _cls: windows_job._Win32(fake_kernel)),
    )
    monkeypatch.setattr(
        windows_job.ctypes, "get_last_error", lambda: 5, raising=False
    )

    with pytest.raises(windows_job.WindowsJobError):
        windows_job.WindowsJobProcess.launch("xray.exe", ["run", "-c", "config.json"])

    assert fake_kernel.closed == [100]
    assert len(fake_kernel.deleted_attribute_lists) == expected_deleted



class FakeLifecycleKernel32:
    def __init__(self, *, terminate_ok=True, query_ok=True, close_failures=()):
        self.terminate_ok = terminate_ok
        self.query_ok = query_ok
        self.close_failures = list(close_failures)
        self.closed = []
        self.terminate_calls = []

    def GetExitCodeProcess(self, _handle, code_pointer):
        import ctypes

        ctypes.cast(code_pointer, ctypes.POINTER(windows_job.wintypes.DWORD)).contents.value = (
            windows_job._STILL_ACTIVE
        )
        return True

    def TerminateProcess(self, handle, exit_code):
        self.terminate_calls.append((handle, exit_code))
        return self.terminate_ok

    def QueryInformationJobObject(self, _job, _class, info_pointer, _size, _returned):
        if not self.query_ok:
            return False
        info = ctypes.cast(
            info_pointer,
            ctypes.POINTER(windows_job._BASIC_ACCOUNTING_INFORMATION),
        ).contents
        info.ActiveProcesses = 1
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        if self.close_failures and self.close_failures[0] == handle:
            self.close_failures.pop(0)
            return False
        return True


def test_terminate_failure_is_reported_without_dropping_owned_handles(monkeypatch):
    fake = FakeLifecycleKernel32(terminate_ok=False)
    monkeypatch.setattr(windows_job.ctypes, "get_last_error", lambda: 5, raising=False)
    process = windows_job.WindowsJobProcess(windows_job._Win32(fake), 10, 20, 123)

    with pytest.raises(windows_job.WindowsJobError, match="TerminateProcess"):
        process.terminate()

    assert process._process_handle == 10
    assert process._job_handle == 20
    assert fake.terminate_calls == [(10, 1)]


def test_active_process_query_failure_is_reported_and_handles_are_retained(monkeypatch):
    fake = FakeLifecycleKernel32(query_ok=False)
    monkeypatch.setattr(windows_job.ctypes, "get_last_error", lambda: 5, raising=False)
    process = windows_job.WindowsJobProcess(windows_job._Win32(fake), 10, 20, 123)

    with pytest.raises(windows_job.WindowsJobError, match="QueryInformationJobObject"):
        process.poll()

    assert process._process_handle == 10
    assert process._job_handle == 20


def test_close_preserves_job_handle_when_job_close_fails_and_can_retry(monkeypatch):
    fake = FakeLifecycleKernel32(close_failures=[20])
    monkeypatch.setattr(windows_job.ctypes, "get_last_error", lambda: 5, raising=False)
    process = windows_job.WindowsJobProcess(windows_job._Win32(fake), 10, 20, 123)

    with pytest.raises(windows_job.WindowsJobError, match="CloseHandle\\(job\\)"):
        process.close()

    assert process._process_handle is None
    assert process._job_handle == 20

    process.close()
    assert process._job_handle is None
    assert fake.closed == [10, 20, 20]
