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
