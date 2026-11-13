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
