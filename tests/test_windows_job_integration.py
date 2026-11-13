"""Windows-only integration coverage for real Job Object process trees."""

import os
import subprocess
import sys
import time

import pytest

from apnawin.engines.windows_job import WindowsJobProcess


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")


def test_job_object_contains_child_and_grandchild_after_root_exits(tmp_path):
    child_pid_file = tmp_path / "child.pid"
    grandchild_pid_file = tmp_path / "grandchild.pid"
    grandchild_script = "import time; time.sleep(60)"
    child_script = (
        "import subprocess,sys,time; "
        "grandchild=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
        "open(sys.argv[1],'w',encoding='ascii').write(str(grandchild.pid)); "
        "time.sleep(60)"
    )
    root_script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[2],sys.argv[4]]); "
        "open(sys.argv[1],'w',encoding='ascii').write(str(child.pid)); "
        "time.sleep(60)"
    )
    process = WindowsJobProcess.launch(
        sys.executable,
        [
            "-c", root_script, str(child_pid_file), str(grandchild_pid_file),
            child_script, grandchild_script,
        ],
    )
    try:
        deadline = time.monotonic() + 5
        while (
            (
                not child_pid_file.exists()
                or child_pid_file.stat().st_size == 0
                or not grandchild_pid_file.exists()
                or grandchild_pid_file.stat().st_size == 0
            )
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        assert child_pid_file.exists() and child_pid_file.stat().st_size > 0
        assert grandchild_pid_file.exists() and grandchild_pid_file.stat().st_size > 0
        assert int(child_pid_file.read_text(encoding="ascii")) > 0
        assert int(grandchild_pid_file.read_text(encoding="ascii")) > 0

        process.terminate()
        # The root has exited, but its child and grandchild remain active.
        assert process.poll() is None
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.25)

        process.kill()
        assert process.wait(timeout=5) is not None
        assert process._active_processes() == 0
    finally:
        if process._job_handle:
            try:
                process.kill()
                process.wait(timeout=5)
            finally:
                process.close()


def test_closing_final_job_handle_terminates_descendant_tree(tmp_path):
    import ctypes
    from ctypes import wintypes

    child_pid_file = tmp_path / "child-close.pid"
    child_script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "open(sys.argv[1],'w',encoding='ascii').write(str(child.pid)); "
        "time.sleep(60)"
    )
    process = WindowsJobProcess.launch(
        sys.executable, ["-c", child_script, str(child_pid_file)]
    )
    child_handle = None
    try:
        deadline = time.monotonic() + 5
        while not child_pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child_pid_file.exists(), "helper did not create its child process"
        child_pid = int(child_pid_file.read_text(encoding="ascii"))

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        child_handle = kernel32.OpenProcess(0x00100000, False, child_pid)
        assert child_handle, "could not open child process for exit confirmation"

        # Closing the final job handle must activate KILL_ON_JOB_CLOSE.
        process.close()
        assert kernel32.WaitForSingleObject(child_handle, 5000) == 0
    finally:
        if child_handle:
            kernel32.CloseHandle(child_handle)
        if process._job_handle:
            process.kill()
            process.close()
