"""Windows-only integration coverage for real Job Object process trees."""

import os
import subprocess
import sys
import time

import pytest

from apnawin.engines.windows_job import WindowsJobProcess


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")


def test_job_object_contains_child_after_root_exits(tmp_path):
    child_pid_file = tmp_path / "child.pid"
    child_script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "open(sys.argv[1],'w',encoding='ascii').write(str(child.pid)); "
        "time.sleep(60)"
    )
    process = WindowsJobProcess.launch(
        sys.executable, ["-c", child_script, str(child_pid_file)]
    )
    try:
        deadline = time.monotonic() + 5
        while not child_pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child_pid_file.exists(), "helper did not create its child process"
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        assert child_pid > 0

        process.terminate()
        # The root has exited, but wait() must not report success while its
        # descendant is still active in the Job Object.
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
