import subprocess
import sys

import pytest

from apnawin.services.apk_tool import run_apkanalyzer


def test_runner_captures_bounded_output_from_both_streams():
    output = run_apkanalyzer(
        sys.executable,
        ["-c", "import sys; print('ok'); print('diagnostic', file=sys.stderr)"],
        5,
        1024,
        "failed",
        "timed out",
        "too large",
    )
    assert output.replace(b"\\r\\n", b"\\n") == b"ok\\n"


def test_runner_terminates_process_when_stdout_exceeds_limit():
    with pytest.raises(RuntimeError, match="too large"):
        run_apkanalyzer(
            sys.executable,
            ["-c", "import sys; sys.stdout.write('x' * 2000000)"],
            5,
            1024,
            "failed",
            "timed out",
            "too large",
        )


def test_runner_terminates_process_when_stderr_exceeds_limit():
    with pytest.raises(RuntimeError, match="too large"):
        run_apkanalyzer(
            sys.executable,
            ["-c", "import sys; sys.stderr.write('x' * 2000000)"],
            5,
            1024,
            "failed",
            "timed out",
            "too large",
        )


def test_runner_enforces_timeout():
    with pytest.raises(RuntimeError, match="timed out"):
        run_apkanalyzer(
            sys.executable,
            ["-c", "import time; time.sleep(10)"],
            0.1,
            1024,
            "failed",
            "timed out",
            "too large",
        )


def test_runner_sanitizes_nonzero_exit():
    with pytest.raises(RuntimeError, match="safe failure"):
        run_apkanalyzer(
            sys.executable,
            ["-c", "import sys; print('secret', file=sys.stderr); sys.exit(4)"],
            5,
            1024,
            "safe failure",
            "timed out",
            "too large",
        )
