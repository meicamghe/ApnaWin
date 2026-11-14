"""Run Android SDK APK Analyzer with bounded in-memory output capture."""
from __future__ import annotations

import subprocess
import threading


def run_apkanalyzer(
    executable: str,
    args: list[str],
    timeout: float,
    max_output_bytes: int,
    failure_message: str,
    timeout_message: str,
    output_limit_message: str,
) -> bytes:
    """Capture stdout/stderr concurrently and terminate on timeout or output overflow."""
    if max_output_bytes <= 0:
        raise ValueError("output limit must be positive")
    try:
        process = subprocess.Popen(
            [executable, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise RuntimeError("apkanalyzer could not be started") from exc

    overflow = threading.Event()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}

    def drain(name: str, stream) -> None:
        buffer = buffers[name]
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                if len(buffer) + len(chunk) > max_output_bytes:
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                buffer.extend(chunk)
        finally:
            stream.close()

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join()
        raise RuntimeError(timeout_message) from exc
    for reader in readers:
        reader.join()

    if overflow.is_set():
        raise RuntimeError(output_limit_message)
    if process.returncode != 0:
        raise RuntimeError(failure_message)
    return bytes(buffers["stdout"])
