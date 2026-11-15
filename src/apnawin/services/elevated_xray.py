"""UAC broker for starting Xray's native Windows TUN mode.

The desktop remains medium-integrity. A small, fixed helper installed under
Program Files receives only a profile name and the DPAPI config-store path,
decrypts the config for the same Windows user, and supervises Xray in a
kill-on-close Job Object.
"""
from __future__ import annotations

import argparse
import ctypes
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from ctypes import wintypes
from pathlib import Path

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.xray_process import XrayProcessRunner, is_windows_elevated
from apnawin.storage.xray_config_store import XrayConfigStore


_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_NOASYNC = 0x00000100
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_SYNCHRONIZE = 0x00100000
_EVENT_MODIFY_STATE = 0x0002
_ERROR_CANCELLED = 1223
_READY_EVENT_RE = re.compile(r"^Local\\ApnaWinReady-[0-9a-f]{32}$")
_STOP_EVENT_RE = re.compile(r"^Local\\ApnaWinStop-[0-9a-f]{32}$")


class ElevatedXrayError(RuntimeError):
    """Raised when the UAC broker cannot be started or supervised."""


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.DWORD),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


class _WinApi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Elevated Xray supervision is available only on Windows")
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
        self.shell32.ShellExecuteExW.restype = wintypes.BOOL
        self.kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR
        ]
        self.kernel32.CreateEventW.restype = wintypes.HANDLE
        self.kernel32.OpenEventW.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR
        ]
        self.kernel32.OpenEventW.restype = wintypes.HANDLE
        self.kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        self.kernel32.SetEvent.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
        ]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
        ]
        self.kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
        self.kernel32.GetProcessId.restype = wintypes.DWORD
        self.kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateProcess.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    @staticmethod
    def last_error() -> int:
        return ctypes.get_last_error()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _expected_helper_path() -> Path:
    program_files = os.environ.get("ProgramFiles")
    if not program_files:
        raise PermissionError("Program Files installation is required for UAC elevation")
    return Path(program_files) / "ApnaWin" / "ApnaWinElevator.exe"


def _validate_helper_path(path: str | Path) -> Path:
    raw_helper = Path(path)
    if raw_helper.is_symlink():
        raise PermissionError("Elevated helper must not be a symbolic link")
    helper = raw_helper.resolve(strict=True)
    expected = _expected_helper_path().resolve(strict=False)
    if helper != expected or not helper.is_file():
        raise PermissionError("Elevated helper must be installed at Program Files\\ApnaWin")
    return helper


def _validate_config_store_path(path: str | Path) -> Path:
    raw_store = Path(path)
    if raw_store.is_symlink():
        raise PermissionError("Encrypted config store must not be a symbolic link")
    store = raw_store.resolve(strict=True)
    roots = []
    for variable in ("APPDATA", "LOCALAPPDATA"):
        value = os.environ.get(variable)
        if value:
            roots.append((Path(value) / "ApnaWin").resolve(strict=False))
    if not any(_is_relative_to(store, root) for root in roots):
        raise PermissionError("Encrypted config store must be inside the current user's ApnaWin AppData folder")
    if store.is_symlink() or not store.is_file():
        raise PermissionError("Encrypted config store must be a regular file")
    return store


class ElevatedXrayProcess:
    """Parent-side handle for the elevated helper process."""

    def __init__(self, process_handle, stop_handle, api: _WinApi) -> None:
        self._handle = process_handle
        self._stop_handle = stop_handle
        self._api = api
        self._returncode: int | None = None

    @classmethod
    def launch(
        cls,
        helper_path: str | Path,
        config_store_path: str | Path,
        profile_name: str,
        *,
        readiness_timeout: float = 20.0,
        parent_pid: int | None = None,
        api: _WinApi | None = None,
    ) -> "ElevatedXrayProcess":
        if os.name != "nt":
            raise OSError("Elevated Xray supervision is available only on Windows")
        if (
            not isinstance(readiness_timeout, (int, float))
            or isinstance(readiness_timeout, bool)
            or not math.isfinite(readiness_timeout)
            or readiness_timeout <= 0
        ):
            raise ValueError("readiness_timeout must be a positive number")
        helper = _validate_helper_path(helper_path)
        config_store = _validate_config_store_path(config_store_path)
        if not isinstance(profile_name, str) or not profile_name.strip() or len(profile_name) > 128:
            raise ValueError("profile_name must contain 1 to 128 characters")
        if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in profile_name):
            raise ValueError("profile_name must contain printable characters")

        win = api or _WinApi()
        pid = os.getpid() if parent_pid is None else parent_pid
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("parent_pid must be a positive integer")
        event_name = f"Local\\ApnaWinReady-{uuid.uuid4().hex}"
        stop_event_name = f"Local\\ApnaWinStop-{uuid.uuid4().hex}"
        event_handle = win.kernel32.CreateEventW(None, True, False, event_name)
        if not event_handle:
            raise OSError(win.last_error(), "CreateEventW(ready) failed")
        stop_handle = win.kernel32.CreateEventW(None, True, False, stop_event_name)
        if not stop_handle:
            win.kernel32.CloseHandle(event_handle)
            raise OSError(win.last_error(), "CreateEventW(stop) failed")
        process_handle = None
        try:
            parameters = subprocess.list2cmdline([
                "--parent-pid", str(pid),
                "--ready-event", event_name,
                "--stop-event", stop_event_name,
                "--config-store", str(config_store),
                "--profile-name", profile_name,
            ])
            info = _ShellExecuteInfo()
            info.cbSize = ctypes.sizeof(_ShellExecuteInfo)
            info.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_NOASYNC
            info.lpVerb = "runas"
            info.lpFile = str(helper)
            info.lpParameters = parameters
            info.lpDirectory = str(helper.parent)
            info.nShow = _SW_HIDE
            if not win.shell32.ShellExecuteExW(ctypes.byref(info)):
                error = win.last_error()
                if error == _ERROR_CANCELLED:
                    raise ElevatedXrayError("Administrator consent was cancelled")
                raise OSError(error, "ShellExecuteExW(runas) failed")
            process_handle = info.hProcess
            if not process_handle:
                raise ElevatedXrayError("ShellExecuteExW did not return a helper process handle")

            deadline = time.monotonic() + float(readiness_timeout)
            while True:
                result = win.kernel32.WaitForSingleObject(event_handle, 50)
                if result == _WAIT_OBJECT_0:
                    return cls(process_handle, stop_handle, win)
                if result != _WAIT_TIMEOUT:
                    raise OSError(win.last_error(), "WaitForSingleObject(ready event) failed")
                if win.kernel32.WaitForSingleObject(process_handle, 0) == _WAIT_OBJECT_0:
                    code = cls._get_exit_code(win, process_handle)
                    raise ElevatedXrayError(
                        f"Elevated helper exited before Xray startup (exit code {code})"
                    )
                if time.monotonic() >= deadline:
                    raise TimeoutError("Elevated Xray helper did not become ready in time")
        except Exception:
            if process_handle:
                win.kernel32.TerminateProcess(process_handle, 1)
                win.kernel32.WaitForSingleObject(process_handle, 5000)
                win.kernel32.CloseHandle(process_handle)
            win.kernel32.CloseHandle(stop_handle)
            raise
        finally:
            win.kernel32.CloseHandle(event_handle)

    @staticmethod
    def _get_exit_code(api: _WinApi, handle) -> int:
        code = wintypes.DWORD()
        if not api.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise OSError(api.last_error(), "GetExitCodeProcess failed")
        return int(code.value)

    @property
    def pid(self) -> int:
        if not self._handle:
            raise ElevatedXrayError("Elevated helper process handle is closed")
        return int(self._api.kernel32.GetProcessId(self._handle))

    @property
    def returncode(self) -> int | None:
        return self.poll()

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        if not self._handle:
            return self._returncode
        result = self._api.kernel32.WaitForSingleObject(self._handle, 0)
        if result == _WAIT_TIMEOUT:
            return None
        if result != _WAIT_OBJECT_0:
            raise OSError(self._api.last_error(), "WaitForSingleObject(helper) failed")
        self._returncode = self._get_exit_code(self._api, self._handle)
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative number or None")
        if self._returncode is not None:
            return self._returncode
        if not self._handle:
            raise ElevatedXrayError("Elevated helper process handle is closed")
        milliseconds = _INFINITE if timeout is None else min(int(timeout * 1000), 0xFFFFFFFE)
        result = self._api.kernel32.WaitForSingleObject(self._handle, milliseconds)
        if result == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("ApnaWinElevator", timeout)
        if result != _WAIT_OBJECT_0:
            raise OSError(self._api.last_error(), "WaitForSingleObject(helper) failed")
        self._returncode = self._get_exit_code(self._api, self._handle)
        return self._returncode

    def terminate(self, *, timeout: float = 10.0) -> None:
        if self.poll() is not None:
            return
        if not self._stop_handle or not self._api.kernel32.SetEvent(self._stop_handle):
            raise OSError(self._api.last_error(), "Could not signal elevated Xray helper to stop")
        try:
            self.wait(timeout)
        except subprocess.TimeoutExpired as exc:
            raise ElevatedXrayError(
                "Elevated helper did not stop after the disconnect request"
            ) from exc

    def kill(self, *, timeout: float = 5.0) -> None:
        self.terminate(timeout=timeout)

    def close(self) -> None:
        if self.poll() is None:
            self.terminate()
        if self._handle:
            if not self._api.kernel32.CloseHandle(self._handle):
                raise OSError(self._api.last_error(), "CloseHandle(helper) failed")
            self._handle = None
        if self._stop_handle:
            if not self._api.kernel32.CloseHandle(self._stop_handle):
                raise OSError(self._api.last_error(), "CloseHandle(stop event) failed")
            self._stop_handle = None


def _open_helper_install_root() -> Path:
    executable = Path(sys.executable).resolve(strict=True)
    expected = _expected_helper_path().resolve(strict=False)
    if executable != expected:
        raise PermissionError("Elevated helper must run from Program Files\\ApnaWin")
    return executable.parent


def _cleanup_stale_configs(runtime_dir: Path) -> None:
    cutoff = time.time() - 24 * 60 * 60
    for candidate in runtime_dir.glob("xray-*.json"):
        try:
            if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                candidate.unlink()
        except OSError:
            continue


def elevated_helper_main(argv: list[str] | None = None) -> int:
    """Entry point for the PyInstaller helper built with a requireAdministrator manifest."""
    if os.name != "nt":
        return 2
    parser = argparse.ArgumentParser(prog="ApnaWinElevator")
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--ready-event", required=True)
    parser.add_argument("--stop-event", required=True)
    parser.add_argument("--config-store", required=True)
    parser.add_argument("--profile-name", required=True)
    args = parser.parse_args(argv)

    api = _WinApi()
    parent_handle = None
    event_handle = None
    stop_handle = None
    runner = None
    temp_config = None
    try:
        install_root = _open_helper_install_root()
        if not is_windows_elevated():
            return 3
        if not _READY_EVENT_RE.fullmatch(args.ready_event) or not _STOP_EVENT_RE.fullmatch(args.stop_event):
            return 4
        if args.parent_pid <= 0:
            return 5

        config_store_path = _validate_config_store_path(args.config_store)
        parent_handle = api.kernel32.OpenProcess(
            _SYNCHRONIZE, False, args.parent_pid
        )
        if not parent_handle:
            return 6
        if api.kernel32.WaitForSingleObject(parent_handle, 0) == _WAIT_OBJECT_0:
            return 7
        event_handle = api.kernel32.OpenEventW(
            _EVENT_MODIFY_STATE, False, args.ready_event
        )
        if not event_handle:
            return 8
        stop_handle = api.kernel32.OpenEventW(
            _SYNCHRONIZE, False, args.stop_event
        )
        if not stop_handle:
            return 12

        config_bytes = XrayConfigStore(config_store_path).load(args.profile_name)
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            return 9
        app_data_dir = Path(local_app_data) / "ApnaWin"
        runtime_dir = app_data_dir / "runtime"
        if app_data_dir.is_symlink() or runtime_dir.is_symlink():
            raise PermissionError("Xray runtime directory must not be a symbolic link")
        runtime_dir.mkdir(parents=True, exist_ok=True)
        _cleanup_stale_configs(runtime_dir)
        descriptor, temp_name = tempfile.mkstemp(
            prefix="xray-", suffix=".json", dir=runtime_dir
        )
        temp_config = Path(temp_name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(config_bytes)
            stream.flush()
            os.fsync(stream.fileno())

        xray_executable = install_root / "engine" / "xray.exe"
        runner = XrayProcessRunner(xray_executable, temp_config)
        profile = ConnectionProfile(
            args.profile_name, Transport.XRAY, "127.0.0.1", 443
        )
        runner.start(profile)
        if not runner.is_running:
            return 10
        if not api.kernel32.SetEvent(event_handle):
            return 11

        while True:
            stop_result = api.kernel32.WaitForSingleObject(stop_handle, 100)
            if stop_result == _WAIT_OBJECT_0:
                runner.stop()
                return 0
            if stop_result != _WAIT_TIMEOUT:
                return 13
            if api.kernel32.WaitForSingleObject(parent_handle, 0) == _WAIT_OBJECT_0:
                runner.stop()
                return 0
            if not runner.is_running:
                process = runner._process
                exit_code = getattr(process, "returncode", 1)
                runner.stop()
                return int(exit_code if exit_code is not None else 1)
    except (OSError, ValueError, PermissionError, RuntimeError, subprocess.SubprocessError):
        return 20
    finally:
        if runner is not None:
            try:
                runner.stop()
            except Exception:
                pass
        if parent_handle:
            api.kernel32.CloseHandle(parent_handle)
        if event_handle:
            api.kernel32.CloseHandle(event_handle)
        if stop_handle:
            api.kernel32.CloseHandle(stop_handle)
        if temp_config is not None:
            try:
                temp_config.unlink(missing_ok=True)
            except OSError:
                pass
