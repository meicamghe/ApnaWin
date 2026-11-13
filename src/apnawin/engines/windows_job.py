"""Windows Job Object process launcher with creation-time containment.

This module is safe to import on non-Windows platforms. Win32 APIs are loaded
only when a process is launched on Windows.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from ctypes import wintypes
from dataclasses import dataclass


class WindowsJobError(RuntimeError):
    """A Windows process or Job Object operation failed."""


@dataclass
class _Win32:
    kernel32: object

    @classmethod
    def load(cls) -> "_Win32":
        if os.name != "nt":
            raise WindowsJobError("Windows Job Objects are available only on Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
        ]
        kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        kernel32.InitializeProcThreadAttributeList.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t)
        ]
        kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        kernel32.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)
        ]
        kernel32.DeleteProcThreadAttributeList.restype = None
        kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        kernel32.CreateProcessW.restype = wintypes.BOOL
        kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.c_void_p, ctypes.c_void_p
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)
        ]
        return cls(kernel32)


# Win32 constants
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_STILL_ACTIVE = 259
_INFINITE = 0xFFFFFFFF


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount"
    )]


class _BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _STARTUPINFOEX(ctypes.Structure):
    _fields_ = [("StartupInfo", _STARTUPINFO), ("lpAttributeList", ctypes.c_void_p)]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


def _raise_last_error(operation: str) -> None:
    error = ctypes.get_last_error()
    raise WindowsJobError(f"{operation} failed (WinError {error})")


class WindowsJobProcess:
    """Popen-like controller owning a root process and its complete job tree."""

    def __init__(self, api: _Win32, process_handle, job_handle, pid: int) -> None:
        self._api = api
        self._process_handle = process_handle
        self._job_handle = job_handle
        self.pid = pid
        self.returncode: int | None = None

    @classmethod
    def launch(cls, executable: str, args: list[str]) -> "WindowsJobProcess":
        api = _Win32.load()
        k = api.kernel32
        job = k.CreateJobObjectW(None, None)
        if not job:
            _raise_last_error("CreateJobObjectW")
        process_info = _PROCESS_INFORMATION()
        attribute_list = None
        attribute_buffer = None
        try:
            limits = _EXTENDED_LIMIT_INFORMATION()
            limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k.SetInformationJobObject(
                job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                _raise_last_error("SetInformationJobObject")

            size = ctypes.c_size_t()
            k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            attribute_buffer = ctypes.create_string_buffer(size.value)
            attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            if not k.InitializeProcThreadAttributeList(
                attribute_list, 1, 0, ctypes.byref(size)
            ):
                _raise_last_error("InitializeProcThreadAttributeList")

            job_array = (wintypes.HANDLE * 1)(job)
            if not k.UpdateProcThreadAttribute(
                attribute_list, 0, _PROC_THREAD_ATTRIBUTE_JOB_LIST,
                ctypes.cast(job_array, ctypes.c_void_p), ctypes.sizeof(job_array),
                None, None
            ):
                _raise_last_error("UpdateProcThreadAttribute(JOB_LIST)")

            startup = _STARTUPINFOEX()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.lpAttributeList = attribute_list
            command_line = ctypes.create_unicode_buffer(
                subprocess.list2cmdline([executable, *args])
            )
            if not k.CreateProcessW(
                executable, command_line, None, None, False,
                _EXTENDED_STARTUPINFO_PRESENT | _CREATE_NEW_PROCESS_GROUP,
                None, os.path.dirname(executable) or None,
                ctypes.byref(startup), ctypes.byref(process_info)
            ):
                _raise_last_error("CreateProcessW (Job Object assignment)")
        except Exception:
            if process_info.hProcess:
                k.TerminateProcess(process_info.hProcess, 1)
                k.WaitForSingleObject(process_info.hProcess, 5000)
                k.CloseHandle(process_info.hProcess)
            if process_info.hThread:
                k.CloseHandle(process_info.hThread)
            k.CloseHandle(job)
            raise
        finally:
            if attribute_list:
                k.DeleteProcThreadAttributeList(attribute_list)
        k.CloseHandle(process_info.hThread)
        return cls(api, process_info.hProcess, job, int(process_info.dwProcessId))

    def poll(self) -> int | None:
        if self._process_handle is None:
            return self.returncode
        code = wintypes.DWORD()
        if not self._api.kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code)):
            _raise_last_error("GetExitCodeProcess")
        if code.value == _STILL_ACTIVE:
            return None
        self.returncode = int(code.value)
        return self.returncode

    def terminate(self) -> None:
        if self.poll() is None and not self._api.kernel32.TerminateProcess(self._process_handle, 1):
            _raise_last_error("TerminateProcess")

    def kill(self) -> None:
        if self._job_handle and not self._api.kernel32.TerminateJobObject(self._job_handle, 1):
            _raise_last_error("TerminateJobObject")

    def _active_processes(self) -> int:
        info = _BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        if not self._api.kernel32.QueryInformationJobObject(
            self._job_handle, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)
        ):
            _raise_last_error("QueryInformationJobObject")
        return int(info.ActiveProcesses)

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            code = self.poll()
            if code is not None and self._active_processes() == 0:
                return code
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("Windows Job Object process tree", timeout)
            time.sleep(0.02 if deadline is None else min(0.02, max(0, deadline - time.monotonic())))

    def close(self) -> None:
        """Release ownership; KILL_ON_JOB_CLOSE is the final cleanup guard."""
        k = self._api.kernel32
        if self._process_handle:
            k.CloseHandle(self._process_handle)
            self._process_handle = None
        if self._job_handle:
            k.CloseHandle(self._job_handle)
            self._job_handle = None
