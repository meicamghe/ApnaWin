"""Cross-process Windows mutex with explicit ACL and abandoned-owner recovery.

The module is importable on non-Windows hosts; native acquisition is Windows-only.
"""
from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Protocol


WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
ERROR_ALREADY_EXISTS = 183
SDDL_REVISION_1 = 1
ERROR_INVALID_PARAMETER = 87


class WindowsMutexError(RuntimeError):
    """A Windows mutex could not be safely acquired or released."""


class MutexBackend(Protocol):
    def create(self, name: str, security_sddl: str) -> tuple[object, bool]: ...
    def wait(self, handle: object, timeout_ms: int) -> int: ...
    def release(self, handle: object) -> None: ...
    def close(self, handle: object) -> None: ...


class _NativeWindowsMutexBackend:
    """Small Win32 wrapper; all native calls are isolated here."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows named mutexes are available only on Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p
        ]
        self.kernel32.CreateMutexW.restype = ctypes.c_void_p
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        self.kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
        self.kernel32.ReleaseMutex.restype = ctypes.c_int
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int
        self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p
        ]
        self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.c_int
        )
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = ctypes.c_void_p
        self._last_error = ctypes.get_last_error

    def create(self, name: str, security_sddl: str) -> tuple[object, bool]:
        descriptor = ctypes.c_void_p()
        if not self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(self._last_error())
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", ctypes.c_uint32),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int),
            ]
        attributes = SECURITY_ATTRIBUTES(
            ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, 0
        )
        try:
            ctypes.set_last_error(0)
            handle = self.kernel32.CreateMutexW(
                ctypes.byref(attributes), False, name
            )
            error = self._last_error()
            if not handle:
                raise ctypes.WinError(error)
            return handle, error != ERROR_ALREADY_EXISTS
        finally:
            self.kernel32.LocalFree(descriptor)

    def wait(self, handle: object, timeout_ms: int) -> int:
        result = int(self.kernel32.WaitForSingleObject(handle, timeout_ms))
        if result == WAIT_FAILED:
            raise ctypes.WinError(self._last_error())
        if result not in (WAIT_OBJECT_0, WAIT_ABANDONED, WAIT_TIMEOUT):
            raise WindowsMutexError(f"unexpected WaitForSingleObject result: {result:#x}")
        return result

    def release(self, handle: object) -> None:
        if not self.kernel32.ReleaseMutex(handle):
            raise ctypes.WinError(self._last_error())

    def close(self, handle: object) -> None:
        if not self.kernel32.CloseHandle(handle):
            raise ctypes.WinError(self._last_error())


@dataclass(slots=True)
class WindowsNamedMutex:
    """Own a named mutex for one critical section.

    security_sddl is mandatory. Production callers must use a service-owned
    namespace/name and an explicit DACL granting access only to SYSTEM and the
    installed service SID. Do not accept an SDDL supplied by an IPC client.
    """

    name: str
    security_sddl: str
    backend: MutexBackend | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("mutex name must be a non-empty string")
        if not isinstance(self.security_sddl, str) or not self.security_sddl.strip():
            raise ValueError("an explicit mutex security descriptor is required")
        if self.backend is None:
            self.backend = _NativeWindowsMutexBackend()

    @contextmanager
    def acquire(
        self,
        timeout_ms: int,
        *,
        recover_abandoned: Callable[[], object] | None = None,
    ) -> Iterator[None]:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
            raise ValueError("timeout_ms must be an integer")
        if not 0 <= timeout_ms <= 0xFFFFFFFE:
            raise ValueError("timeout_ms is outside the supported finite range")
        assert self.backend is not None
        handle, _created = self.backend.create(self.name, self.security_sddl)
        owned = False
        try:
            result = self.backend.wait(handle, timeout_ms)
            if result == WAIT_TIMEOUT:
                raise TimeoutError("timed out waiting for the Windows network mutex")
            if result == WAIT_ABANDONED:
                owned = True
                if recover_abandoned is None:
                    raise WindowsMutexError(
                        "mutex owner terminated; recovery callback is required"
                    )
                try:
                    recover_abandoned()
                except Exception as exc:
                    raise WindowsMutexError(
                        "abandoned mutex recovery failed; refusing new work"
                    ) from exc
            elif result == WAIT_OBJECT_0:
                owned = True
            else:
                raise WindowsMutexError("mutex wait returned an unsupported state")
            yield
        finally:
            release_error: Exception | None = None
            if owned:
                try:
                    self.backend.release(handle)
                except Exception as exc:
                    release_error = exc
            try:
                self.backend.close(handle)
            except Exception as exc:
                if release_error is None:
                    release_error = exc
            if release_error is not None:
                raise WindowsMutexError("failed to release or close Windows mutex") from release_error
