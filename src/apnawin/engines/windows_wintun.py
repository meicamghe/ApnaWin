"""Pinned, dynamically loaded native Wintun API adapter for Windows x64.

The DLL is supplied by the installer at an administrator-owned application
path. This module never downloads, searches PATH for, or bundles a driver.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import re
import uuid
from ctypes import wintypes
from pathlib import Path


_LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100
_LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
_ERROR_NO_MORE_ITEMS = 259
_ERROR_BUFFER_OVERFLOW = 111
_MAX_PACKET_SIZE = 0xFFFF
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class WintunNativeError(RuntimeError):
    """A native Wintun operation or DLL validation failed."""


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid(value: str) -> _GUID:
    if not isinstance(value, str):
        raise ValueError("requested_guid must be a UUID string")
    try:
        parsed = uuid.UUID(value.strip("{}"))
    except (ValueError, AttributeError) as exc:
        raise ValueError("requested_guid must be a valid UUID") from exc
    return _GUID.from_buffer_copy(parsed.bytes_le)


def _pe_machine(path: Path) -> int:
    """Read only the bounded PE header needed to reject non-x64 DLLs."""
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise WintunNativeError("Wintun DLL is not a valid PE image")
        offset = int.from_bytes(header[0x3C:0x40], "little")
        if offset < 64 or offset > 1024 * 1024:
            raise WintunNativeError("Wintun DLL has an invalid PE header offset")
        stream.seek(offset)
        pe = stream.read(6)
        if len(pe) != 6 or pe[:4] != b"PE\0\0":
            raise WintunNativeError("Wintun DLL has an invalid PE signature")
        return int.from_bytes(pe[4:6], "little")


def _validate_dll(path: str | os.PathLike[str], expected_sha256: str) -> Path:
    if not isinstance(expected_sha256, str) or _SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError("expected_sha256 must be a lowercase 64-character SHA-256 digest")
    candidate = Path(path)
    if candidate.is_symlink():
        raise WintunNativeError("Wintun DLL path must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise WintunNativeError("Wintun DLL is missing or inaccessible") from exc
    if not resolved.is_file():
        raise WintunNativeError("Wintun DLL path must identify a regular file")
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise WintunNativeError("Could not read Wintun DLL for integrity verification") from exc
    if digest.hexdigest() != expected_sha256:
        raise WintunNativeError("Wintun DLL SHA-256 does not match the pinned digest")
    if _pe_machine(resolved) != 0x8664:
        raise WintunNativeError("Wintun DLL architecture must be Windows x64")
    return resolved


class WindowsWintunBackend:
    """Implements WintunSessionOwner's backend and packet I/O contracts.

    The expected digest must come from a reviewed release manifest. Install the
    DLL beneath an administrator-writable-only directory to close the
    hash/load time-of-check/time-of-use window.
    """

    def __init__(
        self,
        dll_path: str | os.PathLike[str],
        *,
        expected_sha256: str,
    ) -> None:
        if os.name != "nt":
            raise WintunNativeError("Native Wintun is available only on Windows")
        self.dll_path = _validate_dll(dll_path, expected_sha256)
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise WintunNativeError("This Python runtime does not expose the Windows DLL loader")
        try:
            self._dll = loader(
                str(self.dll_path),
                use_last_error=True,
                winmode=(
                    _LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                    | _LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
                ),
            )
        except OSError as exc:
            raise WintunNativeError("Could not load the pinned Wintun DLL") from exc
        self._bind_exports()

    def _bind(self, name: str, restype, argtypes):
        try:
            function = getattr(self._dll, name)
        except AttributeError as exc:
            raise WintunNativeError(f"Wintun DLL is missing required export {name}") from exc
        function.restype = restype
        function.argtypes = argtypes
        return function

    def _bind_exports(self) -> None:
        pointer = wintypes.HANDLE
        self._create_adapter = self._bind(
            "WintunCreateAdapter", pointer,
            [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(_GUID)],
        )
        self._close_adapter = self._bind("WintunCloseAdapter", None, [pointer])
        self._get_adapter_luid = self._bind(
            "WintunGetAdapterLUID", None, [pointer, ctypes.POINTER(ctypes.c_ulonglong)]
        )
        self._start_session = self._bind(
            "WintunStartSession", pointer, [pointer, wintypes.DWORD]
        )
        self._end_session = self._bind("WintunEndSession", None, [pointer])
        self._get_read_wait_event = self._bind(
            "WintunGetReadWaitEvent", pointer, [pointer]
        )
        self._receive_packet = self._bind(
            "WintunReceivePacket", ctypes.POINTER(ctypes.c_ubyte),
            [pointer, ctypes.POINTER(wintypes.DWORD)],
        )
        self._release_receive_packet = self._bind(
            "WintunReleaseReceivePacket", None,
            [pointer, ctypes.POINTER(ctypes.c_ubyte)],
        )
        self._allocate_send_packet = self._bind(
            "WintunAllocateSendPacket", ctypes.POINTER(ctypes.c_ubyte),
            [pointer, wintypes.DWORD],
        )
        self._send_packet = self._bind(
            "WintunSendPacket", None,
            [pointer, ctypes.POINTER(ctypes.c_ubyte)],
        )

    @staticmethod
    def _last_error(operation: str) -> WintunNativeError:
        error = ctypes.get_last_error()
        return WintunNativeError(f"{operation} failed (WinError {error})")

    def create_adapter(self, name: str, tunnel_type: str, requested_guid: str):
        if (
            not isinstance(name, str) or not name or len(name) > 127
            or not isinstance(tunnel_type, str) or not tunnel_type or len(tunnel_type) > 127
            or any(ord(ch) < 32 for ch in name + tunnel_type)
        ):
            raise ValueError("Wintun adapter name and tunnel type must be bounded printable strings")
        guid = _guid(requested_guid)
        adapter = self._create_adapter(name, tunnel_type, ctypes.byref(guid))
        if not adapter:
            raise self._last_error("WintunCreateAdapter")
        return adapter

    def get_adapter_luid(self, adapter) -> int:
        luid = ctypes.c_ulonglong()
        self._get_adapter_luid(adapter, ctypes.byref(luid))
        return int(luid.value)

    def start_session(self, adapter, ring_capacity: int):
        if (
            isinstance(ring_capacity, bool) or not isinstance(ring_capacity, int)
            or not 0x20000 <= ring_capacity <= 0x4000000
            or ring_capacity & (ring_capacity - 1)
        ):
            raise ValueError("ring_capacity must be a power of two from 128 KiB to 64 MiB")
        session = self._start_session(adapter, ring_capacity)
        if not session:
            raise self._last_error("WintunStartSession")
        return session

    def end_session(self, session) -> None:
        self._end_session(session)

    def close_adapter(self, adapter) -> None:
        self._close_adapter(adapter)

    def get_read_wait_event(self, session):
        event = self._get_read_wait_event(session)
        if not event:
            raise self._last_error("WintunGetReadWaitEvent")
        # This event is owned by Wintun. The caller must not CloseHandle it.
        return event

    def receive_packet(self, session):
        """Return (buffer, release_callback), or None when the ring is empty."""
        size = wintypes.DWORD()
        packet = self._receive_packet(session, ctypes.byref(size))
        if not packet:
            error = ctypes.get_last_error()
            if error == _ERROR_NO_MORE_ITEMS:
                return None
            raise WintunNativeError(f"WintunReceivePacket failed (WinError {error})")
        if not 1 <= size.value <= _MAX_PACKET_SIZE:
            self._release_receive_packet(session, packet)
            raise WintunNativeError("Wintun returned an invalid IP packet size")
        buffer_type = ctypes.c_ubyte * int(size.value)
        buffer = buffer_type.from_address(ctypes.addressof(packet.contents))
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                self._release_receive_packet(session, packet)
                released = True

        return buffer, release

    def send_packet(self, session, packet: bytes | bytearray | memoryview) -> bool:
        """Send one IP packet; False means bounded Wintun ring backpressure."""
        try:
            view = memoryview(packet)
        except TypeError as exc:
            raise TypeError("packet must support the buffer protocol") from exc
        if view.ndim != 1 or not view.contiguous:
            raise ValueError("packet must be a contiguous one-dimensional buffer")
        data = view.cast("B")
        if not 1 <= data.nbytes <= _MAX_PACKET_SIZE:
            raise ValueError("packet size must be between 1 and 65535 bytes")
        target = self._allocate_send_packet(session, data.nbytes)
        if not target:
            error = ctypes.get_last_error()
            if error == _ERROR_BUFFER_OVERFLOW:
                return False
            raise WintunNativeError(f"WintunAllocateSendPacket failed (WinError {error})")
        ctypes.memmove(target, data.tobytes(), data.nbytes)
        self._send_packet(session, target)
        return True
