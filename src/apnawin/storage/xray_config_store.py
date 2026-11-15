"""Per-user DPAPI encryption for imported Xray TUN configurations.

The store never writes Xray credentials in plaintext. Windows DPAPI uses the
current user scope (not LOCAL_MACHINE), so another Windows account cannot
decrypt the profile data.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import Callable

from apnawin.engines.xray_process import (
    MAX_XRAY_CONFIG_BYTES,
    _reject_json_constant,
    _unique_json_object,
    inspect_tun_inbound,
)


_FORMAT_VERSION = 1
_MAX_STORE_BYTES = 24 * 1024 * 1024
_ENTROPY = b"ApnaWin:XrayConfig:DPAPI:v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _make_blob(data: bytes):
    if not data:
        raise ValueError("DPAPI input cannot be empty")
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(
        len(data),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _windows_crypto():
    if os.name != "nt":
        raise OSError("Windows DPAPI is available only on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    protect = crypt32.CryptProtectData
    protect.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    protect.restype = wintypes.BOOL

    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    unprotect.restype = wintypes.BOOL

    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    return protect, unprotect, local_free


def dpapi_protect(plaintext: bytes) -> bytes:
    """Encrypt bytes with current-user DPAPI and application-specific entropy."""
    protect, _unprotect, local_free = _windows_crypto()
    source, source_buffer = _make_blob(plaintext)
    entropy, entropy_buffer = _make_blob(_ENTROPY)
    output = _DataBlob()
    try:
        if not protect(
            ctypes.byref(source),
            "ApnaWin Xray configuration",
            ctypes.byref(entropy),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            local_free(output.pbData)
        # Keep input buffers alive until the native call has returned.
        _ = source_buffer, entropy_buffer


def dpapi_unprotect(ciphertext: bytes) -> bytes:
    """Decrypt current-user DPAPI bytes protected by this application."""
    _protect, unprotect, local_free = _windows_crypto()
    source, source_buffer = _make_blob(ciphertext)
    entropy, entropy_buffer = _make_blob(_ENTROPY)
    output = _DataBlob()
    description = wintypes.LPWSTR()
    try:
        if not unprotect(
            ctypes.byref(source),
            ctypes.byref(description),
            ctypes.byref(entropy),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            local_free(output.pbData)
        if description:
            local_free(description)
        _ = source_buffer, entropy_buffer


def _profile_key(profile_name: str) -> str:
    if not isinstance(profile_name, str):
        raise TypeError("profile_name must be a string")
    name = profile_name.strip()
    if not name or len(name) > 128 or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in name):
        raise ValueError("profile_name must be 1 to 128 printable characters")
    return name.casefold()


def _validate_config(config_bytes: bytes) -> bytes:
    if not isinstance(config_bytes, bytes):
        raise TypeError("Xray config must be supplied as UTF-8 bytes")
    if not config_bytes or len(config_bytes) > MAX_XRAY_CONFIG_BYTES:
        raise ValueError("Xray config is empty or exceeds the configured size limit")
    try:
        text = config_bytes.decode("utf-8")
        config = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError("Xray config must be valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid Xray config JSON: {exc.msg}") from exc
    if not isinstance(config, dict):
        raise ValueError("Xray config must be a JSON object")
    inspect_tun_inbound(config)
    return config_bytes


class XrayConfigStore:
    """Atomic encrypted config storage keyed by case-insensitive profile name."""

    def __init__(
        self,
        path: str | Path,
        *,
        protect: Callable[[bytes], bytes] = dpapi_protect,
        unprotect: Callable[[bytes], bytes] = dpapi_unprotect,
    ) -> None:
        self.path = Path(path)
        self._protect = protect
        self._unprotect = unprotect

    def _read_records(self) -> dict[str, str]:
        if self.path.is_symlink():
            raise OSError("Encrypted Xray config store must not be a symbolic link")
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(_MAX_STORE_BYTES + 1)
        except FileNotFoundError:
            return {}
        if len(raw) > _MAX_STORE_BYTES:
            raise ValueError("Encrypted Xray config store exceeds its size limit")
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except UnicodeDecodeError as exc:
            raise ValueError("Encrypted Xray config store must be valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid encrypted config store JSON: {exc.msg}") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"format_version", "configs"}
            or isinstance(payload.get("format_version"), bool)
            or not isinstance(payload.get("format_version"), int)
            or payload.get("format_version") != _FORMAT_VERSION
            or not isinstance(payload.get("configs"), dict)
        ):
            raise ValueError("Encrypted Xray config store has an invalid schema")
        records = payload["configs"]
        if any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            for key, value in records.items()
        ):
            raise ValueError("Encrypted Xray config store contains an invalid record")
        return records

    def _write_records(self, records: dict[str, str]) -> None:
        payload = {
            "format_version": _FORMAT_VERSION,
            "configs": records,
        }
        serialized = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(serialized) > _MAX_STORE_BYTES:
            raise ValueError("Encrypted Xray config store exceeds its size limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise OSError("Encrypted Xray config store must not be a symbolic link")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, profile_name: str, config_bytes: bytes) -> None:
        key = _profile_key(profile_name)
        plaintext = _validate_config(config_bytes)
        ciphertext = self._protect(plaintext)
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise ValueError("DPAPI protector returned invalid ciphertext")
        records = self._read_records()
        records[key] = base64.b64encode(ciphertext).decode("ascii")
        self._write_records(records)

    def load(self, profile_name: str) -> bytes:
        key = _profile_key(profile_name)
        records = self._read_records()
        if key not in records:
            raise KeyError(f"No Xray config is stored for profile {profile_name!r}")
        try:
            ciphertext = base64.b64decode(records[key], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Stored Xray config ciphertext is not valid base64") from exc
        plaintext = self._unprotect(ciphertext)
        return _validate_config(plaintext)

    def has_config(self, profile_name: str) -> bool:
        return _profile_key(profile_name) in self._read_records()

    def rename(self, old_profile_name: str, new_profile_name: str) -> None:
        old_key = _profile_key(old_profile_name)
        new_key = _profile_key(new_profile_name)
        records = self._read_records()
        if old_key not in records:
            return
        if new_key != old_key and new_key in records:
            raise ValueError("A config is already stored for the new profile name")
        records[new_key] = records.pop(old_key)
        self._write_records(records)

    def remove(self, profile_name: str) -> None:
        key = _profile_key(profile_name)
        records = self._read_records()
        if key in records:
            del records[key]
            self._write_records(records)
