"""Current-user DPAPI storage for experimental UDPQ profile credentials."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.udpq_sidecar import UdpqClientConfig
from apnawin.storage.xray_config_store import dpapi_protect, dpapi_unprotect

_FORMAT_VERSION = 1
_MAX_STORE_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_BYTES = 64 * 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


def _profile_key(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("profile name must be a string")
    normalized = name.strip()
    if (
        not normalized
        or len(normalized) > 128
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in normalized)
    ):
        raise ValueError("profile name must contain 1 to 128 printable characters")
    return normalized.casefold()


def _serialize_config(config: UdpqClientConfig) -> bytes:
    if not isinstance(config, UdpqClientConfig):
        raise TypeError("config must be a UdpqClientConfig")
    document = {
        "schema_version": 1,
        "server_host": config.server_host,
        "server_port": config.server_port,
        "server_port_spec": config.server_port_spec,
        "auth_str": config.auth_str,
        "alpn": config.alpn,
        "server_name": config.server_name,
        "up_mbps": config.up_mbps,
        "down_mbps": config.down_mbps,
        "socks_host": config.socks_host,
        "socks_port": config.socks_port,
        "ca_file": config.ca_file,
        "protocol": config.protocol,
        "obfs": config.obfs,
        "hop_interval": config.hop_interval,
        "fast_open": config.fast_open,
        "lazy_start": config.lazy_start,
    }
    raw = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if not raw or len(raw) > _MAX_CONFIG_BYTES:
        raise ValueError("UDPQ profile config is empty or exceeds the size limit")
    return raw


def _deserialize_config(raw: bytes) -> UdpqClientConfig:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_CONFIG_BYTES:
        raise ValueError("UDPQ profile plaintext is empty or exceeds the size limit")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("UDPQ profile plaintext is invalid JSON") from exc
    expected = {
        "schema_version", "server_host", "server_port", "server_port_spec", "auth_str", "alpn",
        "server_name", "up_mbps", "down_mbps", "socks_host", "socks_port",
        "ca_file", "protocol", "obfs", "hop_interval", "fast_open", "lazy_start",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or isinstance(document.get("schema_version"), bool)
        or not isinstance(document.get("schema_version"), int)
        or document.get("schema_version") != 1
    ):
        raise ValueError("UDPQ profile schema has missing or unknown fields")
    values = {key: value for key, value in document.items() if key != "schema_version"}
    return UdpqClientConfig(**values)


class UdpqConfigStore:
    """Atomically store UDPQ credentials encrypted with current-user Windows DPAPI."""

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
            raise OSError("UDPQ config store must not be a symbolic link")
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(_MAX_STORE_BYTES + 1)
        except FileNotFoundError:
            return {}
        if len(raw) > _MAX_STORE_BYTES:
            raise ValueError("UDPQ config store exceeds its size limit")
        try:
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ValueError("UDPQ config store is invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"format_version", "configs"}
            or isinstance(document.get("format_version"), bool)
            or not isinstance(document.get("format_version"), int)
            or document.get("format_version") != _FORMAT_VERSION
            or not isinstance(document.get("configs"), dict)
        ):
            raise ValueError("UDPQ config store schema is invalid")
        records = document["configs"]
        if any(
            not isinstance(key, str) or not key
            or not isinstance(value, str) or not value
            for key, value in records.items()
        ):
            raise ValueError("UDPQ config store contains an invalid record")
        return records

    def _write_records(self, records: dict[str, str]) -> None:
        raw = (
            json.dumps(
                {"format_version": _FORMAT_VERSION, "configs": records},
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")
        if len(raw) > _MAX_STORE_BYTES:
            raise ValueError("UDPQ config store exceeds its size limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise OSError("UDPQ config store must not be a symbolic link")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, profile: ConnectionProfile, config: UdpqClientConfig) -> None:
        if not isinstance(profile, ConnectionProfile) or profile.transport is not Transport.UDPQ:
            raise ValueError("UDPQ config requires a UDPQ connection profile")
        if (
            profile.endpoint_host.casefold().rstrip(".")
            != config.server_host.casefold().rstrip(".")
            or profile.endpoint_port != config.server_port
        ):
            # IP literals and DNS names are normalized by UdpqClientConfig.
            import ipaddress
            left = profile.endpoint_host.strip("[]")
            right = config.server_host.strip("[]")
            try:
                matches = ipaddress.ip_address(left) == ipaddress.ip_address(right)
            except ValueError:
                matches = left.casefold().rstrip(".") == right.casefold().rstrip(".")
            if not matches or profile.endpoint_port != config.server_port:
                raise ValueError("UDPQ config endpoint does not match profile metadata")
        key = _profile_key(profile.name)
        ciphertext = self._protect(_serialize_config(config))
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise ValueError("DPAPI protector returned invalid ciphertext")
        records = self._read_records()
        records[key] = base64.b64encode(ciphertext).decode("ascii")
        self._write_records(records)

    def load(self, profile_name: str) -> UdpqClientConfig:
        key = _profile_key(profile_name)
        records = self._read_records()
        if key not in records:
            raise KeyError(f"No UDPQ config is stored for profile {profile_name!r}")
        try:
            ciphertext = base64.b64decode(records[key], validate=True)
            plaintext = self._unprotect(ciphertext)
        except (ValueError, TypeError) as exc:
            raise ValueError("Stored UDPQ config could not be decrypted") from exc
        return _deserialize_config(plaintext)

    def has_config(self, profile_name: str) -> bool:
        return _profile_key(profile_name) in self._read_records()

    def rename(self, old_profile_name: str, new_profile_name: str) -> None:
        old_key = _profile_key(old_profile_name)
        new_key = _profile_key(new_profile_name)
        records = self._read_records()
        if old_key not in records:
            return
        if new_key != old_key and new_key in records:
            raise ValueError("A UDPQ config already exists for the new profile name")
        records[new_key] = records.pop(old_key)
        self._write_records(records)

    def remove_many(self, profile_names: list[str]) -> None:
        if not isinstance(profile_names, list):
            raise TypeError("profile_names must be a list")
        keys = {_profile_key(name) for name in profile_names}
        if not keys:
            return
        records = self._read_records()
        changed = False
        for key in keys:
            if key in records:
                del records[key]
                changed = True
        if changed:
            self._write_records(records)

    def remove(self, profile_name: str) -> None:
        self.remove_many([profile_name])
