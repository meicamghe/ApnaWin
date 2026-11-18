"""Current-user encrypted storage for APNA SSH profile secrets and payload settings."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig
from apnawin.storage.xray_config_store import dpapi_protect, dpapi_unprotect


_FORMAT_VERSION = 1
_MAX_STORE_BYTES = 32 * 1024 * 1024
_MAX_PROFILE_BYTES = 256 * 1024


class ApnaProfileStoreError(RuntimeError):
    """APNA encrypted profile store is malformed or could not be persisted."""


def _profile_key(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("profile name must be text")
    normalized = name.strip()
    if not normalized or len(normalized) > 128 or any(ord(char) < 32 for char in normalized):
        raise ValueError("profile name must contain 1 to 128 printable characters")
    return normalized.casefold()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _serialize_config(config: ApnaTunnelSessionConfig) -> bytes:
    if not isinstance(config, ApnaTunnelSessionConfig):
        raise TypeError("config must be an ApnaTunnelSessionConfig")
    ssh = config.ssh
    payload = config.payload
    document = {
        "schema_version": 1,
        "ssh": {
            "ssh_host": ssh.ssh_host,
            "ssh_port": ssh.ssh_port,
            "username": ssh.username,
            "password": ssh.password,
            "key_filename": ssh.key_filename,
            "known_hosts_files": list(ssh.known_hosts_files),
            "host_key_sha256": ssh.host_key_sha256,
            "local_host": ssh.local_host,
            "local_port": ssh.local_port,
            "connect_timeout": ssh.connect_timeout,
            "auth_timeout": ssh.auth_timeout,
            "banner_timeout": ssh.banner_timeout,
        },
        "payload": {
            "mode": payload.mode.value,
            "connect_host": payload.connect_host,
            "connect_port": payload.connect_port,
            "target_host": payload.target_host,
            "target_port": payload.target_port,
            "payload": payload.payload,
            "sni": payload.sni,
            "cf_host": payload.cf_host,
            "brand": payload.brand,
            "user_agent": payload.user_agent,
            "protocol": payload.protocol,
            "dropbear_no_response": payload.dropbear_no_response,
            "validate_http_response": payload.validate_http_response,
            "expected_http_statuses": list(payload.expected_http_statuses),
            "connect_timeout": payload.connect_timeout,
            "read_timeout": payload.read_timeout,
            "max_response_header_bytes": payload.max_response_header_bytes,
        },
        "udpgw_host": config.udpgw_host,
        "udpgw_port": config.udpgw_port,
        "transparent_dns": config.transparent_dns,
        "dns_resolver": config.dns_resolver,
        "max_udp_flows": config.max_udp_flows,
        "keepalive_interval": config.keepalive_interval,
        "udp_idle_timeout": config.udp_idle_timeout,
        "connect_timeout": config.connect_timeout,
    }
    raw = (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError("APNA profile configuration exceeds the size limit")
    return raw


def _deserialize_config(raw: bytes) -> ApnaTunnelSessionConfig:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_PROFILE_BYTES:
        raise ApnaProfileStoreError("APNA profile plaintext is empty or exceeds the size limit")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise ApnaProfileStoreError("APNA profile plaintext is invalid JSON") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ApnaProfileStoreError("APNA profile schema version is unsupported")
    expected = {
        "schema_version", "ssh", "payload", "udpgw_host", "udpgw_port",
        "transparent_dns", "dns_resolver", "max_udp_flows", "keepalive_interval",
        "udp_idle_timeout", "connect_timeout",
    }
    if set(document) != expected:
        raise ApnaProfileStoreError("APNA profile schema has missing or unknown fields")
    ssh_raw = document["ssh"]
    payload_raw = document["payload"]
    if not isinstance(ssh_raw, dict) or not isinstance(payload_raw, dict):
        raise ApnaProfileStoreError("APNA SSH or payload settings are invalid")
    ssh_expected = {
        "ssh_host", "ssh_port", "username", "password", "key_filename",
        "known_hosts_files", "host_key_sha256", "local_host", "local_port",
        "connect_timeout", "auth_timeout", "banner_timeout",
    }
    payload_expected = {
        "mode", "connect_host", "connect_port", "target_host", "target_port",
        "payload", "sni", "cf_host", "brand", "user_agent", "protocol", "dropbear_no_response",
        "validate_http_response", "expected_http_statuses", "connect_timeout",
        "read_timeout", "max_response_header_bytes",
    }
    if set(ssh_raw) != ssh_expected or set(payload_raw) != payload_expected:
        raise ApnaProfileStoreError("APNA SSH or payload schema has missing or unknown fields")
    try:
        ssh = ApnaSshConfig(
            ssh_host=ssh_raw["ssh_host"],
            ssh_port=ssh_raw["ssh_port"],
            username=ssh_raw["username"],
            password=ssh_raw["password"],
            key_filename=ssh_raw["key_filename"],
            known_hosts_files=tuple(ssh_raw["known_hosts_files"]),
            host_key_sha256=ssh_raw["host_key_sha256"],
            local_host=ssh_raw["local_host"],
            local_port=ssh_raw["local_port"],
            connect_timeout=ssh_raw["connect_timeout"],
            auth_timeout=ssh_raw["auth_timeout"],
            banner_timeout=ssh_raw["banner_timeout"],
        )
        payload = PayloadSocketConfig(
            mode=PayloadSocketMode(payload_raw["mode"]),
            connect_host=payload_raw["connect_host"],
            connect_port=payload_raw["connect_port"],
            target_host=payload_raw["target_host"],
            target_port=payload_raw["target_port"],
            payload=payload_raw["payload"],
            sni=payload_raw["sni"],
            cf_host=payload_raw["cf_host"],
            brand=payload_raw["brand"],
            user_agent=payload_raw["user_agent"],
            protocol=payload_raw["protocol"],
            dropbear_no_response=payload_raw["dropbear_no_response"],
            validate_http_response=payload_raw["validate_http_response"],
            expected_http_statuses=tuple(payload_raw["expected_http_statuses"]),
            connect_timeout=payload_raw["connect_timeout"],
            read_timeout=payload_raw["read_timeout"],
            max_response_header_bytes=payload_raw["max_response_header_bytes"],
        )
        return ApnaTunnelSessionConfig(
            ssh=ssh,
            payload=payload,
            udpgw_host=document["udpgw_host"],
            udpgw_port=document["udpgw_port"],
            transparent_dns=document["transparent_dns"],
            dns_resolver=document["dns_resolver"],
            max_udp_flows=document["max_udp_flows"],
            keepalive_interval=document["keepalive_interval"],
            udp_idle_timeout=document["udp_idle_timeout"],
            connect_timeout=document["connect_timeout"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ApnaProfileStoreError("APNA profile contains invalid connection settings") from exc


class ApnaProfileStore:
    """Atomic encrypted profile store; secrets are protected by current-user DPAPI."""

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

    def _read(self) -> dict[str, str]:
        if self.path.is_symlink():
            raise ApnaProfileStoreError("APNA profile store must not be a symbolic link")
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(_MAX_STORE_BYTES + 1)
        except FileNotFoundError:
            return {}
        if len(raw) > _MAX_STORE_BYTES:
            raise ApnaProfileStoreError("APNA profile store exceeds the size limit")
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError) as exc:
            raise ApnaProfileStoreError("APNA profile store is invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"format_version", "profiles"}
            or document["format_version"] != _FORMAT_VERSION
            or not isinstance(document["profiles"], dict)
        ):
            raise ApnaProfileStoreError("APNA profile store schema is invalid")
        records = document["profiles"]
        if any(
            not isinstance(name, str) or not name
            or not isinstance(value, str) or not value
            for name, value in records.items()
        ):
            raise ApnaProfileStoreError("APNA profile store contains an invalid record")
        return records

    def _write(self, records: dict[str, str]) -> None:
        raw = (
            json.dumps(
                {"format_version": _FORMAT_VERSION, "profiles": records},
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")
        if len(raw) > _MAX_STORE_BYTES:
            raise ApnaProfileStoreError("APNA profile store exceeds the size limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ApnaProfileStoreError("APNA profile store must not be a symbolic link")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, profile: ConnectionProfile, config: ApnaTunnelSessionConfig) -> None:
        self.save_many([(profile, config)])

    def save_many(
        self,
        entries: list[tuple[ConnectionProfile, ApnaTunnelSessionConfig]],
    ) -> None:
        """Encrypt a batch and atomically persist it with one read/write cycle."""
        if not isinstance(entries, list):
            raise TypeError("entries must be a list")
        updates: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("each APNA entry must be a (profile, config) pair")
            profile, config = entry
            if not isinstance(profile, ConnectionProfile) or profile.transport is not Transport.APNA_SSH:
                raise TypeError("profile must be an APNA_SSH ConnectionProfile")
            if (
                config.ssh.ssh_host != profile.endpoint_host
                or config.ssh.ssh_port != profile.endpoint_port
            ):
                raise ValueError("APNA SSH settings must match the selected profile endpoint")
            key = _profile_key(profile.name)
            if key in updates:
                raise ValueError("APNA batch contains duplicate profile names")
            ciphertext = self._protect(_serialize_config(config))
            if not isinstance(ciphertext, bytes) or not ciphertext:
                raise ApnaProfileStoreError("DPAPI protector returned invalid ciphertext")
            updates[key] = base64.b64encode(ciphertext).decode("ascii")
        if not updates:
            return
        records = self._read()
        records.update(updates)
        self._write(records)

    def remove_many(self, profile_names: list[str]) -> None:
        """Remove a batch of profile records with one read/write cycle."""
        if not isinstance(profile_names, list):
            raise TypeError("profile_names must be a list")
        keys = {_profile_key(name) for name in profile_names}
        if not keys:
            return
        records = self._read()
        changed = False
        for key in keys:
            if key in records:
                del records[key]
                changed = True
        if changed:
            self._write(records)

    def has_profile(self, profile: ConnectionProfile) -> bool:
        """Return whether encrypted settings exist without decrypting secrets."""
        if not isinstance(profile, ConnectionProfile) or profile.transport is not Transport.APNA_SSH:
            raise TypeError("profile must be an APNA_SSH ConnectionProfile")
        return _profile_key(profile.name) in self._read()

    def load(self, profile: ConnectionProfile) -> ApnaTunnelSessionConfig:
        if not isinstance(profile, ConnectionProfile) or profile.transport is not Transport.APNA_SSH:
            raise TypeError("profile must be an APNA_SSH ConnectionProfile")
        key = _profile_key(profile.name)
        records = self._read()
        if key not in records:
            raise KeyError(f"No APNA SSH settings are stored for profile {profile.name!r}")
        try:
            ciphertext = base64.b64decode(records[key], validate=True)
            plaintext = self._unprotect(ciphertext)
        except Exception as exc:
            raise ApnaProfileStoreError("Could not decrypt APNA profile settings") from exc
        config = _deserialize_config(plaintext)
        if (
            config.ssh.ssh_host != profile.endpoint_host
            or config.ssh.ssh_port != profile.endpoint_port
        ):
            raise ApnaProfileStoreError("Stored APNA SSH endpoint does not match profile metadata")
        return config

    def remove(self, profile_name: str) -> None:
        key = _profile_key(profile_name)
        records = self._read()
        if key in records:
            del records[key]
            self._write(records)

    def has_config(self, profile_name: str) -> bool:
        """Return whether an encrypted APNA configuration exists for a profile."""
        key = _profile_key(profile_name)
        return key in self._read()

    def rename(self, old_profile: ConnectionProfile, new_profile: ConnectionProfile) -> None:
        """Move an encrypted APNA config to a renamed profile without exposing secrets."""
        if (
            not isinstance(old_profile, ConnectionProfile)
            or not isinstance(new_profile, ConnectionProfile)
            or old_profile.transport is not Transport.APNA_SSH
            or new_profile.transport is not Transport.APNA_SSH
        ):
            raise TypeError("old_profile and new_profile must be APNA_SSH profiles")
        config = self.load(old_profile)
        self.save(new_profile, config)
        self.remove(old_profile.name)
