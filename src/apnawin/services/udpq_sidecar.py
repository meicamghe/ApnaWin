"""Experimental Hysteria-v1/UDPQ client sidecar lifecycle.

This service only starts the local SOCKS5 sidecar. It is intentionally not
registered as a VPN transport until APNA's protected ALPN/config mapping is
verified and the sidecar is composed with the existing Xray/Wintun TUN engine.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from apnawin.engines.windows_job import WindowsJobProcess


def _validate_host(host: str, field: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError(f"{field} must be a non-empty host")
    if any(ord(char) < 33 or ord(char) == 127 for char in host):
        raise ValueError(f"{field} cannot contain whitespace or control characters")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if any(char in host for char in ":/\\@?#[]"):
        raise ValueError(f"{field} must be an IP address or DNS hostname")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"{field} must be a valid DNS hostname") from exc
    normalized = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    if not normalized or len(normalized) > 253:
        raise ValueError(f"{field} must be a valid DNS hostname")
    for label in normalized.split("."):
        if (
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (char.isalnum() or char == "-") for char in label)
        ):
            raise ValueError(f"{field} must be a valid DNS hostname")
    return ascii_host.lower()


def _validate_port(port: int, field: str) -> None:
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError(f"{field} must be an integer")
    if not 1 <= port <= 65535:
        raise ValueError(f"{field} must be between 1 and 65535")


def _format_host_port(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


@dataclass(frozen=True, slots=True)
class UdpqClientConfig:
    """Strict subset of the StarUDP/Hysteria-v1 client JSON configuration."""

    server_host: str
    server_port: int
    auth_str: str
    alpn: str
    server_name: str
    up_mbps: int
    down_mbps: int
    socks_host: str
    socks_port: int
    ca_file: str | None = None
    protocol: str = "udp"
    obfs: str = ""
    hop_interval: int = 10
    fast_open: bool = False
    lazy_start: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "server_host", _validate_host(self.server_host, "server_host"))
        _validate_port(self.server_port, "server_port")
        object.__setattr__(self, "server_name", _validate_host(self.server_name, "server_name"))
        if self.socks_host not in {"127.0.0.1", "::1"}:
            raise ValueError("SOCKS5 listener must bind to an IP loopback address")
        _validate_port(self.socks_port, "socks_port")
        if self.protocol not in {"udp", "wechat", "wechat-video"}:
            raise ValueError(
                "Windows supports only the upstream UDP, wechat, and wechat-video packet modes; faketcp is Linux-only"
            )
        for field in ("up_mbps", "down_mbps"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field} must be an integer")
            if not 1 <= value <= 100000:
                raise ValueError(f"{field} must be between 1 and 100000 Mbps")
        if not isinstance(self.auth_str, str) or len(self.auth_str) > 4096:
            raise ValueError("auth_str must be a string of at most 4096 characters")
        if any(ord(char) < 32 or ord(char) == 127 for char in self.auth_str):
            raise ValueError("auth_str cannot contain control characters")
        if (
            not isinstance(self.alpn, str)
            or not self.alpn
            or len(self.alpn) > 255
            or any(ord(char) < 33 or ord(char) > 126 for char in self.alpn)
        ):
            raise ValueError("alpn must be 1 to 255 visible ASCII characters")
        if not isinstance(self.obfs, str) or len(self.obfs) > 1024:
            raise ValueError("obfs must be a string of at most 1024 characters")
        if any(ord(char) < 32 or ord(char) == 127 for char in self.obfs):
            raise ValueError("obfs cannot contain control characters")
        if isinstance(self.hop_interval, bool) or not isinstance(self.hop_interval, int):
            raise TypeError("hop_interval must be an integer")
        if not 0 <= self.hop_interval <= 86400:
            raise ValueError("hop_interval must be between 0 and 86400 seconds")
        if not isinstance(self.fast_open, bool) or not isinstance(self.lazy_start, bool):
            raise TypeError("fast_open and lazy_start must be booleans")
        if self.ca_file is not None:
            if not isinstance(self.ca_file, str) or not self.ca_file:
                raise ValueError("ca_file must be a non-empty path string")
            ca_path = Path(self.ca_file).expanduser()
            if ca_path.is_symlink() or not ca_path.is_file():
                raise ValueError("ca_file must refer to a regular, non-symlink CA file")
            object.__setattr__(self, "ca_file", str(ca_path.resolve()))

    def to_json_bytes(self) -> bytes:
        """Return upstream-compatible JSON with certificate verification enabled."""
        config = {
            "server": _format_host_port(self.server_host, self.server_port),
            "protocol": self.protocol,
            "auth_str": self.auth_str,
            "alpn": self.alpn,
            "server_name": self.server_name,
            "insecure": False,
            "up_mbps": self.up_mbps,
            "down_mbps": self.down_mbps,
            "obfs": self.obfs,
            "hop_interval": self.hop_interval,
            "fast_open": self.fast_open,
            "lazy_start": self.lazy_start,
            "socks5": {
                "listen": _format_host_port(self.socks_host, self.socks_port),
                "disable_udp": False,
            },
        }
        if self.ca_file is not None:
            config["ca"] = str(Path(self.ca_file))
        encoded = json.dumps(
            config,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > 64 * 1024:
            raise ValueError("UDPQ client config exceeds 64 KiB")
        return encoded


def _probe_socks5(host: str, port: int, timeout: float) -> bool:
    """Confirm a live no-auth SOCKS5 listener, not merely an open TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall(b"\x05\x01\x00")
            return stream.recv(2) == b"\x05\x00"
    except OSError:
        return False



def load_udpq_runtime_sha256(manifest_path: str | Path) -> str:
    """Load the pinned UDPQ executable digest from the protected runtime manifest."""
    path = Path(manifest_path)
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("The installed runtime manifest is missing or unsafe")
    raw = path.read_bytes()
    if not raw or len(raw) > 64 * 1024:
        raise ValueError("The installed runtime manifest is empty or too large")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate runtime manifest key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"invalid runtime manifest constant: {value}")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("The installed runtime manifest is invalid JSON") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or not isinstance(document.get("udpq"), dict)
    ):
        raise ValueError("The installed runtime manifest has no UDPQ entry")
    digest = document["udpq"].get("executable_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in digest)
    ):
        raise ValueError("The installed runtime manifest has an invalid UDPQ SHA-256")
    return digest.lower()


class UdpqSidecarSupervisor:
    """Own a Windows UDPQ client process and its ephemeral private config file."""

    def __init__(
        self,
        executable: str | Path,
        *,
        private_dir: str | Path | None = None,
        startup_timeout: float = 30.0,
        stop_timeout: float = 10.0,
        process_factory: Callable[[str, list[str]], object] | None = None,
        socks_probe: Callable[[str, int, float], bool] = _probe_socks5,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        platform_name: str | None = None,
        expected_sha256: str | None = None,
    ) -> None:
        self.executable = Path(executable).expanduser().absolute()
        self.private_dir = (
            Path(private_dir).expanduser().absolute()
            if private_dir
            else self._default_private_dir()
        )
        self._validate_timeout(startup_timeout, "startup_timeout")
        self._validate_timeout(stop_timeout, "stop_timeout")
        self.startup_timeout = float(startup_timeout)
        self.stop_timeout = float(stop_timeout)
        self._process_factory = process_factory or self._launch_process
        self._socks_probe = socks_probe
        self._sleep = sleeper
        self._monotonic = monotonic
        self._platform_name = os.name if platform_name is None else platform_name
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected_sha256)
        ):
            raise ValueError("expected_sha256 must be a 64-character hexadecimal digest")
        self.expected_sha256 = expected_sha256.lower() if expected_sha256 else None
        self._process = None
        self._config_path: Path | None = None
        self._socks_address: tuple[str, int] | None = None

    @staticmethod
    def _validate_timeout(value: float, field: str) -> None:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{field} must be a positive number")

    @staticmethod
    def _default_private_dir() -> Path:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise OSError("LOCALAPPDATA is required for private UDPQ config storage")
        return Path(local_app_data) / "ApnaWin" / "private"

    @staticmethod
    def _launch_process(executable: str, args: list[str]) -> WindowsJobProcess:
        return WindowsJobProcess.launch(executable, args)

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def socks_address(self) -> tuple[str, int] | None:
        return self._socks_address

    def _write_private_config(self, config: bytes) -> Path:
        self.private_dir.mkdir(parents=True, exist_ok=True)
        if self.private_dir.is_symlink():
            raise OSError("UDPQ private config directory must not be a symbolic link")
        descriptor, name = tempfile.mkstemp(
            prefix="udpq-", suffix=".json", dir=self.private_dir
        )
        path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(config)
                stream.flush()
                os.fsync(stream.fileno())
            if self._platform_name != "nt":
                path.chmod(0o600)
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def start(self, config: UdpqClientConfig) -> tuple[str, int]:
        if not isinstance(config, UdpqClientConfig):
            raise TypeError("config must be a UdpqClientConfig")
        if self._platform_name != "nt":
            raise OSError("The UDPQ Windows sidecar is available only on Windows")
        if self._process is not None:
            raise RuntimeError("A UDPQ sidecar process is already owned")
        if self.executable.is_symlink() or not self.executable.is_file():
            raise FileNotFoundError("The installed UDPQ sidecar is missing or unsafe")
        with self.executable.open("rb") as executable_stream:
            if executable_stream.read(2) != b"MZ":
                raise ValueError("The UDPQ sidecar must be a Windows PE executable")
            if self.expected_sha256 is not None:
                executable_stream.seek(0)
                digest = hashlib.sha256()
                for chunk in iter(lambda: executable_stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != self.expected_sha256:
                    raise ValueError("The UDPQ sidecar SHA-256 does not match the installed runtime manifest")

        config_path = self._write_private_config(config.to_json_bytes())
        self._config_path = config_path
        try:
            self._process = self._process_factory(
                str(self.executable),
                ["--no-check", "client", "--config", str(config_path)],
            )
            deadline = self._monotonic() + self.startup_timeout
            while True:
                exit_code = self._process.poll()
                if exit_code is not None:
                    raise RuntimeError(
                        f"UDPQ sidecar exited before SOCKS5 readiness (exit code {exit_code})"
                    )
                if self._socks_probe(
                    config.socks_host, config.socks_port, min(1.0, self.startup_timeout)
                ):
                    config_path.unlink(missing_ok=True)
                    self._config_path = None
                    self._socks_address = (config.socks_host, config.socks_port)
                    return self._socks_address
                if self._monotonic() >= deadline:
                    raise TimeoutError("UDPQ sidecar did not expose a ready SOCKS5 listener")
                self._sleep(0.1)
        except Exception:
            self._stop_process()
            raise
        finally:
            if self._config_path is not None:
                self._config_path.unlink(missing_ok=True)
                self._config_path = None

    def _stop_process(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.stop_timeout)
            process.close()
        except Exception:
            # Retain ownership if termination or handle cleanup is uncertain.
            raise
        self._process = None
        self._socks_address = None

    def stop(self) -> None:
        self._stop_process()
