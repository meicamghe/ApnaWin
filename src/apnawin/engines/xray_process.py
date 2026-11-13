"""Safe process supervision for a separately installed Xray executable.

This module deliberately does not claim that a running Xray process means a
working tunnel. It validates a supplied config, supervises the process, and
can check whether an explicitly configured localhost SOCKS inbound is listening.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from apnawin.domain.profile import ConnectionProfile, Transport


class XrayProcessError(RuntimeError):
    """Raised when Xray cannot be validated or supervised."""


@dataclass(frozen=True, slots=True)
class LocalSocksInbound:
    """An explicitly configured loopback-only SOCKS listener."""

    host: str
    port: int


def inspect_local_socks_inbound(config: dict) -> LocalSocksInbound:
    """Find exactly one explicit loopback SOCKS inbound; reject exposed binds."""
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError("Xray config must contain an inbounds list")

    candidates: list[LocalSocksInbound] = []
    for inbound in inbounds:
        if not isinstance(inbound, dict) or inbound.get("protocol") != "socks":
            continue
        host = inbound.get("listen")
        port = inbound.get("port")
        if not isinstance(host, str) or not host.strip():
            raise ValueError("SOCKS inbound must specify an explicit loopback listen address")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("SOCKS inbound must listen only on loopback")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("SOCKS inbound port must be an integer from 1 to 65535")
        candidates.append(LocalSocksInbound(host, port))

    if len(candidates) != 1:
        raise ValueError("Xray config must define exactly one local SOCKS inbound")
    return candidates[0]


class XrayProcessRunner:
    """Run Xray with an explicit config without shell interpolation.

    The caller must provide a complete, authorized Xray JSON config. The
    connection profile is checked for transport selection only: its host and
    port are not enough to infer an Xray outbound protocol or credentials.
    """

    def __init__(
        self,
        executable: str | Path,
        config_path: str | Path,
        *,
        validation_timeout: float = 10.0,
        stop_timeout: float = 5.0,
    ) -> None:
        self.executable = Path(executable).expanduser()
        self.config_path = Path(config_path).expanduser()
        self.validation_timeout = validation_timeout
        self.stop_timeout = stop_timeout
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _read_config(self) -> dict:
        try:
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Xray config must be readable UTF-8 JSON") from exc
        if not isinstance(config, dict):
            raise ValueError("Xray config root must be a JSON object")
        return config

    def _validate_inputs(self, profile: ConnectionProfile) -> None:
        if not isinstance(profile, ConnectionProfile):
            raise TypeError("profile must be a ConnectionProfile")
        if profile.transport is not Transport.XRAY:
            raise ValueError("Xray process runner requires an Xray profile")
        if not self.executable.is_file():
            raise FileNotFoundError(f"Xray executable not found: {self.executable}")
        if not self.config_path.is_file():
            raise FileNotFoundError(f"Xray config not found: {self.config_path}")
        self._read_config()

    def local_socks_inbound(self) -> LocalSocksInbound:
        """Return the single explicitly configured loopback SOCKS endpoint."""
        return inspect_local_socks_inbound(self._read_config())

    def is_socks_ready(self, *, connect_timeout: float = 0.5) -> bool:
        """Check local TCP listener availability, not remote tunnel health."""
        inbound = self.local_socks_inbound()
        try:
            with socket.create_connection(
                (inbound.host, inbound.port), timeout=connect_timeout
            ):
                return True
        except OSError:
            return False

    def is_socks_protocol_ready(self, *, timeout: float = 1.0) -> bool:
        """Negotiate SOCKS5 no-auth on localhost; does not test remote traffic.

        Credentials are deliberately not read or sent by this diagnostic.
        A listener requiring username/password therefore returns False.
        """
        inbound = self.local_socks_inbound()
        try:
            with socket.create_connection(
                (inbound.host, inbound.port), timeout=timeout
            ) as connection:
                connection.settimeout(timeout)
                connection.sendall(bytes((5, 1, 0)))
                return connection.recv(2) == bytes((5, 0))
        except OSError:
            return False

    def validate(self, profile: ConnectionProfile) -> None:
        """Run Xray's config test; this does not establish network connectivity."""
        self._validate_inputs(profile)
        command = [
            str(self.executable),
            "run",
            "-test",
            "-c",
            str(self.config_path),
        ]
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.validation_timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise XrayProcessError("Xray config validation timed out") from exc
        except OSError as exc:
            raise XrayProcessError("Could not execute Xray config validation") from exc
        if result.returncode != 0:
            raise XrayProcessError(
                f"Xray rejected the configuration (exit code {result.returncode})"
            )

    def start(self, profile: ConnectionProfile) -> None:
        """Validate and start Xray. A live process is not proof of a live tunnel."""
        if self.is_running:
            raise XrayProcessError("Xray is already running")
        self._validate_inputs(profile)
        self.validate(profile)
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = subprocess.Popen(
                [str(self.executable), "run", "-c", str(self.config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creationflags,
            )
        except OSError as exc:
            raise XrayProcessError("Could not start Xray") from exc
        self._process = process
        if process.poll() is not None:
            self._process = None
            raise XrayProcessError(
                f"Xray exited during startup (exit code {process.returncode})"
            )

    def stop(self) -> None:
        """Stop the supervised process; safe to call repeatedly."""
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=self.stop_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.stop_timeout)
        self._process = None
