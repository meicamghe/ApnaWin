"""Safe process supervision for a separately installed Xray executable.

This module deliberately does not claim that a running Xray process means a
working tunnel. It validates a supplied config, supervises the process, and
can check whether an explicitly configured localhost SOCKS inbound is listening.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.windows_job import WindowsJobProcess, WindowsJobError


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
        self._validate_timeout(validation_timeout, "validation_timeout")
        self._validate_timeout(stop_timeout, "stop_timeout")
        self.executable = Path(executable).expanduser()
        self.config_path = Path(config_path).expanduser()
        self.validation_timeout = float(validation_timeout)
        self.stop_timeout = float(stop_timeout)
        self._process: subprocess.Popen[bytes] | WindowsJobProcess | None = None

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
        config = self._read_config()
        # The runner exposes this local proxy to the desktop client. Refuse
        # wildcard/non-loopback binds before either validation or launch so a
        # malformed profile cannot accidentally publish an unauthenticated proxy.
        inspect_local_socks_inbound(config)

    def local_socks_inbound(self) -> LocalSocksInbound:
        """Return the single explicitly configured loopback SOCKS endpoint."""
        return inspect_local_socks_inbound(self._read_config())

    @staticmethod
    def _validate_timeout(timeout: float, name: str = "timeout") -> None:
        """Reject values that socket APIs cannot use as a bounded timeout."""
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError(f"{name} must be a finite positive number")

    @classmethod
    def _read_socks_reply(cls, connection: socket.socket) -> int:
        """Consume and validate a complete SOCKS5 CONNECT reply; return REP."""
        version, reply, reserved, address_type = cls._recv_exact(connection, 4)
        if version != 5 or reserved != 0:
            raise OSError("malformed SOCKS5 reply header")
        if address_type == 1:
            address_length = 4
        elif address_type == 4:
            address_length = 16
        elif address_type == 3:
            address_length = cls._recv_exact(connection, 1)[0]
            if address_length == 0:
                raise OSError("malformed SOCKS5 domain reply")
        else:
            raise OSError("unsupported SOCKS5 reply address type")
        cls._recv_exact(connection, address_length + 2)
        return reply

    def is_socks_ready(self, *, connect_timeout: float = 0.5) -> bool:
        """Check local TCP listener availability, not remote tunnel health."""
        self._validate_timeout(connect_timeout, "connect_timeout")
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
        self._validate_timeout(timeout)
        inbound = self.local_socks_inbound()
        try:
            with socket.create_connection(
                (inbound.host, inbound.port), timeout=timeout
            ) as connection:
                connection.settimeout(timeout)
                connection.sendall(bytes((5, 1, 0)))
                return self._recv_exact(connection, 2) == bytes((5, 0))
        except OSError:
            return False

    @staticmethod
    def _recv_exact(connection: socket.socket, size: int) -> bytes:
        """Read exactly size bytes or fail on a truncated SOCKS response."""
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise OSError("truncated SOCKS5 response")
            chunks.extend(chunk)
        return bytes(chunks)

    def socks_connect(self, destination_host: str, destination_port: int, *, timeout: float = 3.0) -> bool:
        """Ask the local SOCKS5 proxy to CONNECT to an explicit destination.

        This performs a real outbound connection attempt through the proxy.
        Callers must supply a destination they are authorized to test. No
        credentials are sent; only SOCKS5 no-authentication is supported.
        True means the proxy replied SOCKS5 success, not that application
        data was exchanged or that the full VPN routing configuration works.
        """
        if not isinstance(destination_host, str) or not destination_host.strip():
            raise ValueError("destination_host must be a non-empty hostname or IP address")
        if isinstance(destination_port, bool) or not isinstance(destination_port, int) or not 1 <= destination_port <= 65535:
            raise ValueError("destination_port must be an integer from 1 to 65535")
        self._validate_timeout(timeout)
        host = destination_host.strip()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                encoded_host = host.encode("idna")
            except UnicodeError as exc:
                raise ValueError("destination_host is not a valid IDNA hostname") from exc
            if not encoded_host or len(encoded_host) > 255:
                raise ValueError("destination hostname must be 1 to 255 encoded bytes")
            destination = bytes((3, len(encoded_host))) + encoded_host
        else:
            if address.version == 4:
                destination = bytes((1,)) + address.packed
            else:
                destination = bytes((4,)) + address.packed
        request = bytes((5, 1, 0)) + destination + destination_port.to_bytes(2, "big")
        inbound = self.local_socks_inbound()
        try:
            with socket.create_connection((inbound.host, inbound.port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall(bytes((5, 1, 0)))
                if self._recv_exact(connection, 2) != bytes((5, 0)):
                    return False
                connection.sendall(request)
                return self._read_socks_reply(connection) == 0
        except OSError:
            return False

    def socks_exchange(
        self,
        destination_host: str,
        destination_port: int,
        payload: bytes,
        *,
        timeout: float = 3.0,
        max_response_bytes: int = 65536,
    ) -> bytes | None:
        """Send bounded application bytes through SOCKS5 and read to EOF.

        Returns response bytes on a clean EOF, or None on socket/proxy failure.
        The caller owns payload framing and must choose an authorized endpoint.
        A response-size overflow raises ValueError rather than truncating data.
        This does not establish system-wide tunnel routing.
        """
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if not isinstance(destination_host, str) or not destination_host.strip():
            raise ValueError("destination_host must be a non-empty hostname or IP address")
        if isinstance(destination_port, bool) or not isinstance(destination_port, int) or not 1 <= destination_port <= 65535:
            raise ValueError("destination_port must be an integer from 1 to 65535")

        host = destination_host.strip()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                encoded_host = host.encode("idna")
            except UnicodeError as exc:
                raise ValueError("destination_host is not a valid IDNA hostname") from exc
            if not encoded_host or len(encoded_host) > 255:
                raise ValueError("destination hostname must be 1 to 255 encoded bytes")
            destination = bytes((3, len(encoded_host))) + encoded_host
        else:
            destination = (bytes((1,)) + address.packed if address.version == 4
                           else bytes((4,)) + address.packed)
        request = bytes((5, 1, 0)) + destination + destination_port.to_bytes(2, "big")
        inbound = self.local_socks_inbound()
        try:
            with socket.create_connection((inbound.host, inbound.port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall(bytes((5, 1, 0)))
                if self._recv_exact(connection, 2) != bytes((5, 0)):
                    return None
                connection.sendall(request)
                if self._read_socks_reply(connection) != 0:
                    return None
                if payload:
                    connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    chunk = connection.recv(min(4096, max_response_bytes + 1 - len(response)))
                    if not chunk:
                        return bytes(response)
                    response.extend(chunk)
                    if len(response) > max_response_bytes:
                        raise ValueError("SOCKS response exceeded max_response_bytes")
        except OSError:
            return None

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
        try:
            if os.name == "nt":
                # Creation-time JOB_LIST assignment prevents descendants from
                # escaping between process creation and later job assignment.
                process = WindowsJobProcess.launch(
                    str(self.executable), ["run", "-c", str(self.config_path)]
                )
            else:
                process = subprocess.Popen(
                    [str(self.executable), "run", "-c", str(self.config_path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                )
        except (OSError, WindowsJobError) as exc:
            raise XrayProcessError("Could not start contained Xray process") from exc
        self._process = process
        if process.poll() is not None:
            if isinstance(process, WindowsJobProcess):
                try:
                    process.close()
                except WindowsJobError as exc:
                    self._process = process
                    raise XrayProcessError("Could not release Xray process handles") from exc
            self._process = None
            raise XrayProcessError(
                f"Xray exited during startup (exit code {process.returncode})"
            )

    def stop(self) -> None:
        """Stop the process and confirm exit before releasing its reference.

        If termination fails while the child is still alive, retain the process
        handle so the caller can inspect/retry instead of reporting a false stop.
        """
        process = self._process
        if process is None:
            return
        if isinstance(process, WindowsJobProcess):
            try:
                # Terminate the root first, then require the whole job to drain.
                process.terminate()
                try:
                    process.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.stop_timeout)
            except (OSError, WindowsJobError, subprocess.TimeoutExpired) as exc:
                raise XrayProcessError(
                    "Could not confirm that the Xray Job Object process tree stopped"
                ) from exc
            try:
                process.close()
            except WindowsJobError as exc:
                raise XrayProcessError("Could not release Xray process handles") from exc
            self._process = None
            return
        if process.poll() is not None:
            self._process = None
            return

        try:
            process.terminate()
        except OSError as exc:
            if process.poll() is None:
                raise XrayProcessError("Could not request Xray termination") from exc

        if process.poll() is None:
            try:
                process.wait(timeout=self.stop_timeout)
            except subprocess.TimeoutExpired:
                if os.name == "nt" and getattr(process, "pid", None) is not None:
                    # taskkill /T asks Windows to include descendants when the
                    # supervised process is still present. Fall back to Popen.kill
                    # if taskkill is unavailable or cannot complete. Lightweight
                    # process doubles without a PID use the direct kill fallback.
                    try:
                        tree_result = subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=self.stop_timeout,
                            check=False,
                            shell=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        tree_result = None
                    if tree_result is not None and tree_result.returncode == 0:
                        try:
                            process.wait(timeout=self.stop_timeout)
                        except subprocess.TimeoutExpired:
                            pass
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError as exc:
                        if process.poll() is None:
                            raise XrayProcessError("Could not force-stop Xray") from exc
                try:
                    process.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired as exc:
                    raise XrayProcessError(
                        "Xray did not exit after the force-stop request"
                    ) from exc
                except OSError as exc:
                    if process.poll() is None:
                        raise XrayProcessError("Could not confirm Xray process exit") from exc
            except OSError as exc:
                if process.poll() is None:
                    raise XrayProcessError("Could not wait for Xray to stop") from exc

        if process.poll() is not None:
            self._process = None
        else:
            raise XrayProcessError("Xray is still running after the stop request")
