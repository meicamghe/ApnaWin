"""Safe process supervision for a separately installed Xray executable.

This module deliberately does not claim that a running Xray process means a
working tunnel. It validates a supplied config, supervises the process, and
can check whether an explicitly configured localhost SOCKS inbound is listening.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import math
import os
import socket
import subprocess
import time
from dataclasses import dataclass


MAX_XRAY_CONFIG_BYTES = 16 * 1024 * 1024
from pathlib import Path

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.windows_job import WindowsJobProcess, WindowsJobError


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Build a JSON object while rejecting ambiguous duplicate keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject JavaScript-style non-finite values accepted by json.loads by default."""
    raise ValueError(f"Invalid JSON constant: {value}")


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

    if len(inbounds) != 1:
        raise ValueError("Xray config must define exactly one inbound")

    inbound = inbounds[0]
    if not isinstance(inbound, dict):
        raise ValueError("Xray inbound must be an object")
    if inbound.get("protocol") != "socks":
        raise ValueError("Xray's single inbound must use the SOCKS protocol")

    host = inbound.get("listen")
    port = inbound.get("port")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("SOCKS inbound must specify an explicit loopback listen address")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("SOCKS inbound must listen only on loopback")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("SOCKS inbound port must be an integer from 1 to 65535")
    return LocalSocksInbound(host, port)


@dataclass(frozen=True, slots=True)
class XrayTunInbound:
    """Validated full-tunnel inbound managed by Xray's native Windows TUN backend."""

    name: str
    desc: str
    mtu: int
    gateway: tuple[str, ...]
    dns: tuple[str, ...]
    routes: tuple[str, ...]
    auto_outbounds_interface: str
    leak_protection: tuple[str, ...]


def inspect_tun_inbound(config: dict) -> XrayTunInbound:
    """Validate the strict Windows full-tunnel policy before running Xray."""
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or len(inbounds) != 1:
        raise ValueError("Xray TUN config must define exactly one inbound")
    inbound = inbounds[0]
    if not isinstance(inbound, dict) or inbound.get("protocol") != "tun":
        raise ValueError("Xray's single inbound must use the TUN protocol")
    if set(inbound) - {"tag", "protocol", "settings", "port"}:
        raise ValueError("Xray TUN inbound contains unsupported fields")
    if "port" in inbound:
        port = inbound["port"]
        if isinstance(port, bool) or not isinstance(port, int) or port != 0:
            raise ValueError("Xray TUN inbound port must be omitted or zero")
    settings = inbound.get("settings")
    allowed = {
        "name", "desc", "mtu", "gateway", "dns", "userLevel",
        "autoSystemRoutingTable", "autoOutboundsInterface",
        "autoSystemDnsToGateway", "autoSystemWfpBlockLeak",
    }
    if not isinstance(settings, dict) or set(settings) - allowed:
        raise ValueError("Xray TUN settings are missing or contain unsupported fields")

    name = settings.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("Xray TUN name must contain 1 to 128 characters")
    if name != name.strip() or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in name):
        raise ValueError("Xray TUN name must be trimmed printable text")
    desc = settings.get("desc", "Wintun")
    if not isinstance(desc, str) or not desc.strip() or len(desc) > 128:
        raise ValueError("Xray TUN desc must contain 1 to 128 characters")
    if desc != desc.strip() or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in desc):
        raise ValueError("Xray TUN desc must be trimmed printable text")

    mtu = settings.get("mtu", 1500)
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 9000:
        raise ValueError("Xray TUN MTU must be an integer from 576 through 9000")

    gateway_raw = settings.get("gateway")
    if not isinstance(gateway_raw, list) or len(gateway_raw) != 2:
        raise ValueError("Xray TUN gateway must define one IPv4 and one IPv6 prefix")
    gateway: list[str] = []
    gateway_families: set[int] = set()
    for value in gateway_raw:
        if not isinstance(value, str):
            raise ValueError("Xray TUN gateway entries must be CIDR strings")
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError as exc:
            raise ValueError("Xray TUN gateway contains an invalid IP prefix") from exc
        address = interface.ip
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("Xray TUN gateway addresses must be usable unicast addresses")
        if address.version in gateway_families:
            raise ValueError("Xray TUN gateway must contain one prefix per IP family")
        gateway_families.add(address.version)
        gateway.append(str(interface))
    if gateway_families != {4, 6}:
        raise ValueError("Xray TUN gateway must include IPv4 and IPv6")

    dns_raw = settings.get("dns")
    if not isinstance(dns_raw, list) or not 1 <= len(dns_raw) <= 8:
        raise ValueError("Xray TUN DNS must contain 1 to 8 server addresses")
    dns: list[str] = []
    for value in dns_raw:
        if not isinstance(value, str):
            raise ValueError("Xray TUN DNS entries must be IP address strings")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Xray TUN DNS contains an invalid IP address") from exc
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("Xray TUN DNS servers must be usable unicast addresses")
        normalized = str(address)
        if normalized in dns:
            raise ValueError("Xray TUN DNS server addresses must be unique")
        dns.append(normalized)

    routes_raw = settings.get("autoSystemRoutingTable")
    if not isinstance(routes_raw, list) or len(routes_raw) != 2:
        raise ValueError("Xray TUN must route both IPv4 and IPv6 default routes")
    routes: list[str] = []
    route_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for value in routes_raw:
        if not isinstance(value, str):
            raise ValueError("Xray TUN routes must be CIDR strings")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError("Xray TUN route contains an invalid network prefix") from exc
        if network.prefixlen != 0 or network in route_networks:
            raise ValueError("Xray TUN routes must contain unique IPv4 and IPv6 defaults")
        route_networks.add(network)
        routes.append(str(network))
    if route_networks != {
        ipaddress.ip_network("0.0.0.0/0"),
        ipaddress.ip_network("::/0"),
    }:
        raise ValueError("Xray TUN must route both 0.0.0.0/0 and ::/0")

    outbound_interface = settings.get("autoOutboundsInterface")
    if outbound_interface != "auto":
        raise ValueError("Xray TUN must set autoOutboundsInterface to 'auto' to avoid routing loops")

    leak_raw = settings.get("autoSystemWfpBlockLeak")
    if (
        not isinstance(leak_raw, list)
        or len(leak_raw) != 2
        or any(not isinstance(value, str) for value in leak_raw)
        or set(leak_raw) != {"allexceptlan", "dns"}
    ):
        raise ValueError(
            "Xray TUN must enable allexceptlan and dns WFP leak-protection filters"
        )
    if "autoSystemDnsToGateway" in settings:
        value = settings["autoSystemDnsToGateway"]
        if not isinstance(value, bool) or value:
            raise ValueError("autoSystemDnsToGateway must be false on Windows")
    user_level = settings.get("userLevel", 0)
    if isinstance(user_level, bool) or not isinstance(user_level, int) or not 0 <= user_level <= 0xFFFFFFFF:
        raise ValueError("Xray TUN userLevel must be an unsigned 32-bit integer")

    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("Xray TUN config must contain at least one outbound")

    return XrayTunInbound(
        name=name,
        desc=desc,
        mtu=mtu,
        gateway=tuple(gateway),
        dns=tuple(dns),
        routes=tuple(routes),
        auto_outbounds_interface=outbound_interface,
        leak_protection=tuple(leak_raw),
    )


def inspect_xray_inbound(config: dict) -> LocalSocksInbound | XrayTunInbound:
    """Accept either a protected loopback SOCKS config or a strict full TUN config."""
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or len(inbounds) != 1:
        raise ValueError("Xray config must contain exactly one supported inbound")
    inbound = inbounds[0]
    if not isinstance(inbound, dict):
        raise ValueError("Xray inbound must be an object")
    protocol = inbound.get("protocol")
    if protocol == "socks":
        return inspect_local_socks_inbound(config)
    if protocol == "tun":
        return inspect_tun_inbound(config)
    raise ValueError("Xray inbound must use SOCKS or TUN protocol")



def parse_xray_config_bytes(raw_config: bytes) -> dict:
    """Decode bounded UTF-8 Xray JSON and reject ambiguous/non-standard JSON."""
    if not isinstance(raw_config, bytes):
        raise TypeError("Xray config must be supplied as bytes")
    if not raw_config or len(raw_config) > MAX_XRAY_CONFIG_BYTES:
        raise ValueError("Xray config must be non-empty and within the size limit")
    try:
        config = json.loads(
            raw_config.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Xray config must be valid UTF-8 JSON without duplicate keys") from exc
    if not isinstance(config, dict):
        raise ValueError("Xray config root must be a JSON object")
    return config


def is_windows_elevated() -> bool:
    """Return whether this process has an elevated Windows administrator token."""
    if os.name != "nt":
        return False
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    is_user_admin = shell32.IsUserAnAdmin
    is_user_admin.argtypes = []
    is_user_admin.restype = ctypes.c_int
    return bool(is_user_admin())


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
        new_console: bool = False,
    ) -> None:
        self._validate_timeout(validation_timeout, "validation_timeout")
        self._validate_timeout(stop_timeout, "stop_timeout")
        if not isinstance(new_console, bool):
            raise ValueError("new_console must be a boolean")
        self.executable = Path(executable).expanduser()
        self.config_path = Path(config_path).expanduser()
        self.validation_timeout = float(validation_timeout)
        self.stop_timeout = float(stop_timeout)
        self.new_console = new_console
        self._process: subprocess.Popen[bytes] | WindowsJobProcess | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _read_config(self) -> dict:
        try:
            with self.config_path.open("rb") as stream:
                raw_config = stream.read(MAX_XRAY_CONFIG_BYTES + 1)
            if len(raw_config) > MAX_XRAY_CONFIG_BYTES:
                raise ValueError("Xray config exceeds the maximum supported size")
            config = json.loads(
                raw_config.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError("Xray config must be readable UTF-8 JSON within the size limit") from exc
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
        inbound = inspect_xray_inbound(config)
        if isinstance(inbound, XrayTunInbound) and os.name == "nt":
            # Xray's Windows TUN backend dynamically loads Wintun from beside
            # xray.exe. Never let the engine silently fall back to SOCKS-only.
            wintun_dll = self.executable.parent / "wintun.dll"
            if not wintun_dll.is_file():
                raise FileNotFoundError(
                    "Windows TUN mode requires the matching wintun.dll beside xray.exe"
                )
            if not is_windows_elevated():
                raise PermissionError(
                    "Windows TUN requires an elevated administrator token; "
                    "the desktop-to-helper elevation workflow is not integrated yet"
                )

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

    def wait_for_socks_protocol_ready(
        self,
        *,
        timeout: float = 5.0,
        poll_interval: float = 0.1,
        probe_timeout: float = 0.5,
    ) -> bool:
        """Wait a bounded time for local SOCKS5 no-auth negotiation to succeed.

        This is a local proxy-readiness check only. It does not verify an
        outbound destination, tunnel routing, DNS behavior, or VPN health.
        """
        self._validate_timeout(timeout)
        self._validate_timeout(poll_interval, "poll_interval")
        self._validate_timeout(probe_timeout, "probe_timeout")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self.is_socks_protocol_ready(timeout=min(probe_timeout, remaining)):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(poll_interval, remaining))

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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
                    str(self.executable),
                    ["run", "-c", str(self.config_path)],
                    new_console=self.new_console,
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
                # Prefer Xray's console-control shutdown path when the helper
                # created a dedicated hidden console. Fall back to terminating
                # the root, then the complete Job Object if graceful stop stalls.
                send_ctrl_break = getattr(process, "send_ctrl_break", None)
                graceful_requested = bool(send_ctrl_break and send_ctrl_break())
                if not graceful_requested:
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
