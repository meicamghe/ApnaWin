"""Verify a real HTTPS exchange is routed through the ApnaWin TUN interface."""
from __future__ import annotations

import base64
import ipaddress
import os
import socket
import ssl
import subprocess
from dataclasses import dataclass
from typing import Callable

from apnawin.services.windows_tunnel_diagnostics import WindowsTunnelDiagnostics


@dataclass(frozen=True)
class TrafficProbeResult:
    destination_ip: str
    interface_index: int
    http_status: int


class WindowsTunnelTrafficProbe:
    """Check selected route then complete a TLS/HTTP request over that route."""

    def __init__(
        self,
        *,
        host: str = "www.cloudflare.com",
        path: str = "/cdn-cgi/trace",
        timeout: float = 8.0,
        diagnostics_factory=WindowsTunnelDiagnostics,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        resolver: Callable = socket.getaddrinfo,
        connector: Callable = socket.create_connection,
    ) -> None:
        if not isinstance(host, str) or not host or len(host) > 253 or any(ch in host for ch in "\r\n'"):
            raise ValueError("probe host is invalid")
        if not isinstance(path, str) or not path.startswith("/") or any(ch in path for ch in "\r\n"):
            raise ValueError("probe path must be an absolute HTTP path")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("probe timeout must be positive")
        self.host = host
        self.path = path
        self.timeout = float(timeout)
        self._diagnostics_factory = diagnostics_factory
        self._runner = runner
        self._resolver = resolver
        self._connector = connector

    def _route_interface(self, address: str) -> int:
        ip = ipaddress.ip_address(address)
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$r=Find-NetRoute -RemoteIPAddress '{ip}' | Select-Object -First 1; "
            "if ($null -eq $r) { exit 3 }; "
            "[int]$r.InterfaceIndex | ConvertTo-Json -Compress"
        )
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = self._runner(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                errors="replace", timeout=self.timeout, check=False, shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("Could not inspect the selected Windows route") from exc
        if result.returncode != 0:
            raise RuntimeError("Windows could not resolve a route for the traffic probe")
        try:
            index = int(result.stdout.strip())
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Windows returned an invalid route interface index") from exc
        if not 1 <= index <= 0xFFFFFFFF:
            raise RuntimeError("Windows returned an out-of-range route interface index")
        return index

    def verify(self) -> TrafficProbeResult:
        if os.name != "nt":
            raise OSError("The Windows TUN traffic probe is available only on Windows")
        snapshot = self._diagnostics_factory(adapter_name="ApnaWin", timeout=self.timeout).snapshot()
        if not snapshot.routing_ready or snapshot.interface_index is None:
            raise RuntimeError("ApnaWin adapter, dual-stack routes or DNS are not ready")
        answers = self._resolver(
            self.host, 443, type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        addresses: list[str] = []
        for family, _socktype, _proto, _canonname, sockaddr in answers:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = str(ipaddress.ip_address(sockaddr[0]))
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise RuntimeError("Traffic probe hostname did not resolve to an IP address")

        failures = []
        for address in addresses:
            route_index = self._route_interface(address)
            if route_index != snapshot.interface_index:
                failures.append(f"{address} selects interface {route_index}, not ApnaWin")
                continue
            try:
                raw = self._connector((address, 443), timeout=self.timeout)
                with raw:
                    context = ssl.create_default_context()
                    with context.wrap_socket(raw, server_hostname=self.host) as secure:
                        request = (
                            f"GET {self.path} HTTP/1.1\r\n"
                            f"Host: {self.host}\r\n"
                            "Connection: close\r\n"
                            "User-Agent: ApnaWin-Tunnel-Probe/1\r\n\r\n"
                        ).encode("ascii")
                        secure.sendall(request)
                        response = secure.recv(4096)
                first_line = response.split(b"\r\n", 1)[0]
                fields = first_line.split()
                if len(fields) < 2 or fields[0] != b"HTTP/1.1":
                    raise RuntimeError("Traffic probe returned an invalid HTTP response")
                status = int(fields[1])
                if not 200 <= status < 400:
                    raise RuntimeError(f"Traffic probe returned HTTP {status}")
                return TrafficProbeResult(address, route_index, status)
            except (OSError, ssl.SSLError, ValueError, RuntimeError) as exc:
                failures.append(f"{address}: {type(exc).__name__}")
        raise RuntimeError(
            "No HTTPS traffic probe completed through the ApnaWin interface ("
            + "; ".join(failures[:4]) + ")"
        )
