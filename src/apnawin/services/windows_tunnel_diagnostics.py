"""Read-only Windows adapter, default-route and DNS diagnostics."""
from __future__ import annotations

import base64
import ipaddress
import json
import math
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class TunnelSnapshot:
    adapter_present: bool
    adapter_status: str
    interface_index: int | None
    ipv4_default_route: bool
    ipv6_default_route: bool
    dns_servers: tuple[str, ...]

    @property
    def adapter_up(self) -> bool:
        return self.adapter_present and self.adapter_status.casefold() == "up"

    @property
    def routes_ready(self) -> bool:
        return self.ipv4_default_route and self.ipv6_default_route

    @property
    def dns_ready(self) -> bool:
        return bool(self.dns_servers)

    @property
    def routing_ready(self) -> bool:
        return self.adapter_up and self.routes_ready and self.dns_ready


class WindowsTunnelDiagnostics:
    """Query the ApnaWin TUN adapter without changing routes or DNS settings."""

    def __init__(
        self,
        *,
        adapter_name: str = "ApnaWin",
        powershell_executable: str = "powershell.exe",
        timeout: float = 5.0,
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
    ) -> None:
        if (
            not isinstance(adapter_name, str)
            or not adapter_name
            or len(adapter_name) > 128
            or not re.fullmatch(r"[A-Za-z0-9 _.-]+", adapter_name)
        ):
            raise ValueError("adapter_name must be 1 to 128 safe Windows adapter alias characters")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        if not isinstance(powershell_executable, str) or not powershell_executable:
            raise ValueError("powershell_executable must be a non-empty string")
        self.adapter_name = adapter_name
        self.powershell_executable = powershell_executable
        self.timeout = float(timeout)
        self._runner = runner or subprocess.run

    def snapshot(self) -> TunnelSnapshot:
        if os.name != "nt":
            raise OSError("Windows tunnel diagnostics are available only on Windows")
        alias = self.adapter_name.replace("'", "''")
        script = f"""
$ErrorActionPreference = 'Stop'
$a = Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $a) {{
    [pscustomobject]@{{
        adapter_present = $false
        adapter_status = ''
        interface_index = $null
        ipv4_default_route = $false
        ipv6_default_route = $false
        dns_servers = @()
    }} | ConvertTo-Json -Compress
    exit 0
}}
$idx = [int]$a.ifIndex
# Require the best combined route/interface metric to select only the TUN.
$r4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object {{
    $ipif = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $ipif) {{
        [pscustomobject]@{{ InterfaceIndex = [int]$_.InterfaceIndex; Metric = [long]$_.RouteMetric + [long]$ipif.InterfaceMetric }}
    }}
}})
$r6 = @(Get-NetRoute -DestinationPrefix '::/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object {{
    $ipif = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $ipif) {{
        [pscustomobject]@{{ InterfaceIndex = [int]$_.InterfaceIndex; Metric = [long]$_.RouteMetric + [long]$ipif.InterfaceMetric }}
    }}
}})
$best4 = @()
if ($r4.Count -gt 0) {{
    $metric4 = ($r4 | Measure-Object -Property Metric -Minimum).Minimum
    $best4 = @($r4 | Where-Object {{ $_.Metric -eq $metric4 }} | Select-Object -ExpandProperty InterfaceIndex -Unique)
}}
$best6 = @()
if ($r6.Count -gt 0) {{
    $metric6 = ($r6 | Measure-Object -Property Metric -Minimum).Minimum
    $best6 = @($r6 | Where-Object {{ $_.Metric -eq $metric6 }} | Select-Object -ExpandProperty InterfaceIndex -Unique)
}}
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | ForEach-Object {{ $_.ServerAddresses }} | Where-Object {{ $_ }})
[pscustomobject]@{{
    adapter_present = $true
    adapter_status = [string]$a.Status
    interface_index = $idx
    ipv4_default_route = ($best4.Count -gt 0 -and @($best4 | Where-Object {{ $_ -ne $idx }}).Count -eq 0)
    ipv6_default_route = ($best6.Count -gt 0 -and @($best6 | Where-Object {{ $_ -ne $idx }}).Count -eq 0)
    dns_servers = $dns
}} | ConvertTo-Json -Compress -Depth 4
"""
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = self._runner(
                [
                    self.powershell_executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    encoded,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Windows tunnel diagnostics timed out") from exc
        except OSError as exc:
            raise OSError("Could not start PowerShell tunnel diagnostics") from exc
        if result.returncode != 0:
            raise RuntimeError("PowerShell tunnel diagnostics failed")
        try:
            payload = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("PowerShell returned invalid tunnel diagnostics JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Tunnel diagnostics JSON must be an object")
        required = {
            "adapter_present",
            "adapter_status",
            "interface_index",
            "ipv4_default_route",
            "ipv6_default_route",
            "dns_servers",
        }
        if set(payload) != required:
            raise ValueError("Tunnel diagnostics JSON has an invalid schema")
        if not isinstance(payload["adapter_present"], bool):
            raise ValueError("adapter_present must be a boolean")
        if not isinstance(payload["adapter_status"], str):
            raise ValueError("adapter_status must be a string")
        index = payload["interface_index"]
        if index is not None and (
            isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= 0xFFFFFFFF
        ):
            raise ValueError("interface_index is invalid")
        for key in ("ipv4_default_route", "ipv6_default_route"):
            if not isinstance(payload[key], bool):
                raise ValueError(f"{key} must be a boolean")
        dns = payload["dns_servers"]
        if isinstance(dns, str):
            dns = [dns]
        if not isinstance(dns, list) or len(dns) > 32:
            raise ValueError("dns_servers must be a bounded array")
        normalized_dns: list[str] = []
        for address in dns:
            if not isinstance(address, str):
                raise ValueError("DNS server addresses must be strings")
            try:
                normalized_dns.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise ValueError("PowerShell returned an invalid DNS server address") from exc
        if payload["adapter_present"] and index is None:
            raise ValueError("A present tunnel adapter must have an interface index")
        return TunnelSnapshot(
            adapter_present=payload["adapter_present"],
            adapter_status=payload["adapter_status"],
            interface_index=index,
            ipv4_default_route=payload["ipv4_default_route"],
            ipv6_default_route=payload["ipv6_default_route"],
            dns_servers=tuple(normalized_dns),
        )
