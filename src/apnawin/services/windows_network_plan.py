"""Pure validation for future Windows TUN route and DNS intent; no OS mutation."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TypeAlias

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
_MAX_LUID = (1 << 64) - 1
_MAX_METRIC = (1 << 32) - 1
_MAX_DNS_SERVERS = 16


def _luid(value: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_LUID:
        raise ValueError(f"{field} must be a positive 64-bit interface LUID")


def _address(value: str, field: str) -> IPAddress:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be an IP address without surrounding whitespace")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """An exact route entry addressed by stable interface LUID."""
    destination: str
    next_hop: str
    interface_luid: int
    metric: int

    def __post_init__(self) -> None:
        _luid(self.interface_luid, "interface_luid")
        if isinstance(self.metric, bool) or not isinstance(self.metric, int) or not 0 <= self.metric <= _MAX_METRIC:
            raise ValueError("metric must be an unsigned 32-bit integer")
        if not isinstance(self.destination, str) or not self.destination:
            raise ValueError("destination must be a CIDR network")
        try:
            network = ipaddress.ip_network(self.destination, strict=True)
        except ValueError as exc:
            raise ValueError("destination must be a canonical CIDR network") from exc
        hop = _address(self.next_hop, "next_hop")
        if network.version != hop.version:
            raise ValueError("route destination and next_hop address families must match")
        object.__setattr__(self, "destination", str(network))
        object.__setattr__(self, "next_hop", str(hop))

    @property
    def network(self) -> IPNetwork:
        return ipaddress.ip_network(self.destination, strict=True)


@dataclass(frozen=True, slots=True)
class DnsSpec:
    """A bounded explicit DNS server list assigned to one interface."""
    interface_luid: int
    servers: tuple[str, ...]

    def __post_init__(self) -> None:
        _luid(self.interface_luid, "interface_luid")
        if not isinstance(self.servers, tuple):
            raise ValueError("servers must be an immutable tuple")
        if not 1 <= len(self.servers) <= _MAX_DNS_SERVERS:
            raise ValueError(f"servers must contain 1 to {_MAX_DNS_SERVERS} addresses")
        normalized: list[str] = []
        for server in self.servers:
            address = str(_address(server, "DNS server"))
            if address in normalized:
                raise ValueError("DNS server addresses must be unique")
            normalized.append(address)
        object.__setattr__(self, "servers", tuple(normalized))


@dataclass(frozen=True, slots=True)
class WindowsNetworkPlan:
    """Validated network intent, never an executable privileged command."""
    tunnel_interface_luid: int
    physical_interface_luid: int
    endpoint_bypass_route: RouteSpec
    tunnel_default_routes: tuple[RouteSpec, ...]
    dns: DnsSpec

    def __post_init__(self) -> None:
        _luid(self.tunnel_interface_luid, "tunnel_interface_luid")
        _luid(self.physical_interface_luid, "physical_interface_luid")
        if self.tunnel_interface_luid == self.physical_interface_luid:
            raise ValueError("tunnel and physical interface LUIDs must differ")
        if not isinstance(self.endpoint_bypass_route, RouteSpec):
            raise TypeError("endpoint_bypass_route must be a RouteSpec")
        if not isinstance(self.tunnel_default_routes, tuple):
            raise ValueError("tunnel_default_routes must be an immutable tuple")
        if not 1 <= len(self.tunnel_default_routes) <= 2:
            raise ValueError("one or two tunnel default routes are required")
        if not isinstance(self.dns, DnsSpec):
            raise TypeError("dns must be a DnsSpec")

        bypass = self.endpoint_bypass_route
        if bypass.interface_luid != self.physical_interface_luid:
            raise ValueError("endpoint bypass route must use the physical interface")
        if bypass.network.prefixlen != bypass.network.max_prefixlen:
            raise ValueError("endpoint bypass route must be a single-host /32 or /128 route")

        families: set[int] = set()
        for route in self.tunnel_default_routes:
            if not isinstance(route, RouteSpec):
                raise TypeError("tunnel_default_routes must contain RouteSpec values")
            network = route.network
            if network.prefixlen != 0:
                raise ValueError("tunnel routes must be default routes (/0)")
            if route.interface_luid != self.tunnel_interface_luid:
                raise ValueError("tunnel default routes must use the tunnel interface")
            if network.version in families:
                raise ValueError("only one default route per address family is allowed")
            families.add(network.version)
        if self.dns.interface_luid != self.tunnel_interface_luid:
            raise ValueError("DNS servers must be assigned to the tunnel interface")

    @property
    def ordered_routes(self) -> tuple[RouteSpec, ...]:
        """Pin the remote endpoint physically before adding tunnel defaults."""
        return (self.endpoint_bypass_route, *self.tunnel_default_routes)
