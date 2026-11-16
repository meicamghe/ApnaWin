"""Bounded LRU flow-ID allocation for the BadVPN UDPGW protocol."""
from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias

IPAddress: TypeAlias = IPv4Address | IPv6Address
FlowKey: TypeAlias = tuple[IPAddress, int, IPAddress, int]


@dataclass(frozen=True, slots=True)
class UdpGwFlowLease:
    connection_id: int
    rebind: bool


class UdpGwFlowTable:
    """Map UDP 4-tuples to 16-bit IDs with bounded least-recently-used reuse."""

    def __init__(self, *, max_connections: int = 256) -> None:
        if (
            isinstance(max_connections, bool)
            or not isinstance(max_connections, int)
            or not 1 <= max_connections <= 0xFFFF
        ):
            raise ValueError("max_connections must be between 1 and 65535")
        self._max_connections = max_connections
        self._flows: OrderedDict[FlowKey, int] = OrderedDict()
        self._reverse: dict[int, FlowKey] = {}
        self._next_id = 1

    @property
    def count(self) -> int:
        return len(self._flows)

    def get_or_create(
        self,
        *,
        local_address: str | IPAddress,
        local_port: int,
        remote_address: str | IPAddress,
        remote_port: int,
    ) -> UdpGwFlowLease:
        local_ip = self._parse_address(local_address, "local_address")
        remote_ip = self._parse_address(remote_address, "remote_address")
        self._validate_port(local_port, "local_port")
        self._validate_port(remote_port, "remote_port")
        key: FlowKey = (local_ip, local_port, remote_ip, remote_port)

        existing = self._flows.get(key)
        if existing is not None:
            self._flows.move_to_end(key)
            return UdpGwFlowLease(existing, False)

        if len(self._flows) < self._max_connections:
            connection_id = self._allocate_id()
        else:
            old_key, connection_id = self._flows.popitem(last=False)
            del self._reverse[connection_id]

        self._flows[key] = connection_id
        self._reverse[connection_id] = key
        return UdpGwFlowLease(connection_id, True)

    def lookup(self, connection_id: int) -> FlowKey | None:
        if isinstance(connection_id, bool) or not isinstance(connection_id, int):
            raise TypeError("connection_id must be an integer")
        return self._reverse.get(connection_id)

    def remove(
        self,
        *,
        local_address: str | IPAddress,
        local_port: int,
        remote_address: str | IPAddress,
        remote_port: int,
    ) -> bool:
        local_ip = self._parse_address(local_address, "local_address")
        remote_ip = self._parse_address(remote_address, "remote_address")
        self._validate_port(local_port, "local_port")
        self._validate_port(remote_port, "remote_port")
        key: FlowKey = (local_ip, local_port, remote_ip, remote_port)
        connection_id = self._flows.pop(key, None)
        if connection_id is None:
            return False
        self._reverse.pop(connection_id, None)
        return True

    def clear(self) -> None:
        self._flows.clear()
        self._reverse.clear()
        self._next_id = 1

    def _allocate_id(self) -> int:
        for _ in range(0xFFFF):
            candidate = self._next_id
            self._next_id = 1 if candidate == 0xFFFF else candidate + 1
            if candidate not in self._reverse:
                return candidate
        raise RuntimeError("No free UDPGW connection IDs")

    @staticmethod
    def _parse_address(value: str | IPAddress, name: str) -> IPAddress:
        try:
            return ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be an IPv4 or IPv6 address") from exc

    @staticmethod
    def _validate_port(value: int, name: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"{name} must be between 1 and 65535")
