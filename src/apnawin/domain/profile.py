"""Validated, transport-neutral connection profile model."""

from dataclasses import dataclass
from enum import Enum


class Transport(str, Enum):
    XRAY = "xray"
    OPENVPN = "openvpn"
    SOCKS = "socks"


@dataclass(frozen=True, slots=True)
class ConnectionProfile:
    name: str
    transport: Transport
    endpoint_host: str
    endpoint_port: int

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Profile name cannot be empty")
        if not self.endpoint_host.strip():
            raise ValueError("Endpoint host cannot be empty")
        if not 1 <= self.endpoint_port <= 65535:
            raise ValueError("Endpoint port must be between 1 and 65535")
