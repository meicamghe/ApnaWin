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
        if not isinstance(self.name, str):
            raise TypeError("Profile name must be a string")
        if not self.name.strip():
            raise ValueError("Profile name cannot be empty")
        if len(self.name) > 128:
            raise ValueError("Profile name cannot exceed 128 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in self.name):
            raise ValueError("Profile name cannot contain control characters")

        if not isinstance(self.transport, Transport):
            raise TypeError("Profile transport must be a Transport value")

        if not isinstance(self.endpoint_host, str):
            raise TypeError("Endpoint host must be a string")
        if not self.endpoint_host or not self.endpoint_host.strip():
            raise ValueError("Endpoint host cannot be empty")
        if len(self.endpoint_host) > 253:
            raise ValueError("Endpoint host cannot exceed 253 characters")
        if any(character.isspace() or ord(character) < 32 or ord(character) == 127
               for character in self.endpoint_host):
            raise ValueError("Endpoint host cannot contain whitespace or control characters")

        if isinstance(self.endpoint_port, bool) or not isinstance(self.endpoint_port, int):
            raise TypeError("Endpoint port must be an integer")
        if not 1 <= self.endpoint_port <= 65535:
            raise ValueError("Endpoint port must be between 1 and 65535")
