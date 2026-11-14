"""Validated, transport-neutral connection profile model."""

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from unicodedata import category


def _contains_control_characters(value: str) -> bool:
    """Return whether a string contains any Unicode control character."""
    return any(category(character) == "Cc" for character in value)


def _validate_endpoint_host(host: str) -> None:
    """Accept IP literals or DNS names, never URLs or host:port strings."""
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return
    except ValueError:
        pass

    # A colon is not valid in a DNS name; this also rejects malformed IPv6
    # literals and accidental host:port / URL input.
    if ":" in candidate or any(char in candidate for char in "/\\@?#"):
        raise ValueError("Endpoint host must be an IP address or DNS hostname, not a URL")

    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Endpoint host must be a valid DNS hostname") from exc

    # Permit a fully-qualified DNS name with one terminal dot.
    normalized = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    if not normalized or len(normalized) > 253:
        raise ValueError("Endpoint host must be a valid DNS hostname")
    labels = normalized.split(".")
    label_pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("Endpoint host must be a valid DNS hostname")


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
        if _contains_control_characters(self.name):
            raise ValueError("Profile name cannot contain control characters")

        if not isinstance(self.transport, Transport):
            raise TypeError("Profile transport must be a Transport value")

        if not isinstance(self.endpoint_host, str):
            raise TypeError("Endpoint host must be a string")
        if not self.endpoint_host or not self.endpoint_host.strip():
            raise ValueError("Endpoint host cannot be empty")
        if len(self.endpoint_host) > 253:
            raise ValueError("Endpoint host cannot exceed 253 characters")
        if (
            any(character.isspace() for character in self.endpoint_host)
            or _contains_control_characters(self.endpoint_host)
        ):
            raise ValueError("Endpoint host cannot contain whitespace or control characters")
        _validate_endpoint_host(self.endpoint_host)

        if isinstance(self.endpoint_port, bool) or not isinstance(self.endpoint_port, int):
            raise TypeError("Endpoint port must be an integer")
        if not 1 <= self.endpoint_port <= 65535:
            raise ValueError("Endpoint port must be between 1 and 65535")
