"""APNA-style SSH payload expansion and segmented stream writes.

The APNA primary DEX exposes the formatter/injector method names and token
strings implemented here. The one-second delay is a configurable default
corroborated by closely related public framework sources; it is not yet
confirmed from APNA's protected method bytecode.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Protocol


_MAX_TEMPLATE_CHARS = 64 * 1024
_ROTATE = re.compile(r"\[rotate=(.*?)\]")
_DELAY_SPLIT = "[delay_split]"
_INSTANT_SPLIT = "[instant_split]"


class PayloadFormatError(ValueError):
    """Raised when a payload template or its endpoint substitutions are unsafe."""


class PayloadWriter(Protocol):
    def write(self, data: bytes) -> object: ...

    def flush(self) -> object: ...


@dataclass(frozen=True, slots=True)
class PayloadChunk:
    """One byte sequence to write/flush, with an optional following delay."""

    data: bytes
    delay_after_ms: int = 0


class PayloadRotation:
    """Round-robin state for [rotate=a;b] expressions, scoped to one profile."""

    def __init__(self) -> None:
        self._template: str | None = None
        self._indices: dict[int, int] = {}

    def expand(self, template: str) -> str:
        if template != self._template:
            self._template = template
            self._indices.clear()

        occurrence = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal occurrence
            values = match.group(1).split(";")
            if not values or any(not value for value in values):
                raise PayloadFormatError("Rotate expressions must contain non-empty values")
            previous = self._indices.get(occurrence, -1)
            selected = (previous + 1) % len(values)
            self._indices[occurrence] = selected
            occurrence += 1
            return values[selected]

        return _ROTATE.sub(replace, template)


def _validate_endpoint(host: str, port: int, protocol: str) -> None:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise PayloadFormatError("SSH host must be a non-empty hostname or IP address")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in host):
        raise PayloadFormatError("SSH host contains whitespace or non-ASCII/control characters")
    if any(char in host for char in "/\\@?#[]"):
        raise PayloadFormatError("SSH host must not contain URL or authority delimiters")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise PayloadFormatError("SSH port must be an integer between 1 and 65535")
    if not isinstance(protocol, str) or not protocol or len(protocol) > 32:
        raise PayloadFormatError("Payload protocol token is invalid")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in protocol):
        raise PayloadFormatError("Payload protocol contains whitespace or control characters")


def render_apna_payload(
    template: str,
    *,
    host: str,
    port: int,
    protocol: str = "HTTP/1.0",
    rotation: PayloadRotation | None = None,
    delay_split_ms: int = 1000,
) -> tuple[PayloadChunk, ...]:
    """Expand APNA-observed tokens into ordered ISO-8859-1 stream chunks.

    [instant_split] creates an immediate write/flush boundary.
    [delay_split] creates a write/flush boundary followed by delay_split_ms.
    Unknown tokens are preserved verbatim rather than silently rewritten.
    """
    if not isinstance(template, str):
        raise TypeError("Payload template must be text")
    if len(template) > _MAX_TEMPLATE_CHARS:
        raise PayloadFormatError("Payload template exceeds the size limit")
    _validate_endpoint(host, port, protocol)
    if isinstance(delay_split_ms, bool) or not isinstance(delay_split_ms, int):
        raise TypeError("Split delay must be an integer number of milliseconds")
    if not 0 <= delay_split_ms <= 10_000:
        raise PayloadFormatError("Split delay must be between 0 and 10000 milliseconds")

    expanded = rotation.expand(template) if rotation is not None else _ROTATE.sub(
        lambda match: _first_rotate_value(match.group(1)), template
    )
    substitutions = {
        "[host]": host,
        "[host_port]": f"{host}:{port}",
        "[port]": str(port),
        "[protocol]": protocol,
        "[ssh]": f"{host}:{port}",
        "[crlf]": "\r\n",
        "[cr]": "\r",
        "[lf]": "\n",
        "[lfcr]": "\n\r",
    }
    for token, value in substitutions.items():
        expanded = expanded.replace(token, value)

    if _DELAY_SPLIT not in expanded and _INSTANT_SPLIT not in expanded:
        return (_chunk(expanded, 0),)

    chunks: list[PayloadChunk] = []
    delay_parts = expanded.split(_DELAY_SPLIT)
    for delay_index, delay_part in enumerate(delay_parts):
        instant_parts = delay_part.split(_INSTANT_SPLIT)
        for instant_index, part in enumerate(instant_parts):
            is_last_in_delay_part = instant_index == len(instant_parts) - 1
            has_following_delay_part = delay_index < len(delay_parts) - 1
            delay = delay_split_ms if is_last_in_delay_part and has_following_delay_part else 0
            chunks.append(_chunk(part, delay))
    return tuple(chunks)


def _first_rotate_value(value: str) -> str:
    values = value.split(";")
    if not values or any(not item for item in values):
        raise PayloadFormatError("Rotate expressions must contain non-empty values")
    return values[0]


def _chunk(text: str, delay_after_ms: int) -> PayloadChunk:
    try:
        data = text.encode("iso-8859-1", errors="strict")
    except UnicodeEncodeError as exc:
        raise PayloadFormatError("Payload contains characters outside ISO-8859-1") from exc
    return PayloadChunk(data=data, delay_after_ms=delay_after_ms)


def send_payload(
    writer: PayloadWriter,
    chunks: tuple[PayloadChunk, ...],
    *,
    sleep: Callable[[float], object] = time.sleep,
) -> None:
    """Write and flush each segment; sleep only after delayed split markers."""
    for chunk in chunks:
        if chunk.data:
            writer.write(chunk.data)
        writer.flush()
        if chunk.delay_after_ms:
            sleep(chunk.delay_after_ms / 1000)
