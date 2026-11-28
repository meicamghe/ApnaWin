"""APNA-style SSH payload expansion and segmented stream writes.

The APNA primary DEX exposes the formatter/injector call graph, split tokens,
ISO-8859-1 writes, and a delay-split path. Its bytecode loads 1000 ms directly
before Thread.sleep(long), so the default below matches this APK and remains
configurable for catalog compatibility. Hidden formatter keys are cross-checked
against the related implementation.
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
    """Round-robin [rotate=...] state recovered from APNA primary DEX."""

    def __init__(self) -> None:
        self._last_payload: str | None = None
        self._indices: dict[int, int] = {}

    def expand(self, payload: str) -> str:
        # APNA formatCustomPayload applies host/token substitutions before rotate.
        if payload != self._last_payload:
            self._indices.clear()
            self._last_payload = payload

        for occurrence, match in enumerate(_ROTATE.finditer(payload)):
            values = _java_split(match.group(1), ";")
            if not values:
                continue
            selected = (self._indices.get(occurrence, -1) + 1) % len(values)
            self._indices[occurrence] = selected
            # Android uses String.replace, replacing every identical expression.
            payload = payload.replace(match.group(0), values[selected])
        return payload


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
    method: str = "CONNECT",
    protocol: str = "HTTP/1.0",
    user_agent: str | None = None,
    cf_host: str | None = None,
    brand: str | None = None,
    rotation: PayloadRotation | None = None,
    delay_split_ms: int = 1000,
) -> tuple[PayloadChunk, ...]:
    """Expand observed tokens into ordered ISO-8859-1 chunks.

    APNA DEX confirms the formatter signature, replacement loop, rotation call,
    split methods and ISO-8859-1 encoding. The default delay is sibling-derived
    and configurable; it is not an asserted APNA v51 constant.
    """
    if not isinstance(template, str):
        raise TypeError("Payload template must be text")
    if len(template) > _MAX_TEMPLATE_CHARS:
        raise PayloadFormatError("Payload template exceeds the size limit")
    _validate_endpoint(host, port, protocol)
    if not isinstance(method, str) or not method or len(method) > 32:
        raise PayloadFormatError("Payload method token is invalid")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in method):
        raise PayloadFormatError("Payload method contains whitespace or control characters")
    if user_agent is None:
        user_agent = (
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36"
        )
    if not isinstance(user_agent, str) or len(user_agent) > 1024:
        raise PayloadFormatError("user_agent is invalid")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in user_agent):
        raise PayloadFormatError("user_agent contains control or non-ASCII characters")
    if isinstance(delay_split_ms, bool) or not isinstance(delay_split_ms, int):
        raise TypeError("Split delay must be an integer number of milliseconds")
    if not 0 <= delay_split_ms <= 10_000:
        raise PayloadFormatError("Split delay must be between 0 and 10000 milliseconds")

    # The catalog layer supplies [cf] and [brand] before the DEX formatter.
    expanded = template
    if cf_host is not None:
        _validate_endpoint(cf_host, 1, protocol)
        expanded = expanded.replace("[cf]", cf_host)
    if brand is not None:
        if (
            not isinstance(brand, str)
            or len(brand) > 128
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in brand)
        ):
            raise PayloadFormatError("brand contains invalid characters")
        expanded = expanded.replace("[brand]", brand)

    # Preserve the insertion order recovered from formatCustomPayload.
    substitutions = {
        "[method]": method,
        "[host]": host,
        "[port]": str(port),
        "[host_port]": f"{host}:{port}",
        "[protocol]": protocol,
        "[ssh]": f"{host}:{port}",
        "[crlf]": "\r\n",
        "[cr]": "\r",
        "[lf]": "\n",
        "[lfcr]": "\n\r",
        r"\n": "\n",
        r"\r": "\r",
        "[ua]": user_agent,
    }
    for token, value in substitutions.items():
        expanded = expanded.replace(token, value)

    # APNA DEX calls parseRotate after its ordered placeholder replacement loop.
    expanded = rotation.expand(expanded) if rotation is not None else _replace_rotate_first(expanded)

    if _DELAY_SPLIT not in expanded and _INSTANT_SPLIT not in expanded:
        return (_chunk(expanded, 0),)

    chunks: list[PayloadChunk] = []
    delay_parts = _java_split(expanded, _DELAY_SPLIT)
    for delay_index, delay_part in enumerate(delay_parts):
        instant_parts = _java_split(delay_part, _INSTANT_SPLIT)
        for instant_index, part in enumerate(instant_parts):
            is_last_in_delay_part = instant_index == len(instant_parts) - 1
            has_following_delay_part = delay_index < len(delay_parts) - 1
            delay = delay_split_ms if is_last_in_delay_part and has_following_delay_part else 0
            chunks.append(_chunk(part, delay))
    return tuple(chunks)


def _java_split(value: str, delimiter: str) -> list[str]:
    """Match Java String.split(regex) trailing-empty removal for literal tokens."""
    if value == "":
        # Java String.split returns one empty element when the input itself
        # is empty and the pattern has no match.
        return [""]
    parts = value.split(delimiter)
    while parts and parts[-1] == "":
        parts.pop()
    return parts


def _replace_rotate_first(payload: str) -> str:
    return PayloadRotation().expand(payload)


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
