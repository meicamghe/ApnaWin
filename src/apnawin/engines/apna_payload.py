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
    """Round-robin [rotate=...] state matching the related Android framework."""

    def __init__(self) -> None:
        self._last_payload: str | None = None
        self._indices: dict[int, int] = {}

    def expand(self, payload: str) -> str:
        # The related formatter applies host/token substitutions before rotate.
        if payload != self._last_payload:
            self._indices.clear()
            self._last_payload = payload

        occurrence = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal occurrence
            values = match.group(1).split(";")
            if not values or any(not value for value in values):
                raise PayloadFormatError("Rotate expressions must contain non-empty values")
            selected = (self._indices.get(occurrence, -1) + 1) % len(values)
            self._indices[occurrence] = selected
            occurrence += 1
            return values[selected]

        return _ROTATE.sub(replace, payload)


class PayloadRandom:
    """Injectable selector for [random=...] expressions, independently testable."""

    def __init__(self, chooser: Callable[[int], int] | None = None) -> None:
        import random

        self._chooser = chooser or random.SystemRandom().randrange

    def expand(self, payload: str) -> str:
        def replace(match: re.Match[str]) -> str:
            values = match.group(1).split(";")
            if not values or any(not value for value in values):
                raise PayloadFormatError("Random expressions must contain non-empty values")
            selected = self._chooser(len(values))
            if isinstance(selected, bool) or not isinstance(selected, int):
                raise PayloadFormatError("Random selector returned an invalid index")
            if not 0 <= selected < len(values):
                raise PayloadFormatError("Random selector returned an out-of-range index")
            return values[selected]

        return re.sub(r"\[random=(.*?)\]", replace, payload)



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
    method: str = "CONNECT",
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36"
    ),
    rotation: PayloadRotation | None = None,
    randomizer: PayloadRandom | None = None,
    delay_split_ms: int = 1000,
) -> tuple[PayloadChunk, ...]:
    """Expand framework-family payload tokens into ordered ISO-8859-1 chunks.

    The token set and processing order are corroborated by a closely related
    Android implementation; APNA protected bytecode still needs direct checking.
    """
    if not isinstance(template, str):
        raise TypeError("Payload template must be text")
    if len(template) > _MAX_TEMPLATE_CHARS:
        raise PayloadFormatError("Payload template exceeds the size limit")
    _validate_endpoint(host, port, protocol)
    for name, value, limit in (
        ("method", method, 32),
        ("user_agent", user_agent, 1024),
    ):
        if not isinstance(value, str) or not value or len(value) > limit:
            raise PayloadFormatError(f"{name} is invalid")
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            raise PayloadFormatError(f"{name} contains control or non-ASCII characters")
        if name == "method" and any(char.isspace() for char in value):
            raise PayloadFormatError("method cannot contain whitespace")
    if isinstance(delay_split_ms, bool) or not isinstance(delay_split_ms, int):
        raise TypeError("Split delay must be an integer number of milliseconds")
    if not 0 <= delay_split_ms <= 10_000:
        raise PayloadFormatError("Split delay must be between 0 and 10000 milliseconds")

    substitutions = {
        "[method]": method,
        "[host]": host,
        "[ip]": host,
        "[host_port]": f"{host}:{port}",
        "[port]": str(port),
        "[protocol]": protocol,
        "[ssh]": f"{host}:{port}",
        "[vpn]": f"{host}:{port}",
        "[ua]": user_agent,
        "[crlf]": "\\r\\n",
        "[cr]": "\\r",
        "[lf]": "\\n",
        "[lfcr]": "\\n\\r",
        r"\\n": "\\n",
        r"\\r": "\\r",
    }
    expanded = template
    for token, value in substitutions.items():
        expanded = expanded.replace(token, value)

    # This ordering mirrors the related framework's formatCustomPayload:
    # rotate first, then random selection, then repeated line-ending macros.
    expanded = rotation.expand(expanded) if rotation is not None else _replace_rotate_first(expanded)
    expanded = (randomizer or PayloadRandom()).expand(expanded)
    expanded = _expand_repeated_line_endings(expanded)

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


def _replace_rotate_first(payload: str) -> str:
    rotation = PayloadRotation()
    return rotation.expand(payload)


def _expand_repeated_line_endings(payload: str) -> str:
    replacements = (
        (re.compile(r"\[cr\*(\d+)\]"), "\r"),
        (re.compile(r"\\[lf\\*(\\d+)\\]"), "\\n"),
        (re.compile(r"\[cr\*(\d+)\]"), "\r"),
        (re.compile(r"\[lfcr\*(\d+)\]"), "\n\r"),
    )
    for pattern, ending in replacements:
        def replace(match: re.Match[str]) -> str:
            count = int(match.group(1))
            if count > 4096:
                raise PayloadFormatError("Repeated line-ending count exceeds the limit")
            return ending * count

        payload = pattern.sub(replace, payload)
    return payload



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
