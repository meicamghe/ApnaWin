"""Length-prefixed framing for the future local privileged IPC transport.

This module parses complete frames only; it does not open a pipe or read from
an untrusted stream. A pipe server must read the fixed header first, validate
the declared length, and then read exactly that many bytes.
"""
from __future__ import annotations

import struct

from apnawin.services.privileged_protocol import (
    MAX_REQUEST_BYTES,
    PrivilegedRequest,
    decode_privileged_request,
)

_HEADER = struct.Struct("<I")
FRAME_HEADER_BYTES = _HEADER.size


class PrivilegedFrameError(ValueError):
    """A length-prefixed privileged request frame is malformed or oversized."""


def encode_privileged_frame(payload: bytes) -> bytes:
    """Validate and encode one request as a 32-bit little-endian length + JSON."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise PrivilegedFrameError("request payload is empty or exceeds 64 KiB")
    try:
        decode_privileged_request(payload)
    except (TypeError, ValueError) as exc:
        raise PrivilegedFrameError("request payload is not a valid protocol envelope") from exc
    return _HEADER.pack(len(payload)) + payload


def decode_privileged_frame(frame: bytes) -> PrivilegedRequest:
    """Decode exactly one complete frame; reject truncation and trailing bytes."""
    if not isinstance(frame, bytes):
        raise TypeError("frame must be bytes")
    if len(frame) < FRAME_HEADER_BYTES:
        raise PrivilegedFrameError("request frame is shorter than its length header")
    (declared_length,) = _HEADER.unpack_from(frame)
    if not 1 <= declared_length <= MAX_REQUEST_BYTES:
        raise PrivilegedFrameError("declared request length is empty or exceeds 64 KiB")
    expected_length = FRAME_HEADER_BYTES + declared_length
    if len(frame) != expected_length:
        raise PrivilegedFrameError("request frame length does not match its header")
    try:
        return decode_privileged_request(frame[FRAME_HEADER_BYTES:])
    except (TypeError, ValueError) as exc:
        raise PrivilegedFrameError("request frame contains an invalid protocol envelope") from exc
