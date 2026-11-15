import json
import struct

import pytest

from apnawin.services.privileged_frame import (
    FRAME_HEADER_BYTES,
    PrivilegedFrameError,
    decode_privileged_frame,
    encode_privileged_frame,
)


REQUEST = {
    "version": 1,
    "request_id": "abcdefab-cdef-abcd-efab-cdefabcdef01",
    "transaction_id": "12345678-1234-5678-9abc-def012345678",
    "operation": "snapshot_network",
    "arguments": {},
}


def payload():
    return json.dumps(REQUEST, separators=(",", ":")).encode("utf-8")


def test_round_trip_length_prefixed_request():
    body = payload()
    frame = encode_privileged_frame(body)
    assert struct.unpack_from("<I", frame)[0] == len(body)
    assert len(frame) == FRAME_HEADER_BYTES + len(body)
    request = decode_privileged_frame(frame)
    assert request.operation == "snapshot_network"
    assert request.arguments == {}


def test_encoder_rejects_invalid_envelope():
    with pytest.raises(PrivilegedFrameError, match="valid protocol"):
        encode_privileged_frame(b'{"version":1}')


@pytest.mark.parametrize("frame", [b"", b"\x00", b"\x00\x00\x00"])
def test_decoder_rejects_truncated_header(frame):
    with pytest.raises(PrivilegedFrameError, match="header"):
        decode_privileged_frame(frame)


@pytest.mark.parametrize("length", [0, 65537, 0xFFFFFFFF])
def test_decoder_rejects_invalid_declared_length(length):
    frame = struct.pack("<I", length)
    with pytest.raises(PrivilegedFrameError, match="declared"):
        decode_privileged_frame(frame)


def test_decoder_rejects_truncated_payload():
    body = payload()
    frame = struct.pack("<I", len(body)) + body[:-1]
    with pytest.raises(PrivilegedFrameError, match="does not match"):
        decode_privileged_frame(frame)


def test_decoder_rejects_trailing_bytes_and_second_frame():
    frame = encode_privileged_frame(payload())
    with pytest.raises(PrivilegedFrameError, match="does not match"):
        decode_privileged_frame(frame + b"\x00")


def test_decoder_rejects_valid_length_with_invalid_json():
    body = b"{not-json}"
    frame = struct.pack("<I", len(body)) + body
    with pytest.raises(PrivilegedFrameError, match="invalid protocol"):
        decode_privileged_frame(frame)


def test_rejects_non_bytes_inputs():
    with pytest.raises(TypeError, match="payload"):
        encode_privileged_frame("not bytes")
    with pytest.raises(TypeError, match="frame"):
        decode_privileged_frame(bytearray(b"1234"))
