import json
import uuid

import pytest

from apnawin.services.privileged_protocol import (
    MAX_REQUEST_BYTES,
    PrivilegedRequestError,
    decode_privileged_request,
)


REQUEST_ID = "abcdefab-cdef-abcd-efab-cdefabcdef01"
TRANSACTION_ID = "12345678-1234-5678-9abc-def012345678"


def payload(**overrides):
    request = {
        "version": 1,
        "request_id": REQUEST_ID,
        "transaction_id": TRANSACTION_ID,
        "operation": "snapshot_network",
        "arguments": {},
    }
    request.update(overrides)
    return json.dumps(request, separators=(",", ":")).encode()


def test_decodes_exact_valid_envelope():
    request = decode_privileged_request(payload())
    assert request.version == 1
    assert request.request_id == uuid.UUID(REQUEST_ID)
    assert request.transaction_id == uuid.UUID(TRANSACTION_ID)
    assert request.operation == "snapshot_network"
    assert request.arguments == {}


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b'{"version":1,"version":1}',
        b'{"version":NaN}',
        b'{"version":1e999}',
        b"\xff",
        b"[]",
    ],
)
def test_rejects_invalid_or_ambiguous_json(body):
    with pytest.raises(PrivilegedRequestError):
        decode_privileged_request(body)


def test_rejects_escaped_lone_surrogate():
    body = payload(arguments={"value": "\ud800"})
    with pytest.raises(PrivilegedRequestError, match="Unicode"):
        decode_privileged_request(body)


def test_rejects_oversized_request():
    with pytest.raises(PrivilegedRequestError, match="64 KiB"):
        decode_privileged_request(b" " * (MAX_REQUEST_BYTES + 1))


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": True},
        {"version": 2},
        {"extra": "field"},
        {"operation": "run_command"},
        {"operation": ""},
        {"request_id": "NOT-A-UUID"},
        {"request_id": REQUEST_ID.upper()},
        {"arguments": []},
    ],
)
def test_rejects_invalid_envelope_fields(overrides):
    with pytest.raises(PrivilegedRequestError):
        decode_privileged_request(payload(**overrides))


def test_rejects_excessive_nesting():
    nested = {"value": None}
    for _ in range(20):
        nested = {"value": nested}
    with pytest.raises(PrivilegedRequestError, match="nesting"):
        decode_privileged_request(payload(arguments=nested))


def test_rejects_excessive_array_size():
    with pytest.raises(PrivilegedRequestError, match="array"):
        decode_privileged_request(payload(arguments={"items": [0] * 1025}))


def test_rejects_excessive_object_members():
    with pytest.raises(PrivilegedRequestError, match="members"):
        decode_privileged_request(payload(arguments={str(i): i for i in range(129)}))


def test_rejects_excessive_string_size():
    with pytest.raises(PrivilegedRequestError, match="string"):
        decode_privileged_request(payload(arguments={"value": "x" * 8193}))


def test_rejects_non_bytes_payload():
    with pytest.raises(TypeError, match="bytes"):
        decode_privileged_request("not bytes")



def test_rejects_lone_surrogate_in_object_key():
    body = (
        b'{"version":1,"request_id":"' + REQUEST_ID.encode()
        + b'","transaction_id":"' + TRANSACTION_ID.encode()
        + b'","operation":"snapshot_network","arguments":{"\\ud800":1}}'
    )
    with pytest.raises(PrivilegedRequestError, match="key"):
        decode_privileged_request(body)


def test_rejects_integer_exceeding_bounded_numeric_size():
    body = payload(arguments={"value": 1 << 256})
    with pytest.raises(PrivilegedRequestError, match="integer"):
        decode_privileged_request(body)


def test_accepts_integer_at_numeric_size_limit():
    body = payload(arguments={"value": (1 << 256) - 1})
    request = decode_privileged_request(body)
    assert request.arguments["value"] == (1 << 256) - 1
