from __future__ import annotations

import math
import socket
import struct

import pytest

from apnawin.engines.apna_udp_dns_probe import (
    UdpDnsProbeError,
    _query_bytes,
    _validate_response,
    probe_udp_dns,
)


def _response(
    query: bytes,
    *,
    answers: int = 1,
    flags: int = 0x8180,
    question: bytes | None = None,
) -> bytes:
    transaction_id = struct.unpack("!H", query[:2])[0]
    question = query[12:] if question is None else question
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, answers, 0, 0)
    # A compressed owner name, A/IN, TTL=60, RDLENGTH=4, 93.184.216.34.
    answer = b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
    return header + question + answer


def test_query_is_a_recursive_example_com_question() -> None:
    query = _query_bytes(0x1234)
    assert query[:12] == struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    assert query[12:] == b"\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01"


def test_response_validator_checks_transaction_and_answer() -> None:
    query = _query_bytes(0x4567)
    assert _validate_response(_response(query), 0x4567)
    assert not _validate_response(_response(query), 0x4568)
    assert not _validate_response(_response(query, answers=0), 0x4567)
    assert not _validate_response(_response(query, flags=0x8183), 0x4567)


@pytest.mark.parametrize(
    "flags",
    (
        0x0180,  # Not a response.
        0x8980,  # Unsupported opcode.
        0x8380,  # Truncated response.
        0x8183,  # NXDOMAIN.
    ),
)
def test_response_validator_rejects_wrong_dns_response_flags(flags: int) -> None:
    query = _query_bytes(0x1234)
    assert not _validate_response(_response(query, flags=flags), 0x1234)


def test_response_validator_requires_the_exact_question() -> None:
    query = _query_bytes(0x1234)
    wrong_question = b"\\x03bad\\x03com\\x00\\x00\\x01\\x00\\x01"
    assert not _validate_response(
        _response(query, question=wrong_question), 0x1234
    )


def test_response_validator_rejects_short_and_non_byte_responses() -> None:
    assert not _validate_response(b"short", 0x1234)
    assert not _validate_response("not bytes", 0x1234)  # type: ignore[arg-type]


def test_udp_dns_probe_uses_each_configured_address_family(monkeypatch) -> None:
    observed = []

    class FakeSocket:
        def __init__(self, family, kind):
            self.family = family

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def settimeout(self, value):
            self.timeout = value

        def sendto(self, query, destination):
            observed.append((self.family, destination, query))
            self.query = query

        def recvfrom(self, size):
            server = "1.1.1.1" if self.family == socket.AF_INET else "2606:4700:4700::1111"
            return _response(self.query), (server, 53)

    monkeypatch.setattr(socket, "socket", FakeSocket)
    assert probe_udp_dns(("1.1.1.1", "2606:4700:4700::1111")) == (4, 6)
    assert [item[0] for item in observed] == [socket.AF_INET, socket.AF_INET6]


def test_udp_dns_probe_fails_closed_when_ipv6_dns_does_not_reply(monkeypatch) -> None:
    class FakeSocket:
        def __init__(self, family, kind):
            self.family = family

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def settimeout(self, value):
            return None

        def sendto(self, query, destination):
            self.query = query

        def recvfrom(self, size):
            if self.family == socket.AF_INET6:
                raise socket.timeout("timed out")
            return _response(self.query), ("1.1.1.1", 53)

    monkeypatch.setattr(socket, "socket", FakeSocket)
    with pytest.raises(UdpDnsProbeError, match="family 6"):
        probe_udp_dns(("1.1.1.1", "2606:4700:4700::1111"), timeout=0.01)


@pytest.mark.parametrize("timeout", (0, -1, math.inf, -math.inf, math.nan, True))
def test_udp_dns_probe_rejects_non_finite_or_non_positive_timeout(timeout) -> None:
    with pytest.raises(ValueError, match="timeout"):
        probe_udp_dns(("1.1.1.1",), timeout=timeout)


def test_udp_dns_probe_rejects_invalid_resolver_values() -> None:
    with pytest.raises(ValueError):
        probe_udp_dns(())
    with pytest.raises(ValueError):
        probe_udp_dns(("dns.example.test",))


def test_udp_dns_probe_deduplicates_resolvers() -> None:
    observed = []

    class FakeSocket:
        def __init__(self, family, kind):
            self.family = family

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def settimeout(self, value):
            return None

        def sendto(self, query, destination):
            observed.append(destination)
            self.query = query

        def recvfrom(self, size):
            return _response(self.query), ("1.1.1.1", 53)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(socket, "socket", FakeSocket)
    try:
        assert probe_udp_dns(("1.1.1.1", "1.1.1.1")) == (4,)
        assert observed == [("1.1.1.1", 53)]
    finally:
        monkeypatch.undo()
