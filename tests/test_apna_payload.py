from __future__ import annotations

import pytest

from apnawin.engines.apna_payload import (
    PayloadFormatError,
    PayloadRotation,
    PayloadChunk,
    render_apna_payload,
    send_payload,
)


def test_expands_apna_observed_endpoint_and_line_ending_tokens() -> None:
    chunks = render_apna_payload(
        "[method] [host] [host_port] [port] [protocol] [ssh][crlf][cr][lf][lfcr]",
        host="ssh.example.test",
        port=443,
    )
    assert chunks == (
        PayloadChunk(
            b"[method] ssh.example.test ssh.example.test:443 443 HTTP/1.0 "
            b"ssh.example.test:443\\r\\n\\r\\n\\n\\r"
        ),
    )


def test_instant_split_creates_immediate_flush_boundaries() -> None:
    chunks = render_apna_payload("A[instant_split]B[instant_split]C", host="h.test", port=22)
    assert [chunk.data for chunk in chunks] == [b"A", b"B", b"C"]
    assert [chunk.delay_after_ms for chunk in chunks] == [0, 0, 0]


def test_delay_split_adds_configurable_delay_after_segment() -> None:
    chunks = render_apna_payload(
        "A[delay_split]B", host="h.test", port=22, delay_split_ms=750
    )
    assert chunks == (PayloadChunk(b"A", 750), PayloadChunk(b"B", 0))


def test_combines_instant_and_delayed_splits_in_order() -> None:
    chunks = render_apna_payload(
        "A[instant_split]B[delay_split]C[instant_split]D",
        host="h.test",
        port=22,
    )
    assert chunks == (
        PayloadChunk(b"A", 0),
        PayloadChunk(b"B", 1000),
        PayloadChunk(b"C", 0),
        PayloadChunk(b"D", 0),
    )


def test_rotate_advances_round_robin_and_resets_when_template_changes() -> None:
    rotation = PayloadRotation()
    template = "CONNECT [rotate=a.example;b.example] [port]"
    assert render_apna_payload(
        template, host="ssh.example.test", port=22, rotation=rotation
    )[0].data == b"CONNECT a.example 22"
    assert render_apna_payload(
        template, host="ssh.example.test", port=22, rotation=rotation
    )[0].data == b"CONNECT b.example 22"
    assert render_apna_payload(
        template, host="ssh.example.test", port=22, rotation=rotation
    )[0].data == b"CONNECT a.example 22"
    assert render_apna_payload(
        template + " ", host="ssh.example.test", port=22, rotation=rotation
    )[0].data == b"CONNECT a.example 22 "


def test_unknown_tokens_are_preserved_for_compatibility_visibility() -> None:
    chunks = render_apna_payload(
        "[unknown] [ua] [auth]", host="ssh.example.test", port=22
    )
    assert chunks[0].data == b"[unknown] [ua] [auth]"


@pytest.mark.parametrize(
    ("host", "port"),
    [("bad host", 22), ("host\r\nInjected: yes", 22), ("ssh.example.test", 0)],
)
def test_rejects_unsafe_endpoints(host: str, port: int) -> None:
    with pytest.raises(PayloadFormatError):
        render_apna_payload("test", host=host, port=port)


def test_rejects_payloads_that_cannot_be_encoded_as_iso_8859_1() -> None:
    with pytest.raises(PayloadFormatError, match="ISO-8859-1"):
        render_apna_payload("snowman ☃", host="h.test", port=22)


def test_send_payload_flushes_each_segment_and_sleeps_only_when_requested() -> None:
    class Writer:
        def __init__(self):
            self.writes = []
            self.flushes = 0

        def write(self, data):
            self.writes.append(data)

        def flush(self):
            self.flushes += 1

    writer = Writer()
    sleeps = []
    chunks = render_apna_payload("A[instant_split]B[delay_split]C", host="h.test", port=22)
    send_payload(writer, chunks, sleep=sleeps.append)
    assert writer.writes == [b"A", b"B", b"C"]
    assert writer.flushes == 3
    assert sleeps == [1.0]
