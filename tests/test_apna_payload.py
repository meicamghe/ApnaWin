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
        "[host] [host_port] [port] [protocol] [ssh][crlf][cr][lf][lfcr]",
        host="ssh.example.test",
        port=443,
    )
    assert chunks == (
        PayloadChunk(
            b"ssh.example.test ssh.example.test:443 443 HTTP/1.0 "
            b"ssh.example.test:443\r\n\r\n\n\r"
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
        "[unknown] [auth]", host="ssh.example.test", port=22
    )
    assert chunks[0].data == b"[unknown] [auth]"


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


def test_escaped_newline_tokens_are_converted_to_control_bytes() -> None:
    chunks = render_apna_payload(
        r"A\nB\rC",
        host="ssh.example.test",
        port=22,
    )
    assert chunks[0].data == b"A\nB\rC"


def test_apna_formatter_expands_method_and_default_user_agent() -> None:
    chunks = render_apna_payload(
        "[method] [host] [port] [host_port] [protocol] [ssh][crlf][ua]",
        host="ssh.example.test",
        port=22,
    )
    assert chunks[0].data == (
        b"CONNECT ssh.example.test 22 ssh.example.test:22 HTTP/1.0 "
        b"ssh.example.test:22\r\n"
        b"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        b"(KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36"
    )


def test_rotate_resets_when_formatted_payload_changes_and_replaces_duplicate_tokens_together() -> None:
    rotation = PayloadRotation()
    template = "[host] [rotate=a;b] [rotate=a;b]"
    assert render_apna_payload(template, host="one.test", port=22, rotation=rotation)[0].data == (
        b"one.test a a"
    )
    assert render_apna_payload(template, host="one.test", port=22, rotation=rotation)[0].data == (
        b"one.test b b"
    )
    assert render_apna_payload(template, host="two.test", port=22, rotation=rotation)[0].data == (
        b"two.test a a"
    )


def test_java_split_discards_trailing_empty_segment_without_extra_delay() -> None:
    chunks = render_apna_payload(
        "A[instant_split]", host="h.test", port=22
    )
    assert chunks == (PayloadChunk(b"A", 0),)
    delayed = render_apna_payload(
        "A[delay_split]", host="h.test", port=22
    )
    assert delayed == (PayloadChunk(b"A", 0),)



def test_cf_and_brand_catalog_tokens_are_expanded_before_rotation():
    rotation = PayloadRotation()
    template = "GET / [cf] [brand] [rotate=a;b] [host] [host_port][crlf]"
    chunks = render_apna_payload(
        template,
        host="ssh.example.test",
        port=443,
        cf_host="front.example.test",
        brand="ApnaWin",
        rotation=rotation,
    )
    assert chunks[0].data == (
        b"GET / front.example.test ApnaWin a ssh.example.test ssh.example.test:443\r\n"
    )


def test_rotation_state_resets_when_expanded_host_changes():
    rotation = PayloadRotation()
    template = "CONNECT [rotate=a;b] [host_port]"
    first = render_apna_payload(
        template, host="ssh-a.example.test", port=443, rotation=rotation
    )
    second = render_apna_payload(
        template, host="ssh-a.example.test", port=443, rotation=rotation
    )
    changed = render_apna_payload(
        template, host="ssh-b.example.test", port=443, rotation=rotation
    )
    assert first[0].data.startswith(b"CONNECT a ")
    assert second[0].data.startswith(b"CONNECT b ")
    assert changed[0].data.startswith(b"CONNECT a ")
