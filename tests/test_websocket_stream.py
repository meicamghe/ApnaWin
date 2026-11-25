from __future__ import annotations

import socket
import threading

import pytest

from apnawin.engines.websocket_stream import WebSocketStreamError, WebSocketStreamSocket


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data.extend(chunk)
    return bytes(data)


def _read_client_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = _read_exact(sock, 2)
    assert second & 0x80
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(_read_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_read_exact(sock, 8), "big")
    mask = _read_exact(sock, 4)
    payload = _read_exact(sock, length)
    decoded = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
    return first & 0x0F, decoded


def test_binary_stream_masks_client_frames_and_unwraps_server_frames():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    observed = []

    def peer():
        opcode, payload = _read_client_frame(server)
        observed.append((opcode, payload))
        server.sendall(b"\x82\x0cserver-reply")

    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    try:
        stream.sendall(b"client-request")
        assert stream.recv(64) == b"server-reply"
        assert observed == [(0x2, b"client-request")]
    finally:
        stream.close()
        server.close()
        worker.join(timeout=1)


def test_fragmented_binary_message_and_ping_are_handled():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    pong = []

    def peer():
        server.sendall(b"\x02\x04part")
        server.sendall(b"\x89\x01p")
        server.sendall(b"\x80\x04-two")
        opcode, payload = _read_client_frame(server)
        pong.append((opcode, payload))

    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    try:
        received = stream.recv(16) + stream.recv(16)
        assert received == b"part-two"
        worker.join(timeout=1)
        assert pong == [(0xA, b"p")]
    finally:
        stream.close()
        server.close()


def test_masked_server_frame_is_rejected():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\x82\x80")
    try:
        with pytest.raises(WebSocketStreamError, match="server frames must not be masked"):
            stream.recv(8)
    finally:
        stream.close()
        server.close()


def test_text_frames_are_rejected_for_ssh_stream():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\x81\x02hi")
    try:
        with pytest.raises(WebSocketStreamError, match="text frames cannot carry"):
            stream.recv(8)
    finally:
        stream.close()
        server.close()


def test_close_frame_is_echoed_and_underlying_socket_is_released():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\x88\x02\x03\xe8")
    try:
        assert stream.recv(1) == b""
        opcode, payload = _read_client_frame(server)
        assert opcode == 0x8
        assert payload == b"\x03\xe8"
        stream.close()
        assert client.fileno() == -1
    finally:
        stream.close()
        server.close()


@pytest.mark.parametrize("status", [0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535])
def test_reserved_or_invalid_close_status_is_rejected(status):
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\\x88\\x02" + status.to_bytes(2, "big"))
    try:
        with pytest.raises(WebSocketStreamError, match="reserved or invalid status code"):
            stream.recv(1)
    finally:
        stream.close()
        server.close()


def test_invalid_utf8_close_reason_is_rejected():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\\x88\\x03\\x03\\xe8\\xff")
    try:
        with pytest.raises(WebSocketStreamError, match="not valid UTF-8"):
            stream.recv(1)
    finally:
        stream.close()
        server.close()


def test_registered_application_close_status_and_utf8_reason_are_echoed():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    close_payload = (3001).to_bytes(2, "big") + "normal پایان".encode("utf-8")
    server.sendall(bytes((0x88, len(close_payload))) + close_payload)
    try:
        assert stream.recv(1) == b""
        opcode, payload = _read_client_frame(server)
        assert opcode == 0x8
        assert payload == close_payload
    finally:
        stream.close()
        server.close()


def test_empty_close_payload_is_echoed():
    client, server = socket.socketpair()
    stream = WebSocketStreamSocket(client)
    server.sendall(b"\\x88\\x00")
    try:
        assert stream.recv(1) == b""
        opcode, payload = _read_client_frame(server)
        assert opcode == 0x8
        assert payload == b""
    finally:
        stream.close()
        server.close()
