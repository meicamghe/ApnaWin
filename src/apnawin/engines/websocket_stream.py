"""RFC 6455 binary-message stream adapter for SSH-over-WebSocket payloads."""
from __future__ import annotations

import os
import socket
import struct
import threading


class WebSocketStreamError(ConnectionError):
    """The WebSocket peer sent an invalid frame or closed mid-frame."""


class WebSocketStreamSocket:
    """Expose WebSocket binary frames as a socket-like SSH byte stream."""

    def __init__(self, sock: socket.socket, *, max_frame_bytes: int = 16 * 1024 * 1024) -> None:
        if not callable(getattr(sock, "recv", None)) or not callable(getattr(sock, "sendall", None)):
            raise TypeError("WebSocket transport requires a socket-like object")
        if isinstance(max_frame_bytes, bool) or not isinstance(max_frame_bytes, int):
            raise TypeError("max_frame_bytes must be an integer")
        if not 1024 <= max_frame_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_frame_bytes is outside the safe range")
        self._socket = sock
        self._max_frame_bytes = max_frame_bytes
        self._receive_buffer = bytearray()
        self._receive_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._fragmented = False
        self._closed = False
        self._socket_closed = False
        self._close_sent = False

    @property
    def closed(self) -> bool:
        return self._closed

    def _read_exact(self, size: int, *, allow_clean_eof: bool = False) -> bytes | None:
        result = bytearray()
        while len(result) < size:
            chunk = self._socket.recv(size - len(result))
            if not chunk:
                if allow_clean_eof and not result:
                    return None
                raise EOFError("WebSocket peer closed in the middle of a frame")
            result.extend(chunk)
        return bytes(result)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self._closed:
            raise OSError("WebSocket stream is closed")
        if len(payload) > self._max_frame_bytes:
            raise WebSocketStreamError("WebSocket outgoing frame exceeds the configured size limit")
        mask = os.urandom(4)
        length = len(payload)
        first = 0x80 | opcode
        if length < 126:
            header = bytes((first, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
        masked = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
        with self._send_lock:
            if self._closed:
                raise OSError("WebSocket stream is closed")
            self._socket.sendall(header + mask + masked)

    def send(self, data: bytes, flags: int = 0) -> int:
        if flags:
            raise ValueError("WebSocket stream does not support send flags")
        payload = bytes(data)
        if not payload:
            return 0
        self._send_frame(0x2, payload)
        return len(payload)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        if flags:
            raise ValueError("WebSocket stream does not support send flags")
        self.send(data)

    def _read_frame(self) -> None:
        header = self._read_exact(2, allow_clean_eof=True)
        if header is None:
            self._closed = True
            return
        first, second = header
        final = bool(first & 0x80)
        if first & 0x70:
            raise WebSocketStreamError("WebSocket RSV bits must be zero without negotiated extensions")
        opcode = first & 0x0F
        if second & 0x80:
            raise WebSocketStreamError("WebSocket server frames must not be masked")
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
            if length < 126:
                raise WebSocketStreamError("WebSocket frame uses a non-canonical length encoding")
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
            if length < 65536 or length & (1 << 63):
                raise WebSocketStreamError("WebSocket frame uses an invalid 64-bit length")
        if length > self._max_frame_bytes:
            raise WebSocketStreamError("WebSocket incoming frame exceeds the configured size limit")
        if opcode >= 0x8 and (not final or length > 125):
            raise WebSocketStreamError("WebSocket control frames must be final and at most 125 bytes")
        payload = self._read_exact(length)

        if opcode == 0x8:
            if len(payload) == 1:
                raise WebSocketStreamError("WebSocket close frame cannot contain a one-byte status payload")
            if len(payload) >= 2:
                close_code = struct.unpack("!H", payload[:2])[0]
                if (
                    close_code < 1000
                    or close_code in {1004, 1005, 1006, 1015}
                    or 1016 <= close_code <= 2999
                    or close_code >= 5000
                ):
                    raise WebSocketStreamError("WebSocket close frame contains a reserved or invalid status code")
                try:
                    payload[2:].decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise WebSocketStreamError("WebSocket close reason is not valid UTF-8") from exc
            if not self._close_sent:
                try:
                    self._send_frame(0x8, payload)
                    self._close_sent = True
                except OSError:
                    pass
            self._closed = True
            return
        if opcode == 0x9:
            self._send_frame(0xA, payload)
            return
        if opcode == 0xA:
            return
        if opcode == 0x2:
            if self._fragmented:
                raise WebSocketStreamError("WebSocket binary message started before prior fragments completed")
            self._fragmented = not final
        elif opcode == 0x0:
            if not self._fragmented:
                raise WebSocketStreamError("Unexpected WebSocket continuation frame")
            self._fragmented = not final
        elif opcode == 0x1:
            raise WebSocketStreamError("WebSocket text frames cannot carry the SSH byte stream")
        else:
            raise WebSocketStreamError(f"Unsupported WebSocket opcode: {opcode}")
        self._receive_buffer.extend(payload)

    def recv(self, size: int, flags: int = 0) -> bytes:
        if flags:
            raise ValueError("WebSocket stream does not support recv flags")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("recv size must be a non-negative integer")
        if size == 0:
            return b""
        with self._receive_lock:
            while not self._receive_buffer and not self._closed:
                self._read_frame()
            if not self._receive_buffer:
                return b""
            count = min(size, len(self._receive_buffer))
            result = bytes(self._receive_buffer[:count])
            del self._receive_buffer[:count]
            return result

    def settimeout(self, value: float | None) -> None:
        self._socket.settimeout(value)

    def gettimeout(self) -> float | None:
        return self._socket.gettimeout()

    def setblocking(self, flag: bool) -> None:
        self._socket.setblocking(flag)

    def fileno(self) -> int:
        return self._socket.fileno()

    def shutdown(self, how: int) -> None:
        self._socket.shutdown(how)

    def close(self) -> None:
        if self._socket_closed:
            return
        self._closed = True
        self._socket_closed = True
        self._socket.close()
