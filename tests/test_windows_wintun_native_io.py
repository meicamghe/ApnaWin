import ctypes
from ctypes import POINTER, c_ubyte, cast, string_at, wintypes

from apnawin.engines.windows_wintun import WindowsWintunBackend


class FakeFunction:
    def __init__(self, callback=None):
        self.callback = callback
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        if self.callback:
            return self.callback(*args)
        return 1


def test_native_receive_packet_returns_exact_release_callback():
    storage = (c_ubyte * 4)(1, 2, 3, 4)
    pointer = cast(storage, POINTER(c_ubyte))
    released = []
    backend = object.__new__(WindowsWintunBackend)

    def receive(session, size_pointer):
        cast(size_pointer, POINTER(wintypes.DWORD)).contents.value = 4
        return pointer

    backend._receive_packet = FakeFunction(receive)
    backend._release_receive_packet = FakeFunction(
        lambda session, packet: released.append(string_at(packet, 4))
    )
    result = backend.receive_packet(123)
    assert result is not None
    buffer, release = result
    assert bytes(buffer) == b"\x01\x02\x03\x04"
    release()
    release()
    assert released == [b"\x01\x02\x03\x04"]


def test_native_send_packet_copies_bytes_and_sends_once():
    sent = []
    storage = (c_ubyte * 4)()
    backend = object.__new__(WindowsWintunBackend)
    backend._allocate_send_packet = FakeFunction(
        lambda session, size: cast(storage, POINTER(c_ubyte))
    )
    backend._send_packet = FakeFunction(
        lambda session, packet: sent.append(string_at(packet, 4))
    )
    assert backend.send_packet(123, memoryview(b"test"))
    assert sent == [b"test"]


def test_native_send_packet_reports_ring_backpressure(monkeypatch):
    backend = object.__new__(WindowsWintunBackend)
    backend._allocate_send_packet = FakeFunction(lambda session, size: None)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 111, raising=False)
    assert backend.send_packet(123, b"packet") is False
