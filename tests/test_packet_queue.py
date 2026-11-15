import threading
import time

import pytest

from apnawin.engines.packet_queue import (
    BoundedPacketQueue,
    PacketQueueClosed,
    PacketQueueFull,
    PacketQueueTimeout,
)


def test_queue_preserves_fifo_and_bounds_packet_count_and_bytes():
    queue = BoundedPacketQueue(max_packets=2, max_bytes=6, max_packet_size=4)
    queue.put(b"abc")
    queue.put(b"def")
    with pytest.raises(PacketQueueFull):
        queue.put(b"x")
    assert queue.stats.packet_count == 2
    assert queue.stats.queued_bytes == 6
    assert queue.get() == b"abc"
    assert queue.get() == b"def"
    assert queue.stats.queued_bytes == 0


def test_queue_copies_mutable_input():
    queue = BoundedPacketQueue(max_packets=2, max_bytes=16, max_packet_size=16)
    packet = bytearray(b"original")
    queue.put(packet)
    packet[:] = b"modified"
    assert queue.get() == b"original"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_packets": 0},
        {"max_bytes": 0},
        {"max_packet_size": 0},
        {"max_packet_size": 9, "max_bytes": 8},
        {"max_packets": True},
    ],
)
def test_rejects_invalid_bounds(kwargs):
    with pytest.raises(ValueError):
        BoundedPacketQueue(**kwargs)


def test_rejects_empty_and_oversized_packets():
    queue = BoundedPacketQueue(max_packets=2, max_bytes=8, max_packet_size=4)
    with pytest.raises(ValueError, match="empty"):
        queue.put(b"")
    with pytest.raises(ValueError, match="max_packet_size"):
        queue.put(b"12345")


def test_close_drains_existing_packets_and_rejects_new_packets():
    queue = BoundedPacketQueue(max_packets=2, max_bytes=8, max_packet_size=8)
    queue.put(b"keep")
    assert queue.close() == 0
    assert queue.get() == b"keep"
    with pytest.raises(PacketQueueClosed):
        queue.put(b"new")
    with pytest.raises(PacketQueueClosed):
        queue.get()


def test_close_discard_clears_queued_packets_and_reports_bytes():
    queue = BoundedPacketQueue(max_packets=3, max_bytes=12, max_packet_size=8)
    queue.put(b"1234")
    queue.put(b"567")
    assert queue.close(discard=True) == 7
    assert queue.stats.packet_count == 0
    assert queue.stats.queued_bytes == 0
    with pytest.raises(PacketQueueClosed):
        queue.get()


def test_blocked_producer_wakes_when_capacity_is_freed():
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    queue.put(b"first")
    result = []

    def producer():
        queue.put(b"next", timeout=1)
        result.append(True)

    thread = threading.Thread(target=producer)
    thread.start()
    time.sleep(0.02)
    assert thread.is_alive()
    assert queue.get() == b"first"
    thread.join(1)
    assert not thread.is_alive()
    assert result == [True]
    assert queue.get() == b"next"


def test_close_wakes_blocked_producer():
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    queue.put(b"first")
    errors = []

    def producer():
        try:
            queue.put(b"next", timeout=None)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=producer)
    thread.start()
    time.sleep(0.02)
    queue.close()
    thread.join(1)
    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], PacketQueueClosed)


def test_blocking_get_wakes_on_packet_and_close():
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    result = []

    def consumer():
        result.append(queue.get(timeout=1))

    thread = threading.Thread(target=consumer)
    thread.start()
    time.sleep(0.02)
    queue.put(b"data")
    thread.join(1)
    assert not thread.is_alive()
    assert result == [b"data"]

    errors = []
    thread = threading.Thread(target=lambda: _capture_get(queue, errors))
    thread.start()
    time.sleep(0.02)
    queue.close()
    thread.join(1)
    assert not thread.is_alive()
    assert isinstance(errors[0], PacketQueueClosed)


def _capture_get(queue, errors):
    try:
        queue.get(timeout=None)
    except Exception as exc:
        errors.append(exc)


def test_nonblocking_empty_and_timed_operations_are_explicit():
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    with pytest.raises(PacketQueueFull):
        queue.get()
    with pytest.raises(PacketQueueTimeout):
        queue.get(timeout=0.01)
    queue.put(b"12345678")
    with pytest.raises(PacketQueueTimeout):
        queue.put(b"x", timeout=0.01)


@pytest.mark.parametrize("packet", [7, object()])
def test_rejects_values_that_do_not_support_the_buffer_protocol(packet):
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    with pytest.raises(TypeError, match="buffer protocol"):
        queue.put(packet)


@pytest.mark.parametrize("timeout", [-1, float("nan"), float("inf"), True, "1", 10**1000])
def test_rejects_invalid_timeouts(timeout):
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    with pytest.raises(ValueError, match="finite non-negative"):
        queue.put(b"x", timeout=timeout)
    with pytest.raises(ValueError, match="finite non-negative"):
        queue.get(timeout=timeout)


def test_rejects_multidimensional_and_noncontiguous_packet_views():
    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    multidimensional = memoryview(bytearray(b"1234")).cast("B", shape=(2, 2))
    noncontiguous = memoryview(bytearray(b"1234"))[::2]
    with pytest.raises(ValueError, match="one-dimensional"):
        queue.put(multidimensional)
    with pytest.raises(ValueError, match="contiguous"):
        queue.put(noncontiguous)


def test_handoff_received_packet_copies_then_releases_native_lease():
    from apnawin.engines.packet_queue import handoff_received_packet

    class Lease:
        data = memoryview(b"native-packet")

        def __init__(self):
            self.releases = 0

        def release(self):
            self.releases += 1

    queue = BoundedPacketQueue(max_packets=1, max_bytes=32, max_packet_size=32)
    lease = Lease()
    handoff_received_packet(queue, lease)
    assert queue.get() == b"native-packet"
    assert lease.releases == 1


def test_handoff_releases_native_lease_when_queue_is_full():
    from apnawin.engines.packet_queue import handoff_received_packet

    class Lease:
        data = memoryview(b"next")

        def __init__(self):
            self.releases = 0

        def release(self):
            self.releases += 1

    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    queue.put(b"full")
    lease = Lease()
    with pytest.raises(PacketQueueFull):
        handoff_received_packet(queue, lease)
    assert lease.releases == 1
    assert queue.get() == b"full"


def test_handoff_preserves_both_enqueue_and_release_failures():
    from apnawin.engines.packet_queue import PacketHandoffError, handoff_received_packet

    class Lease:
        data = memoryview(b"next")

        def release(self):
            raise OSError("native release failed")

    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    queue.put(b"full")
    with pytest.raises(PacketHandoffError) as caught:
        handoff_received_packet(queue, Lease())
    assert isinstance(caught.value.enqueue_error, PacketQueueFull)
    assert isinstance(caught.value.release_error, OSError)


def test_handoff_surfaces_release_failure_after_successful_copy():
    from apnawin.engines.packet_queue import handoff_received_packet

    class Lease:
        data = memoryview(b"copied")

        def release(self):
            raise OSError("native release failed")

    queue = BoundedPacketQueue(max_packets=1, max_bytes=8, max_packet_size=8)
    with pytest.raises(OSError, match="native release failed"):
        handoff_received_packet(queue, Lease())
    assert queue.get() == b"copied"
