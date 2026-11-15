"""Bounded, thread-safe packet queues for a future Wintun data plane.

This module only moves immutable packet copies between Python threads. It does
not allocate native Wintun send buffers or receive packets from a driver.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Condition
from time import monotonic


class PacketQueueError(RuntimeError):
    """Base error for bounded packet queue operations."""


class PacketQueueClosed(PacketQueueError):
    """The queue has been closed and cannot accept or provide more packets."""


class PacketQueueFull(PacketQueueError):
    """A non-blocking enqueue would exceed the configured queue bounds."""


class PacketQueueTimeout(PacketQueueError):
    """A blocking queue operation exceeded its timeout."""


@dataclass(frozen=True, slots=True)
class PacketQueueStats:
    packet_count: int
    queued_bytes: int
    max_packets: int
    max_bytes: int
    max_packet_size: int
    closed: bool


class BoundedPacketQueue:
    """FIFO queue bounded by both packet count and total payload bytes.

    Packets are copied to immutable bytes at enqueue time. This prevents
    producers from mutating a packet after it has entered the queue. A queue
    instance is intended for one direction; use separate instances for RX/TX.
    """

    def __init__(
        self,
        *,
        max_packets: int = 256,
        max_bytes: int = 4 * 1024 * 1024,
        max_packet_size: int = 65535,
    ) -> None:
        for value, name in (
            (max_packets, "max_packets"),
            (max_bytes, "max_bytes"),
            (max_packet_size, "max_packet_size"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if max_packet_size > max_bytes:
            raise ValueError("max_packet_size cannot exceed max_bytes")
        self._max_packets = max_packets
        self._max_bytes = max_bytes
        self._max_packet_size = max_packet_size
        self._items: deque[bytes] = deque()
        self._queued_bytes = 0
        self._closed = False
        self._condition = Condition()

    @property
    def stats(self) -> PacketQueueStats:
        with self._condition:
            return PacketQueueStats(
                packet_count=len(self._items),
                queued_bytes=self._queued_bytes,
                max_packets=self._max_packets,
                max_bytes=self._max_bytes,
                max_packet_size=self._max_packet_size,
                closed=self._closed,
            )

    def put(self, packet: bytes | bytearray | memoryview, *, timeout: float | None = 0) -> None:
        """Enqueue a packet; timeout=0 is non-blocking, None waits indefinitely."""
        try:
            payload = bytes(packet)
        except (TypeError, ValueError) as exc:
            raise TypeError("packet must support the buffer protocol") from exc
        if not payload:
            raise ValueError("packet must not be empty")
        if len(payload) > self._max_packet_size:
            raise ValueError("packet exceeds max_packet_size")
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        deadline = None if timeout is None else monotonic() + timeout
        with self._condition:
            while True:
                if self._closed:
                    raise PacketQueueClosed("queue is closed")
                has_capacity = (
                    len(self._items) < self._max_packets
                    and self._queued_bytes + len(payload) <= self._max_bytes
                )
                if has_capacity:
                    self._items.append(payload)
                    self._queued_bytes += len(payload)
                    self._condition.notify_all()
                    return
                if timeout == 0:
                    raise PacketQueueFull("packet queue capacity is exhausted")
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise PacketQueueTimeout("timed out waiting for packet queue capacity")
                self._condition.wait(remaining)

    def get(self, *, timeout: float | None = 0) -> bytes:
        """Remove the oldest packet; queued packets remain drainable after close."""
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        deadline = None if timeout is None else monotonic() + timeout
        with self._condition:
            while not self._items:
                if self._closed:
                    raise PacketQueueClosed("queue is closed and drained")
                if timeout == 0:
                    raise PacketQueueFull("packet queue is empty")
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise PacketQueueTimeout("timed out waiting for a packet")
                self._condition.wait(remaining)
            payload = self._items.popleft()
            self._queued_bytes -= len(payload)
            self._condition.notify_all()
            return payload

    def close(self, *, discard: bool = False) -> int:
        """Stop producers and wake waiters; optionally discard queued packets.

        Returns the number of bytes discarded. With discard=False, consumers
        can drain already-enqueued packets before get() reports closed.
        """
        if not isinstance(discard, bool):
            raise TypeError("discard must be a boolean")
        with self._condition:
            self._closed = True
            discarded = self._queued_bytes if discard else 0
            if discard:
                self._items.clear()
                self._queued_bytes = 0
            self._condition.notify_all()
            return discarded
