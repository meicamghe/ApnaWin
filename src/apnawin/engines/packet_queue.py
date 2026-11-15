"""Bounded, thread-safe packet queues for a future Wintun data plane.

This module only moves immutable packet copies between Python threads. It does
not allocate native Wintun send buffers or receive packets from a driver.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from math import isfinite
from threading import Condition, TIMEOUT_MAX
from time import monotonic
from typing import Protocol


class PacketQueueError(RuntimeError):
    """Base error for bounded packet queue operations."""


class PacketQueueClosed(PacketQueueError):
    """The queue has been closed and cannot accept or provide more packets."""


class PacketQueueFull(PacketQueueError):
    """A non-blocking enqueue would exceed the configured queue bounds."""


class PacketQueueTimeout(PacketQueueError):
    """A blocking queue operation exceeded its timeout."""


class PacketHandoffError(PacketQueueError):
    """Both queue insertion and native receive-buffer release failed."""

    def __init__(
        self,
        *,
        enqueued: bool,
        enqueue_error: Exception | None,
        release_error: Exception,
    ) -> None:
        message = (
            "packet was queued but native receive-buffer release failed"
            if enqueued
            else "packet enqueue and native receive-buffer release both failed"
        )
        super().__init__(message)
        self.enqueued = enqueued
        self.enqueue_error = enqueue_error
        self.release_error = release_error


@dataclass(frozen=True, slots=True)
class PacketQueueStats:
    packet_count: int
    queued_bytes: int
    max_packets: int
    max_bytes: int
    max_packet_size: int
    closed: bool


def _deadline_for_timeout(timeout: float | None) -> float | None:
    if timeout is None:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a finite non-negative number or None")
    try:
        valid = isfinite(timeout) and timeout >= 0
        duration = float(timeout)
    except (OverflowError, TypeError, ValueError):
        valid = False
        duration = 0.0
    if not valid:
        raise ValueError("timeout must be a finite non-negative number or None")
    return monotonic() + duration


class ReceivePacketLease(Protocol):
    @property
    def data(self) -> memoryview: ...

    def release(self) -> None: ...


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
            view = memoryview(packet)
        except TypeError as exc:
            raise TypeError("packet must support the buffer protocol") from exc
        if view.ndim != 1 or not view.contiguous:
            raise ValueError("packet must be a contiguous one-dimensional buffer")
        payload = view.tobytes()
        if not payload:
            raise ValueError("packet must not be empty")
        if len(payload) > self._max_packet_size:
            raise ValueError("packet exceeds max_packet_size")
        deadline = _deadline_for_timeout(timeout)
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
                self._condition.wait(
                    None if remaining is None else min(remaining, TIMEOUT_MAX)
                )

    def get(self, *, timeout: float | None = 0) -> bytes:
        """Remove the oldest packet; queued packets remain drainable after close."""
        deadline = _deadline_for_timeout(timeout)
        with self._condition:
            while not self._items:
                if self._closed:
                    raise PacketQueueClosed("queue is closed and drained")
                if timeout == 0:
                    raise PacketQueueFull("packet queue is empty")
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise PacketQueueTimeout("timed out waiting for a packet")
                self._condition.wait(
                    None if remaining is None else min(remaining, TIMEOUT_MAX)
                )
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


def handoff_received_packet(
    queue: BoundedPacketQueue, lease: ReceivePacketLease
) -> None:
    """Copy one native receive lease into the queue, then always release it.

    The queue insertion is deliberately non-blocking so a native Wintun receive
    buffer is never held while waiting for queue capacity. If the queue is full,
    the enqueue error is raised after the release attempt. If both operations
    fail, PacketHandoffError preserves both failures for recovery/diagnostics.
    """
    try:
        queue.put(lease.data, timeout=0)
    except BaseException as enqueue_error:
        try:
            lease.release()
        except BaseException as release_error:
            if isinstance(enqueue_error, Exception) and isinstance(release_error, Exception):
                raise PacketHandoffError(
                    enqueued=False,
                    enqueue_error=enqueue_error,
                    release_error=release_error,
                ) from release_error
            raise release_error from enqueue_error
        raise
    else:
        try:
            lease.release()
        except BaseException as release_error:
            if isinstance(release_error, Exception):
                raise PacketHandoffError(
                    enqueued=True,
                    enqueue_error=None,
                    release_error=release_error,
                ) from release_error
            raise
