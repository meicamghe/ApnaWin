# Bounded packet queue contract

apnawin.engines.packet_queue.BoundedPacketQueue is a platform-neutral FIFO for passing immutable packet copies between producer and consumer threads. It bounds both packet count and aggregate bytes, and separately caps the size of an individual packet. Use distinct queue instances for receive and transmit directions.

## Backpressure and shutdown

- Non-blocking put rejects capacity exhaustion with PacketQueueFull.
- Blocking put and get accept finite timeouts or None for indefinite waits.
- Timeout expiration raises PacketQueueTimeout; it never silently drops a packet.
- close(discard=False) prevents new producers, wakes blocked threads, and allows consumers to drain already queued packets.
- close(discard=True) discards queued copies, returns the discarded byte count, and wakes all waiters.
- All state and byte accounting are protected by one condition lock.

The queue copies inputs into immutable bytes, so a producer cannot mutate a packet after enqueue. This is intentionally a safe handoff abstraction rather than a zero-copy Wintun ring implementation.

## Integration boundary

The future Wintun receive worker must release each native receive packet after copying it into the bounded queue, regardless of enqueue success. The future transmit worker must allocate a Wintun send buffer only when it is ready to copy and send the next queued packet, avoiding allocation while waiting for queue capacity. The native send API consumes the allocated send buffer; there is no separate discard/release operation for a successfully allocated send packet.

This module does not load a DLL, poll Wintun events, mutate routes/DNS, forward traffic, or enable Connect.
