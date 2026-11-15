# Wintun adapter and session ownership contract

## Scope

`apnawin.engines.wintun_session` is a platform-neutral lifecycle owner around an injected backend. It does not load a DLL, create an adapter itself, forward packets, configure IP addresses, mutate routes/DNS, or elevate privileges. The fake backend in unit tests validates ownership semantics only.

## Required backend contract

A future Windows backend must map these narrow methods to the pinned Wintun API:
- `create_adapter(name, tunnel_type, requested_guid)`
- `get_adapter_luid(adapter)`
- `start_session(adapter, ring_capacity)`
- `end_session(session)`
- `close_adapter(adapter)`

The adapter must own and validate every native handle. It must reject unexpected DLL paths and load only a pinned, architecture-matched, signature/hash-verified Wintun binary after license review. Never load an arbitrary DLL found through PATH or a user-writable directory.

## Lifecycle invariants

1. Adapter creation precedes LUID lookup and session start.
2. Ring capacity is a power of two from 128 KiB through 64 MiB.
3. Session shutdown precedes adapter close.
4. If ending a session fails, both session and adapter handles remain owned; the adapter is not closed underneath a live session.
5. If adapter close fails, its handle remains owned and `stop()` can be retried.
6. Initialization failure triggers reverse cleanup. Cleanup failures are surfaced and retained instead of being hidden.
7. A single owner instance rejects reentrant start and makes successful stop idempotent.

## Not implemented

The actual Win32/Wintun FFI, receive/send loops, cancellation/wakeup events, MTU handling, IP address assignment, route/DNS integration, helper service, and end-to-end leak tests are not implemented. Receive packet lease ownership is modeled in Python, and bounded inter-thread packet queues are implemented as platform-neutral components; neither is connected to a native driver. Do not interpret `SESSION_STARTED` as a working VPN connection.

Connect remains disabled until the real backend and full Windows integration pass clean-machine and network acceptance tests.


## Receive packet lease contract

The owner can track one buffer returned by the native receive API. The lease exposes a read-only, contiguous byte view (format `B`, one byte per element) and requires release after packet processing. Non-byte buffer exporters are normalized to byte views so `len(view)` and packet byte length agree. A successful native release removes the lease from the outstanding set; a failed release retains it so the caller can retry.

Session stop refuses to call EndSession while any receive lease remains outstanding. This prevents teardown from invalidating a packet buffer still being consumed. Context-manager use guarantees a release attempt on normal exit and exception exit, but a release callback failure remains visible and retains ownership.

The future FFI must bind the callback to WintunReleaseReceivePacket for the exact packet pointer. The platform-neutral handoff_received_packet helper copies the lease into a bounded queue without blocking and then attempts release; it does not itself call Wintun. If release fails after enqueue, its error marks enqueued=True so callers retry only the lease release and do not enqueue a duplicate packet. Consumers must not retain the memoryview beyond the lease lifetime. Python cannot revoke an already-copied memoryview reference, so the native adapter and packet-processing layer must enforce this lifetime rule.

This abstraction does not implement packet polling, receive loops, send allocation, packet forwarding, or a native DLL.
