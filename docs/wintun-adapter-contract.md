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

The actual Win32/Wintun FFI, packet buffer leases, receive/send loops, bounded queues, cancellation/wakeup events, MTU handling, IP address assignment, route/DNS integration, helper service, and end-to-end leak tests are not implemented. Do not interpret `SESSION_STARTED` as a working VPN connection.

Connect remains disabled until the real backend and full Windows integration pass clean-machine and network acceptance tests.
