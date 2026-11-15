# Wintun adapter and session ownership contract

## Scope

`apnawin.engines.wintun_session` is a platform-neutral lifecycle owner around an injected backend. The fake backend in unit tests validates ownership semantics only.

## Native Windows backend

`apnawin.engines.windows_wintun.WindowsWintunBackend` provides a Windows x64 ctypes adapter for the Wintun C API. It binds the required adapter/session and packet send/receive exports, obtains the adapter LUID, exposes the Wintun read-wait event, and maps the documented empty-ring and send-ring-full conditions to explicit results.

Before loading the DLL it:
- requires an explicit lowercase SHA-256 pin;
- rejects symbolic-link paths, missing/non-regular files and digest mismatches;
- checks the PE machine field is AMD64;
- loads only the supplied absolute path with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`, never PATH lookup;
- fails if any required Wintun export is missing.

The DLL must be installed beneath an administrator-writable-only application directory. The hash check and subsequent load are separate operations, so a user-writable DLL directory would leave a time-of-check/time-of-use replacement risk. The release manifest must establish the digest from a reviewed official Wintun release and retain the corresponding license/notice. The repository does not contain a Wintun DLL and does not download one automatically.

## Required backend contract

The session owner uses:
- `create_adapter(name, tunnel_type, requested_guid)`
- `get_adapter_luid(adapter)`
- `start_session(adapter, ring_capacity)`
- `end_session(session)`
- `close_adapter(adapter)`

The native backend additionally exposes:
- `get_read_wait_event(session)` — borrowed event handle; do not close it;
- `receive_packet(session)` — returns a bounded packet buffer and its exact native release callback, or `None` when the ring is empty;
- `send_packet(session, packet)` — returns `False` on Wintun ring backpressure and raises for other native failures.

## Lifecycle invariants

1. Adapter creation precedes LUID lookup and session start.
2. Ring capacity is a power of two from 128 KiB through 64 MiB.
3. Session shutdown precedes adapter close.
4. If ending a session fails, both session and adapter handles remain owned; the adapter is not closed underneath a live session.
5. If adapter close fails, its handle remains owned and `stop()` can be retried.
6. Initialization failure triggers reverse cleanup. Cleanup failures are surfaced and retained instead of being hidden.
7. A single owner instance rejects reentrant start and makes successful stop idempotent.

## Not implemented

The FFI now exists, but the production packet pump, cancellation/wakeup coordination, MTU handling, interface IP configuration, route/DNS integration, privileged service, and end-to-end leak tests are still not implemented. A Wintun session alone does not forward traffic. Do not interpret `SESSION_STARTED` as a working VPN connection.

Connect remains disabled until the real backend, packet data plane, helper and full Windows integration pass clean-machine and network acceptance tests.


## Receive packet lease contract

The owner can track one buffer returned by the native receive API. The lease exposes a read-only, contiguous byte view (format `B`, one byte per element) and requires release after packet processing. Non-byte buffer exporters are normalized to byte views so `len(view)` and packet byte length agree. A successful native release removes the lease from the outstanding set; a failed release retains it so the caller can retry.

Session stop refuses to call EndSession while any receive lease remains outstanding. This prevents teardown from invalidating a packet buffer still being consumed. Context-manager use guarantees a release attempt on normal exit and exception exit, but a release callback failure remains visible and retains ownership.

The future packet pump must bind the callback to `WintunReleaseReceivePacket` for the exact packet pointer. The platform-neutral `handoff_received_packet` helper copies the lease into a bounded queue without blocking and then attempts release; it does not itself call Wintun. If release fails after enqueue, its error marks `enqueued=True` so callers retry only the lease release and do not enqueue a duplicate packet. Consumers must not retain the memoryview beyond the lease lifetime. Python cannot revoke an already-copied memoryview reference, so the native adapter and packet-processing layer must enforce this lifetime rule.

## Upstream references

- Wintun API and deployment guidance: https://github.com/WireGuard/wintun
- Wintun C API declarations: https://github.com/WireGuard/wintun/blob/master/api/wintun.h
- Official binary distribution: https://www.wintun.net/
