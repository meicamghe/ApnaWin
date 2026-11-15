# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. Android APK inspection is static metadata analysis only; native Android `.so` files are not treated as Windows DLLs.

The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not available.

## Latest CI verification

Workflow [43714910902](https://github.com/meicamghe/ApnaWin/actions/runs/43714910902) passed on commit `b1012d9d7725247f2409fff6fe6cf6b7c39ac756`: 619 tests passed (one warning from a duplicate ZIP-entry fixture); Windows x64 PyInstaller folder build, packaged executable smoke test and portable artifact upload all succeeded. Artifact ID: `14161764950`.

CI validates configured tests and packaging, not live VPN connectivity.

## Windows network transaction

- Wintun is the leading Layer-3 adapter candidate, pending pinned-binary architecture/hash/signature/license verification and clean-machine testing.
- The privileged helper, packet-forwarding integration and production route/DNS adapter do not exist yet.
- `windows_network_plan.py` validates immutable route/DNS intent without OS changes.
- `windows_network_journal.py` provides a bounded versioned journal model and atomic snapshot persistence.
- `windows_network_transaction.py` provides injected-adapter orchestration, before-snapshot preconditions, reverse compare-before-restore compensation and startup reconciliation of persisted journal phases. It does not call Windows APIs.
- `windows-privileged-helper-security.md` specifies the unprivileged desktop / narrow local helper boundary and Windows API mapping.
- The journal directory still needs a restrictive Windows ACL before privileged integration; process-wide single-writer ownership is also required.

## Remote configuration

Available evidence has not established a verified APNA endpoint, authentication scheme, signature format or upstream response schema. Do not invent any of these. No credentials or endpoints are hard-coded.

## Latest engineering changes

- Connection lifecycle cleanup and validation semantics are hardened; a failed cleanup retains the active profile for retry.
- Windows route/DNS intent is validated as an immutable model.
- Journal persistence and conservative recovery orchestration are implemented behind a fakeable adapter interface.
- Connect remains disabled until a production Windows tunnel passes end-to-end route, DNS, leak, disconnect and crash-recovery acceptance tests.


## Latest engineering update

- Added a bounded FIFO packet handoff queue with packet-count, total-byte and per-packet limits; it copies packet data to immutable bytes, provides explicit backpressure/timeouts and supports graceful drain or discard on close. This remains disconnected from native Wintun.
- Hardened queue inputs to require contiguous one-dimensional buffers and finite non-negative timeout values.
- Network transaction executors in one process now share a re-entrant lock keyed by canonical journal path. Cross-process serialization still requires an OS-level mutex in the privileged helper.
