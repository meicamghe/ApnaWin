# ApnaWin — Project Handoff

Last reviewed: 2026-11-14

This document preserves durable product decisions, current implementation boundaries and the next engineering steps. It complements `README.md`, `docs/architecture.md`, `docs/engine-contract.md`, `docs/xray-process-runner.md` and `docs/remote-configuration.md`.

## Product goal

Build a native Windows 10/11 desktop client inspired by the APNA TUNNEL LITE workflow. This is a Windows application, not an Android emulator and not an APK wrapper.

## Current milestone and implementation boundary

The repository contains:

- Native PySide6 desktop application shell.
- Add/edit/select/remove connection profiles; profile-derived UI text is rendered safely as plain text or HTML-escaped for auto-detecting dialogs.
- Local JSON persistence for non-secret profile metadata, with a 1 MiB document-size bound on reads and writes.
- Transport-neutral profile model and tunnel-engine contract.
- Test-only mock engine that performs no network operations.
- Xray process runner with bounded 16 MiB config reads, strict JSON validation (duplicate keys and non-finite constants rejected), discarded validation output, SOCKS diagnostics and process supervision.
- Windows Job Object process-tree containment integrated into the Xray runner.
- Windows GitHub Actions tests and a PyInstaller portable-folder build workflow.

The latest verified Windows CI run is [#130](https://github.com/meicamghe/ApnaWin/actions/runs/43564101918), for commit `99d79795f044c01e4dfe9fa3003e6c5ad744e4f8`. Both the `test` job and `build-windows` job passed, including the PyInstaller build, packaged GUI smoke test and portable-folder artifact upload. The run completed at 2026-11-14 06:01:41 UTC.

**The Connect button remains intentionally disabled.** The current Xray runner is not a complete tunnel engine, and the published CI artifact is not a signed installer or a working VPN client. Do not describe the app as connected or APNA TUNNEL-compatible without end-to-end proof.

The Xray runner's exact limitations are documented in `docs/xray-process-runner.md`: it does not synthesize configuration from host/port alone, configure TUN, change routes/DNS, verify APNA's private protocol, or prove remote traffic forwarding just because a process/listener starts.

## Binding architecture and security decisions

- Keep UI, application orchestration, domain model, engine adapters, Windows platform operations and diagnostics separated.
- Keep privileged networking operations out of the UI process.
- A process start or open local SOCKS port is not equivalent to a working tunnel.
- Do not infer protocol, UUID, keys, TLS/Reality flow, transport or credentials from only a server host and port.
- Do not claim compatibility with APNA TUNNEL's servers until a documented, authorized configuration path and end-to-end test exist.
- Do not embed credentials, private keys, server lists or vendor endpoints in source control.
- Pass process arguments without shell interpolation; redact secrets from logs.
- A production engine must clean up child processes and restore routes, DNS, firewall and TUN resources it changes.
- Verify engine license, redistribution terms, Windows architecture and binary hashes before bundling third-party engines.
- Keep failed Windows process/job handles owned and retryable; never silently fall back to an uncontained Windows child process.

## Milestones

- M0 — repository skeleton, coding conventions and architecture record: complete.
- M1 — inspect APK metadata/resources and document observable features/protocols: preliminary; reproducible verification remains.
- M2 — profile schema, persistence, mock engine contract and desktop profile workflow: implemented baseline; broader usability and integration tests remain.
- M2a — safe Xray process runner and automated process-supervision tests: implemented.
- M2b — Windows Job Object process-tree containment and Xray runner integration: implemented and verified in Windows CI, including child/grandchild containment, creation-time root membership, final-handle-close cleanup and targeted Win32 failure/handle-retention tests.
- M2c — remote configuration discovery plan and provider-neutral security architecture: documented; actual provider integration is blocked on reproducible APK/runtime evidence.
- M3 — integrate one Windows engine end-to-end using an authorized test server and documented configuration.
- M4 — implement elevation/service and TUN adapter lifecycle with rollback and cleanup.
- M5 — package, sign where possible, test on clean Windows 10/11 VMs and publish releases.

## Remote configuration discovery

The Android app may update its server catalog and connection parameters remotely. This must be investigated as a first-class product capability, not replaced by a static Windows server list. The behavior is not yet verified against a reproducible APK/runtime trace. See `docs/remote-configuration.md` for the evidence plan, data-class separation, secure provider-neutral architecture and acceptance criteria. Do not guess API endpoints or implement a speculative client.

## Immediate next steps

1. On every status-check request, inspect the newest GitHub Actions run for workflow **Windows tests and build**. Report status, run number, branch, commit and timestamp; do not reuse stale status.
2. If CI is red, inspect the failing job and logs, reproduce the failure, fix the root cause and rerun tests. If green, continue the next focused task rather than repeatedly rechecking without a reason.
3. Obtain and analyze a reproducible Android APK and authorized runtime observations for server/config refresh. Record verified endpoint, schema, authentication, signing and update-policy evidence before implementing a provider. See `docs/remote-configuration.md`.
4. Continue strict domain validation for profile names, transport values, endpoint hosts and ports, including Unicode control characters; preserve valid schema-v1 profile compatibility. Profile-derived UI text must remain plain-text or be escaped before entering Qt auto-detecting message dialogs.
5. Verify strict JSON persistence: unique same-directory atomic temp files, duplicate JSON key and duplicate profile rejection, fsync/replace failure handling, bounded reads/writes and compatibility with existing schema-v1 files. See `docs/profile-storage.md`.
6. Maintain UI workflow tests for add/edit/select/remove, duplicate handling, removal cancellation, persistence failures and metadata-only storage.
7. Keep Xray config parsing strict and bounded: read at most 16 MiB plus one detection byte, reject duplicate JSON keys and non-finite constants before process execution, and cover nested duplicate keys, malformed roots and oversized files in tests.
8. Test the Xray process runner on Windows 10/11 with fake-process tests and then a separately installed, pinned binary plus an authorized test config.
9. Verify an application-level request through the authorized test endpoint; a SOCKS greeting alone is insufficient.
10. Design the production tunnel adapter only after configuration/protocol and engine licensing are established.
11. Keep Connect disabled until the production adapter passes end-to-end tests and reliable cleanup/rollback.

## CI reporting rule

For a status report, identify the latest run belonging specifically to the workflow named **Windows tests and build**. Return its state (queued, in progress, success, failure or cancelled), run number, branch, commit and execution time. If there are multiple recent runs, use the newest by creation time and say which one was selected. A green earlier run does not override a newer red run.

The workflow uses per-ref concurrency cancellation so superseded commits do not leave redundant Windows builds queued behind one another.

## Session start checklist

1. Read this handoff and the architecture, engine-contract and Xray runner docs.
2. Inspect current branch, latest commit and working tree when a local checkout is available.
3. Check latest Windows tests run and inspect failures before editing.
4. Run existing tests before and after code changes.
5. Make one focused change at a time and update docs when behavior or boundaries change.
6. Never commit secrets, server configs, credentials or customer/private endpoints.

## Historical caveat

Prior chats may include individual commands, build outputs, CI failures and user test observations that are not all represented here. This handoff records the durable information currently recoverable; it is not a complete transcript archive. Reconcile any new user observation with the implementation and tests before treating them as a product guarantee.


## Profile import/export milestone

The desktop UI now supports exporting all loaded profile metadata to a
user-selected JSON file and importing validated profiles as a batch. Imports
append without overwriting existing entries and fail atomically on any
case-insensitive name collision. The existing bounded JSON loader/writer is
reused, so import/export does not introduce a second parsing or serialization
path. Credentials and private keys remain outside the profile format.


## Import error handling follow-up

Import failures now present the underlying validation or I/O detail with actual
line breaks rather than literal backslash-n sequences. Regression coverage
verifies malformed imports leave both the in-memory profile list and existing
destination file untouched, and cancelling the file picker is a no-op.


## Normalized remote catalog foundation

A provider-neutral internal catalog model/parser now exists at
`src/apnawin/domain/remote_catalog.py`. It validates bounded display-only
server metadata, strict JSON, unique identifiers and timezone-aware freshness.
It intentionally excludes connection endpoints and secrets and is not claimed
to match APNA's unknown upstream API. No HTTP client, guessed endpoint,
subscription/auth flow, or automatic refresh is enabled. See
`docs/remote-configuration.md` for the boundary and next evidence gate.



## Remote catalog parser depth hardening

The normalized catalog parser now rejects JSON container nesting beyond 32
levels before invoking the recursive decoder. The scanner correctly ignores
braces/brackets inside quoted strings and preserves JSON escape handling.
Regression tests cover both excessive nesting and bracket-like text inside
ordinary string values. This is parser hardening only; it does not introduce
an upstream API client or alter the verified integration boundary.
