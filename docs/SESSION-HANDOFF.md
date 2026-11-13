# ApnaWin — Project Handoff

Last reviewed: 2026-11-13

This document preserves durable product decisions, current implementation boundaries and the next engineering steps. It complements `README.md`, `docs/architecture.md`, `docs/engine-contract.md` and `docs/xray-process-runner.md`.

## Product goal

Build a native Windows 10/11 desktop client inspired by the APNA TUNNEL LITE workflow. This is a Windows application, not an Android emulator and not an APK wrapper.

## Current milestone and implementation boundary

The latest repository README reports **Milestone M2 in progress**. The repository contains:

- Native PySide6 desktop application shell.
- Add/edit/select/remove connection profiles.
- Local JSON persistence for non-secret profile metadata.
- Transport-neutral profile model and tunnel-engine contract.
- Test-only mock engine that performs no network operations.
- Xray process runner with config validation and process supervision.
- Windows GitHub Actions tests and a PyInstaller portable-folder build workflow.

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

## Milestones

- M0 — repository skeleton, coding conventions and architecture record: complete.
- M1 — inspect APK metadata/resources and document observable features/protocols: preliminary; reproducible verification remains.
- M2 — profile schema, persistence, mock engine contract and desktop profile workflow: in progress.
- M2a — safe Xray process runner and automated process-supervision tests: implemented; verify latest Windows CI.
- M3 — integrate one Windows engine end-to-end using an authorized test server and documented configuration.
- M4 — elevation/service and TUN adapter lifecycle with rollback and cleanup.
- M5 — package, sign where possible, test on clean Windows 10/11 VMs and publish releases.

## Immediate next steps

1. Check the newest GitHub Actions run for workflow **Windows tests** on every status-check request. Report status, run number, branch, commit and timestamp; do not reuse stale status.
2. If CI is red, inspect the failing job and logs, reproduce the failure, fix the root cause and rerun tests. If green, continue the next M2 task rather than repeatedly rechecking without a reason.
3. Review profile validation and persistence tests, including schema-version handling and rejection of unsupported transports/invalid endpoints.
4. Complete UI workflow tests for add/edit/select/remove and verify no secrets are persisted.
5. Test the Xray process runner on Windows 10/11 with fake-process tests and then a separately installed, pinned binary plus an authorized test config.
6. Verify an application-level request through the authorized test endpoint; a SOCKS greeting alone is insufficient.
7. Design the production tunnel adapter only after configuration/protocol and engine licensing are established.
8. Keep Connect disabled until the production adapter passes end-to-end tests and reliable cleanup/rollback.

## CI reporting rule

For a status report, identify the latest run belonging specifically to the workflow named **Windows tests**. Return its state (queued, in progress, success, failure or cancelled), run number, branch, commit and execution time. If there are multiple recent runs, use the newest by creation time and say which one was selected. A green earlier run does not override a newer red run.

## Session start checklist

1. Read this handoff and the architecture, engine-contract and Xray runner docs.
2. Inspect current branch, latest commit and working tree when a local checkout is available.
3. Check latest Windows tests run and inspect failures before editing.
4. Run existing tests before and after code changes.
5. Make one focused change at a time and update docs when behavior or boundaries change.
6. Never commit secrets, server configs, credentials or customer/private endpoints.

## Historical caveat

Prior chats may include individual commands, build outputs, CI failures and user test observations that are not all represented here. This handoff records the durable information currently recoverable; it is not a complete transcript archive. Reconcile any new user observation with the implementation and tests before treating it as a product guarantee.
