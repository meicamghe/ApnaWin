# Session handoff

## Current repository state — 2026-11-16

The current Windows x64 branch is `vpn/integrated-tun-readiness-runtime`, HEAD `76503f2d927eefbf75500c50e0282747513bf68a`. Pull request [#4](https://github.com/meicamghe/ApnaWin/pull/4) is open and mergeable.

The desktop Connect flow is wired to the fixed-path elevated Xray helper. Connect is enabled only for a validated encrypted XRAY TUN profile when the helper is installed under Program Files. The helper verifies the packaged Xray/Wintun hashes, validates the strict dual-stack TUN config, waits for the adapter, effective IPv4/IPv6 default routes and configured DNS, then requires an independent certificate-validated IPv4 TLS egress probe. Adapter/routes/DNS are monitored while connected; repeated unhealthy samples trigger Xray shutdown.

**This is local tunnel-readiness integration, not release acceptance.** It does not establish APNA-provider compatibility, IPv6 application egress, DNS/IPv4/IPv6 leak resistance under failure, or cleanup after forced termination/reboot. Xray's WFP filters are process-owned; ApnaWin has no independent persistent kill switch. The journal/plan/transaction modules remain experimental injected-adapter infrastructure and are not in the production route/DNS path.

An authorized APNA Xray configuration/catalog/authentication source is still unavailable. Do not invent endpoints, credentials or protocol details. Do not claim a working APNA connection until a real authorized profile is tested on clean Windows 10/11 systems.

## Latest CI and portable artifact

Workflow [43819919964](https://github.com/meicamghe/ApnaWin/actions/runs/43819919964) (run 358) passed all 6 jobs on HEAD `76503f2d927eefbf75500c50e0282747513bf68a`: 903 passed, 1 skipped in the full unit/integration suite; VPN readiness/egress, installer/runtime security, Ruff, Windows x64 packaging and final artifact publication all succeeded.

Published artifact: `ApnaWin-Windows-x64`, artifact ID `14204335649`, 76,806,229 bytes, SHA-256 `1b48b8b45a3faf57ef33fc9f0ae2c3ef498e26c3c1f210ff1b9f921f6ea0d513`. The ZIP contains the desktop executable, elevated helper, Xray, Wintun, runtime manifest, licenses and installer script. CI validates configured tests and packaging; it does not execute a real APNA tunnel or prove leak resistance.

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

- Normalized Wintun receive lease views to byte format (`B`) and added coverage for non-byte buffer exporters and invalid views.
- Documented the required service-owned Windows named mutex contract for cross-process serialization, including abandoned-mutex recovery and fail-closed timeout behavior. No named mutex implementation exists yet.

- Added `handoff_received_packet` to make receive-buffer copy-and-release ordering explicit: it never waits for queue capacity while holding a native lease and preserves both enqueue and release failures.

- Clarified receive handoff error semantics: a release failure after successful enqueue reports `enqueued=True`; callers retry only native release, avoiding duplicate queue insertion.

- Split non-blocking queue errors into `PacketQueueFull` for producer backpressure and `PacketQueueEmpty` for an empty consumer read.


## Connection-critical update — 2026-11-15

- Added explicit SDDL builders for the service-owned mutex and local named pipe. The client SID validator now requires a full account SID with a terminal RID; the SYSTEM SID is rejected through the distinct-identity rule.
- CI run 43721142816 passed: 756 tests, Windows x64 PyInstaller build, packaged-app smoke test and portable artifact upload. CI run 43721386311 also passed the experimental native Wintun FFI branch; that duplicate FFI was subsequently removed after the Xray-native TUN path was verified.
- A standalone Python Wintun ctypes adapter was prototyped, then identified as redundant and removed from the product path: Xray-core already owns Wintun, packet I/O, interface setup, routes, DNS and WFP for its native Windows TUN inbound. Do not maintain a second Wintun adapter.
- The critical path is now: pin and package compatible Xray/Wintun binaries; implement the Windows elevation strategy; obtain a real authorized APNA/Xray outbound configuration; run Xray's native TUN inbound with strict dual-stack routes, DNS and WFP filters; verify actual traffic, disconnect and crash recovery. Do not build a second Wintun packet engine or duplicate route/DNS stack.
- CI run 43721855278 passed: 782 tests, Windows x64 application build, packaged-app smoke test and portable artifact upload. No test or build in CI establishes a live VPN tunnel. Keep Connect disabled.


## Architecture correction — native Xray TUN

The upstream Xray-core TUN inbound has native Windows support. Its Windows implementation creates/reuses the Wintun adapter, owns packet I/O, configures interface addresses/MTU/routes/DNS, binds Xray's own outbound sockets to the physical interface, and can install WFP leak filters. Its graceful Close path flushes routes, IP addresses and DNS, closes WFP state, ends the Wintun session and closes the adapter. The standalone Python Wintun FFI experiment was removed as duplicate work.

The runner now accepts a strict TUN inbound and requires both IPv4/IPv6 default routes, one gateway prefix per family, DNS servers, `autoOutboundsInterface: "auto"`, and `autoSystemWfpBlockLeak: ["allexceptlan", "dns"]`. The additional `dns` filter is intentional: Xray's WFP implementation leaves LAN destinations open under `allexceptlan`; the explicit DNS filter also blocks DNS queries to local-LAN resolvers.

On Windows, Xray requires `wintun.dll` beside `xray.exe`. The build pipeline now pins Xray v26.11.9 and Wintun 0.14.1 archives and verifies their hashes/signature/version; the runtime manifest is not yet enforced at launch. Protected installation, elevation and startup recovery remain incomplete. Xray's dynamic WFP session is removed when the process dies, but route/address/DNS cleanup after forced termination must be verified rather than assumed.

Primary upstream references:
- https://xtls.github.io/en/config/inbounds/tun.html
- https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows.go
- https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows_wfp.go
- https://github.com/XTLS/Xray-core/blob/main/proxy/tun/handler.go


## Engine runtime package — verified

CI run 43722164563 passed the Windows runtime installation step: Xray-core v26.11.9 and Wintun 0.14.1 archives passed SHA-256 checks, PE x64 checks, Wintun Authenticode signer validation and Xray version validation. The portable artifact includes both runtime binaries, licenses and a generated runtime manifest. Artifact ID 14165260184 is 67,672,626 bytes and is not expired.


## Encrypted Xray configuration import

The profile UI now has an Xray JSON import action for XRAY profiles. Configs are structurally validated as strict full-tunnel TUN JSON and encrypted at rest using current-user Windows DPAPI with application-specific entropy. Profile rename/remove updates the encrypted config record; metadata export deliberately excludes secrets. The Connect button remains disabled because the UI still lacks the elevation supervisor, Xray config-test/start integration, real authorized APNA config source and live traffic acceptance tests. A Windows DPAPI round-trip integration test is included in CI.


## Encrypted Xray config import

The profile UI supports importing a complete Xray TUN JSON config for an XRAY profile. The config is validated and stored encrypted with current-user DPAPI; profile metadata exports omit credentials. Renames move the encrypted record, and profile deletion removes it. The UI deliberately leaves Connect disabled. The Windows elevation supervisor and end-to-end connection workflow remain outstanding.


## Windows UAC helper — implementation in progress

Added a fixed-path UAC helper design: parent-side ElevatedXrayProcess uses ShellExecuteExW(runas), ready/stop events, and a parent-process handle; the helper validates its Program Files location, decrypts the selected profile with current-user DPAPI, writes a temporary runtime config, starts the fixed Xray binary through XrayProcessRunner, and supervises it. The Windows build is being extended to package the helper with a requireAdministrator manifest and an installer that applies Program Files ACLs.

Important: the helper now requests graceful Xray shutdown through CTRL_BREAK_EVENT in a dedicated hidden console process group, with Job Object termination as fallback. A Windows native test covers signal delivery. It is not yet wired into the main window; route/DNS restoration, WFP leak tests and end-to-end Windows acceptance are still required. Keep Connect disabled.


## Desktop Xray supervisor wrapper

Added XrayTunnelSupervisor as the desktop-side lifecycle abstraction: XRAY-only, requires an encrypted profile config, blocks concurrent starts, delegates UAC launch to ElevatedXrayProcess, polls helper exit and signals the stop event on disconnect. Unit tests cover its start/poll/stop state. The main window is not wired to it yet; no Connected state is permitted until route, DNS, WFP leak and external connectivity checks pass.


## Latest verified Windows build (2026-11-15)

CI run 43724914682 completed successfully: 848 tests passed, one skipped, and the Windows build, elevated helper build, pinned Xray/Wintun runtime installation, packaged-app smoke test and artifact upload all succeeded. Artifact ApnaWin-Windows-x64: ID 14165469958, 75,925,661 bytes, not expired. Commit 6410a2cf5b0b651dd48519bcdca299f246e64143 includes the desktop-side XrayTunnelSupervisor wrapper. The latest commit adds read-only adapter/route/DNS diagnostics. Connect remains disabled; no APNA endpoint/auth format has been established, and live route/DNS/WFP/e2e acceptance is still pending.

## Integrated Windows VPN readiness work — awaiting CI

A consolidated pull request (#4) now combines the active connection workstreams: strict TUN config import and proxy-only outbound policy; fixed-path UAC helper and Xray supervisor; runtime-manifest SHA-256 verification for Xray/Wintun; adapter ownership preflight; effective IPv4/IPv6 default-route metric checks; exact DNS readiness; independent external TLS egress probe; periodic adapter/route/DNS health monitoring; graceful shutdown on startup timeout or repeated health loss. The current PR head is tracked in GitHub pull request #4. Windows CI for the integrated branch is pending/queued; do not report it as passed until the run completes.

The separate Python Wintun packet engine and route/DNS transaction path are not used: Xray native TUN owns those operations. The desktop Connect UI remains disabled until clean Windows 10/11 tests prove provider-specific traffic, DNS and IPv4/IPv6 leak behavior, WFP behavior, normal disconnect, helper/desktop crash and reboot cleanup. APNA's actual remote catalog/authentication schema and an authorized APNA Xray config remain unverified; do not fabricate them.


## Current integrated desktop connection state — 2026-11-16

- The main window now creates the production XrayTunnelEngine and ConnectionController on Windows only when the fixed elevated helper exists under Program Files. Connect is enabled only for an XRAY profile with a validated encrypted config; non-Windows and incomplete installations remain disabled.
- Connect/Disconnect run in a Qt worker thread. The helper withholds its ready event until runtime hashes, TUN adapter, effective IPv4/IPv6 default routes, configured DNS and an independent certificate-validated TLS egress probe pass. The helper watches desktop/stop events and supervises Xray in a Job Object.
- While connected, the helper rechecks adapter/routes/DNS every two seconds. This update adds periodic independent TLS egress checks every 15 seconds; three consecutive failed egress checks request graceful shutdown.
- CI run 43812584700 (run 350) passed all five parallel validation tracks and published the portable artifact. This is component/CI validation, not a live APNA provider acceptance test.
- APNA server catalog endpoint, authentication, response schema and an authorized APNA Xray config remain unverified. Do not claim APNA compatibility or fabricate endpoints. Live tests must still cover provider-specific traffic, DNS and IPv4/IPv6 leaks, WFP behavior, clean disconnect, helper/desktop crash and reboot cleanup.
