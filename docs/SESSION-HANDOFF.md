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


## Reverse-engineering handoff — 2026-11-28 (current)

### Active research branch

- Branch: `research/parallel-re-audit-20261128`
- Based on `main`; check the GitHub compare view for the live ahead/behind count.
- Research-only. Do not merge wholesale from `re/apk-native-extract`; only selectively ported DEX files were added.
- No new Windows build, CI dispatch, SSH work, or PR merge.

### Uploaded `libxray.so`

- SHA-256: `e796e24eece84ab28ab9e20710a8581fbcb1044c6720db5f9c79fecc839f68b5`
- 32,740,552 bytes; Android ARM64; Go 1.26.2; `-buildmode=exe`; ELF ET_DYN with Android interpreter and entry point.
- 39,856 Go function names recovered offline from `.gopclntab`.
- CLI entry points recovered: `main.main`, `main.executeRun`, `main.getConfigFilePath`, `main.startXray`, `main.readConfDir`, `main/confloader.LoadConfig`.
- CLI help includes `run [-c config.json] [-confdir dir]`; config may come from flags, environment or STDIN.
- Xray code includes VLESS, VMess, Trojan, Shadowsocks, Hysteria, WireGuard and Android TUN paths. Compiled code is not proof of UI activation or live connectivity.
- No JNI exports were found in the dynamic symbol table. DEX-to-process launch/config handoff and Android VPNService TUN-FD transfer remain unproven.
- The uploaded file is not yet hash-matched to a specific member path inside `base.apk` or a split. Do not claim exact APK provenance until matched.

### DEX inspection implementation

- Ported `src/apnawin/services/apk_dex.py` with bounded process/native-loader callsite scanning.
- Added `src/apnawin/services/apk_dex_set.py` and `tools/inspect_apk_dex_set.py` to inspect a supplied base/split APK set, aggregate evidence, and join manifest VPN services to the APK where the class is defined.
- Tests added/ported: `tests/test_apk_dex.py`, `tests/test_apk_dex_set.py`. They have not been executed.
- The scanner remains bounded to 64 selected classes per APK. It is not an exhaustive class-name-independent DEX index.
- Example on a machine with Android SDK tools installed:
  `python tools/inspect_apk_dex_set.py APNA-APKs/base.apk APNA-APKs/split_config.arm64_v8a.apk APNA-APKs/split_config.de.apk APNA-APKs/split_config.en.apk APNA-APKs/split_config.fa.apk APNA-APKs/split_config.xxhdpi.apk`

### Go pclntab parser

- `tools/recover_go_pclntab.py` was corrected for Go functab offsets relative to `pcln` and PIE images whose `textStart=0`.
- The parser recovered all 39,856 function names from the uploaded Xray binary using an independent offline extraction pass.
- Synthetic regression tests were expanded but not run. No CI was dispatched.
- Do not assume parser compatibility with `libudpqtwo.so` until tested against that exact binary.

### Remaining priority order

1. Run the new Go parser and DEX split-set tests locally (no CI dispatch unless explicitly requested).
2. Obtain `base.apk` and all relevant split APKs in a locally accessible form, then run the DEX split-set inspector and trace `libxray.so` process/config/TUN handoff.
3. Match uploaded `libxray.so` SHA-256 to its exact APK member path/ABI, or record that it is an external extracted artifact.
4. Obtain direct copies of `libudpqtwo.so` and `libsalamander.so`; analyze each independently.
5. Implement the class-name-independent DEX callsite index; current 64-class candidate scan is only triage.

Keep static evidence, source integration, and runtime proof as separate statuses. Do not claim the VPN is operational from symbol recovery alone.
