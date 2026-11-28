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

## Current handoff — 2026-11-26

- APK reverse engineering remains the active priority. The `libudpqtwo.so` candidate
  addresses and GoReSym v3.4.1 parser findings are recorded in
  [libudpqtwo-stomped-pclntab.md](reverse-engineering/libudpqtwo-stomped-pclntab.md).
- The suspected pclntab is at VA `0xc1a200`; the likely moduledata candidate
  is at `0x10ee3a0`. The moduledata ftab pointer remains unreadable. The
  header-derived functab hypothesis is still unvalidated against a fresh
  extracted binary artifact.
- PR [#8](https://github.com/meicamghe/ApnaWin/pull/8) contains the manual APK
  native-library extraction workflow, its corrected Go pclntab header reader,
  the lazy diagnostics fix in `elevated_xray.py`, and a CI guard that keeps
  Windows packaging opt-in while reverse engineering is in progress.
- CI run [45794271848](https://github.com/meicamghe/ApnaWin/actions/runs/45794271848)
  passed 852 tests with 1 skipped and 1 warning. The Windows packaging job was
  skipped by the new gate. An earlier run before that gate completed both
  tests and Windows packaging successfully; do not treat that as authorization
  for further Windows builds.
- The APK extraction workflow is manual-only and has not yet produced an
  artifact. Do not claim the native library has been freshly re-extracted or
  that GoReSym symbol recovery has succeeded.
- Keep the PR open; do not merge without explicit user approval. Do not start
  another Windows packaging build until APK reverse engineering is complete.
- SSH remains on hold. Continue with APK/native reverse engineering and
  non-SSH protocol support, without guessing APNA endpoints, credentials or
  server-side configuration formats.

## Parallel engineering update — 2026-11-26

- Added `src/apnawin/services/proxy_share_link.py`: strict Xray outbound parsing for VLESS, VMess, Trojan and Shadowsocks individual links. It supports RAW/TCP, WebSocket and gRPC in the tested subset, TLS/REALITY where applicable, SIP002 and legacy Shadowsocks forms, and rejects unknown URI extensions rather than silently dropping them.
- Added bounded newline-separated multi-profile parsing: UTF-8 only, 1 MiB document limit, 500 profile limit, 16 KiB per link, blank/comment lines ignored, and all-or-nothing batch failure with line numbers. No subscription URL fetching or provider-specific Base64/catalog decoding is implemented.
- Added tests for outbound schema mapping, TLS/REALITY, WebSocket/gRPC, four protocols, secret-safe repr, malformed/unknown parameters, host validation, IPv6, batch limits and legacy Shadowsocks Base64 paths.
- CI run [45795956357](https://github.com/meicamghe/ApnaWin/actions/runs/45795956357) passed 888 tests, 1 skipped, 1 warning. Windows packaging was skipped by the reverse-engineering gate.
- Parser output is not wired into the UI or `XrayConfigStore`; do not treat a parsed link as a stored/working profile. The caller must persist credential-bearing config through the existing current-user DPAPI store. Connect remains disabled.
- Xray schema references and current parser limits are recorded in [xray-share-link-import.md](xray-share-link-import.md).
- APK extraction remains manual-only and has not produced a fresh artifact. The GoReSym `moduledata` fallback is still a guarded design proposal, not implemented or validated against a fresh extraction.
- PR [#8](https://github.com/meicamghe/ApnaWin/pull/8) remains open and unmerged. Do not merge without explicit approval; do not start Windows packaging until APK reverse engineering is complete.
- SSH remains on hold. Continue APK/native reverse engineering and non-SSH protocol implementation; do not infer APNA-specific endpoints, credentials or subscription formats.


### Share-link parser hardening — 2026-11-26

- Reject malformed percent escapes and invalid UTF-8 in percent-encoded components.
- Apply strict decoding to URI credentials and profile labels; query decoding uses strict UTF-8 handling.
- VMess textual JSON fields are validated as strings instead of being coerced from arrays, objects or booleans.
- Regression tests cover malformed escapes, invalid UTF-8 and non-string VMess transport fields.
- Commits: `5e286b47774027650f7a5276f182f52cbfee201c`, `5b354cbd30c80197cecd5c37de86a81808ed0283`, `a507605f383fe7f08c61c7234c77d53b0bc38993`, `db00e63ecf7b7db915ef113eba56b84ee55cbf1b`.
- Windows tests workflow [45797565757](https://github.com/meicamghe/ApnaWin/actions/runs/45797565757) was pending on the latest PR head at the time of this update; no result is claimed. Windows packaging remains gated off.


## Fresh PR validation — 2026-11-26

- GitHub Actions run [45797619263](https://github.com/meicamghe/ApnaWin/actions/runs/45797619263) completed successfully for the PR #8 merge ref containing head commit `5510736046e39383c36721e2108938ebcad77479`.
- The Windows test job installed dependencies and executed the complete pytest suite: **900 passed, 1 skipped, 1 warning**. The warning is the intentional duplicate ZIP-entry fixture in `tests/test_apk_inventory.py`.
- The `build-windows` job was **skipped** by the reverse-engineering gate; no Windows package was built.
- This validates the latest parser hardening on the tested PR merge ref. The APK extraction workflow remains manual-only and still has no fresh artifact; GoReSym recovery remains unverified.


### VLESS parser compatibility hardening — 2026-11-26

- Checked the current Project X VLESS outbound and transport compatibility references.
- Custom VLESS identifiers must be fewer than 30 UTF-8 bytes unless they are a canonical UUID.
- VLESS Vision flow accepts only `xtls-rprx-vision` and `xtls-rprx-vision-udp443`, and only with TCP/RAW plus TLS or REALITY in the parser's supported subset. Unsupported flow names, security-less Vision and Vision over WebSocket/gRPC are rejected.
- Added regression coverage for custom ID bounds, both Vision flow variants, TLS and REALITY combinations, and invalid flow/transport combinations.
- Commits: `d46948de0beac1e24cb4d27dc80feba3cd919273`, `d1efb084820bc8adfbb46504dab67d5dbd2baec3`, `6408a07b838f0d4bd1d378bd1adbcccd0db433ec`.
- Previous full-suite run `45797619263` passed 900 tests on the earlier head `5510736`; these latest parser changes still require a fresh CI run. Windows packaging remains gated off.


### VLESS hardening CI result — 2026-11-26

- GitHub Actions run [45798144029](https://github.com/meicamghe/ApnaWin/actions/runs/45798144029) completed successfully on PR #8 head `6db562a7d0363551868c5053abc4f7358ae2c434`.
- Full Windows-hosted pytest suite: **907 passed, 1 skipped, 1 warning**. The `build-windows` job was skipped by the reverse-engineering gate.
- This run validates the VLESS custom-ID bounds and Vision-flow compatibility changes. It does not validate live proxy connectivity or UI integration.
- APK extraction remains manual-only with no fresh artifact; GoReSym symbol recovery remains unverified.


### VLESS identifier boundary CI correction — 2026-11-26

- The first run on the strict 30-byte boundary commit exposed only an assertion-message mismatch: implementation correctly rejected a 30-byte custom ID, while the test expected the newer wording. No parser behavior failure was reported.
- Corrected the validation message in commit `6a0300311be1cefda7c11f2ff13ef9c052e1d8e3`.
- GitHub Actions run [45799031394](https://github.com/meicamghe/ApnaWin/actions/runs/45799031394) passed **908 tests, 1 skipped, 1 warning** on that commit. The `build-windows` job remained skipped by design.
- Added follow-up coverage for 29-byte ASCII and 28-byte multibyte identifiers, rejection at 30 UTF-8 bytes, and uppercase canonical UUID acceptance. These tests are pending a fresh CI run.
- Clarification: non-UUID custom VLESS IDs must be **fewer than 30 UTF-8 bytes**; canonical UUIDs are accepted independently of that custom-ID bound.


### VLESS byte-boundary regression suite — 2026-11-26

- The corrected strict-limit implementation passed GitHub Actions run [45799031394](https://github.com/meicamghe/ApnaWin/actions/runs/45799031394): **908 passed, 1 skipped, 1 warning**.
- Added exact UTF-8 boundary cases: 29 ASCII bytes and 28 multibyte bytes are accepted; 30 ASCII bytes and 30 multibyte bytes are rejected. Uppercase canonical UUID acceptance is also covered.
- GitHub Actions run [45799245783](https://github.com/meicamghe/ApnaWin/actions/runs/45799245783) passed **912 tests, 1 skipped, 1 warning** on PR merge ref containing head `9d412d2e5438cb948c83301fe0dc4f3e86d65bfb`. Windows packaging remained skipped by the reverse-engineering gate.
- The APK extraction workflow now inventories SHA-256 hashes for each APK split and every embedded ABI `.so` entry in `apk-native-inventory.txt`, without executing native code. This workflow/documentation update is pending its own CI validation and a manual extraction run.


### Latest PR validation after APK inventory workflow update — 2026-11-26

- GitHub Actions run [45799645047](https://github.com/meicamghe/ApnaWin/actions/runs/45799645047) passed **912 tests, 1 skipped, 1 warning** on PR merge ref containing head `f25474c7cc492ab889e9880cb8b9cdb20e3ad581`.
- The `build-windows` job was skipped by the reverse-engineering gate.
- The manual APK extraction workflow now emits `apk-native-inventory.txt` with APK archive hashes and hashes of every embedded ABI shared library. The workflow code was inspected after the edit, but it has not been manually dispatched; artifact generation and the ELF report remain unverified.
- No new native-library artifact exists and no Go symbol-recovery success is claimed.


### VMess import validation — 2026-11-26

- The share-link parser now treats VMess JSON version `2` as the supported format. A missing version defaults to `2` for compatibility; explicit unsupported or empty versions fail closed.
- Added regression coverage for absent, valid-default and unsupported VMess versions.
- Implementation, tests and protocol documentation are committed on PR #8. Fresh CI validation is pending; no Windows package was built or requested.
- The latest completed pre-change PR validation is [run 45799895731](https://github.com/meicamghe/ApnaWin/actions/runs/45799895731): **912 passed, 1 skipped, 1 warning** on head `c3c012e481a9c9231509f134ab316274350622bd`. Windows packaging was skipped by the reverse-engineering gate.


### Hysteria2 share-link support — 2026-11-26

- Added `hysteria2://` and `hy2://` import into Xray's Hysteria v2 outbound schema.
- Supports optional auth, default port 443, IPv4/IPv6, SNI, TLS ALPN h3 and Salamander UDP obfuscation.
- TLS verification remains enabled; insecure mode and unsupported options fail closed. Realm URIs, port hopping, ECH and certificate pinning remain unsupported.
- Added tests for the protocol mapping, alias, IPv6, defaults, Salamander, hidden credentials and rejected options. Auth is emitted in Xray `hysteriaSettings`, not the outbound address settings.
- See `docs/xray-share-link-import.md` for exact mapping and upstream references. Fresh CI validation is pending.


### Hysteria2 schema verification — 2026-11-26

- Verified the Xray Hysteria transport object against the current Project X transport documentation: the correct transport selector is `streamSettings.method: "hysteria"`, with version/auth under `hysteriaSettings` and endpoint address/port under outbound `settings`.
- A temporary `network` experiment was reverted after checking the authoritative schema. The parser and regression test retain/assert the documented `method` key. This does not enable connection runtime or alter the disabled Connect state.
- CI passed for the previous head `0572e4d12fe08b855f13c0aab1704df2358c37fe`; the correction is newer and requires its own CI result.


### ELF metadata hardening — 2026-11-26

- Hardened the bounded APK ELF inspector: a file with no section-header table may not claim a nonzero section count or a section-name string-table index.
- Added ELF32 and ELF64 regression cases for both orphaned metadata fields.
- This is static structural validation only; it does not execute or load native code and does not claim Go symbol recovery.
- The parser and tests are committed; the latest CI result for this addition is pending.

### ELF execution-model regression fixture correction — 2026-11-28

- The first full-suite run on the ELF execution-model metadata addition completed with **937 passed, 2 failed, 1 skipped**. Both failures were exact-dictionary expectations in legacy JNI-export fixtures; the implementation returned the three newly documented fields (entry_point, interpreter_present, execution_model) as designed.
- Updated the ELF32 and ELF64 expected dictionaries to include the zero-entry/no-interpreter shared_object_candidate classification.
- Test-only correction committed as 8307b504b5c4752ce66426a82e194563e8220309; a fresh PR validation is pending.
- The run did not reach Windows packaging; build-windows remained skipped by the reverse-engineering gate. No APK extraction artifact or Go symbol recovery is claimed.

### ELF execution-model correction verified — 2026-11-28

- GitHub Actions run [46108752727](https://github.com/meicamghe/ApnaWin/actions/runs/46108752727) passed on PR merge ref containing head 8307b504b5c4752ce66426a82e194563e8220309: **939 passed, 1 skipped, 1 warning**.
- This confirms the ELF32/ELF64 JNI fixture expectations now include the new execution-model fields. The Windows packaging job was skipped by design; this was a test-suite run, not a Windows build.

### All-split native ELF inventory expansion — 2026-11-28

- Added `tools/inventory_apk_native.py`: bounded in-memory SHA-256 and ELF metadata inspection for every `lib/<abi>/lib*.so` member across supplied APK splits. It records malformed/non-ELF members explicitly and never writes, loads or executes native code.
- Added regression tests for multi-split enumeration, hash correctness, PIE/PT_INTERP classification, malformed ELF reporting, duplicate ZIP entries, aggregate-size bounds and empty input.
- Wired `native-elf-inventory.json` into the manual APK extraction artifact and documented its fields and safety limits.
- Validation is pending on the current branch head; no new APK artifact or runtime protocol acceptance is claimed.

### Split-wide native ELF inventory validation — 2026-11-28

- GitHub Actions run [46109322697](https://github.com/meicamghe/ApnaWin/actions/runs/46109322697) passed on code head `8436a803910aef40d16ca9c6c74bf299785cc6c2`: **943 passed, 1 skipped, 2 warnings**.
- The new `test_inventory_apk_native.py` cases passed, including split aggregation, SHA-256 verification, PIE/PT_INTERP classification, malformed ELF handling, duplicate-entry rejection and aggregate-size limits.
- `build-windows` was skipped by the existing reverse-engineering gate. This CI run did not execute the manual APK extraction workflow and produced no native-analysis artifact.


## Static DEX linkage analysis — 2026-11-28

- Added a bounded, read-only DEX smali inspection for up to 64 network/service candidate classes.
- It records method-scoped Runtime.exec, ProcessBuilder, System.load, System.loadLibrary, and secondary-Dex loader callsites, plus native lib*.so literals from the same method.
- Raw smali, method names, descriptors and arbitrary string literals are discarded. The output marks scan truncation and does not claim runtime invocation or successful loading.
- The implementation and regression tests are committed; CI run 46110097915 is validating this change.
- This analysis is offline and does not require an Android device. Protected LIAPP DEX remains out of scope for bypass; any hidden launch owner must remain explicitly unresolved unless readable evidence establishes it.

## Latest completed CI — 2026-11-28

- GitHub Actions run [46109432150](https://github.com/meicamghe/ApnaWin/actions/runs/46109432150) passed on head 723d2089073a8abc9836db9a889e6f6c1b67ead3: **943 passed, 1 skipped, 1 warning**.
- The remaining pytest warning is from the duplicate-ZIP-entry fixture in tests/test_apk_inventory.py. The build-windows job was skipped by the reverse-engineering gate.
- Run 46109432150 did not dispatch the manual APK extraction workflow and produced no fresh APK/ELF artifact.


## Method-level DEX scan CI — 2026-11-28

- GitHub Actions run [46110162159](https://github.com/meicamghe/ApnaWin/actions/runs/46110162159) passed on head 0a1889a320e0d17706155e5acebee1d1b7314e64: **945 passed, 1 skipped, 1 warning**.
- New DEX linkage parser regression tests passed, including method-scoped Runtime.exec, System.loadLibrary, secondary-Dex loader detection, safe .so literal extraction, and exclusion of arbitrary strings.
- Windows packaging remained skipped by the reverse-engineering gate.
- No fresh APK extraction artifact was generated; the native inventory workflow remains manual-only.


## All-split native binary extraction — 2026-11-28

- Added tools/extract_apk_native.py to extract every inventoried lib/<abi>/lib*.so from the committed APK set into a deterministic APK/ABI/library directory tree.
- Each extracted member is streamed with 64 MiB per-file and 256 MiB aggregate limits; SHA-256 and byte size are verified against the prior in-memory inventory before it is recorded.
- The artifact manifest records relative path, hash, size, ELF parse error (if any), and executed=false. No native member is loaded or executed.
- Wired the all-library extraction into the manual APK native-analysis workflow. This makes every ABI/split binary available for subsequent static strings, imports, relocations, Go metadata and protocol-family analysis after the manual workflow is run.
- CI run [46110374404](https://github.com/meicamghe/ApnaWin/actions/runs/46110374404) passed on head 41779d545a70ca5f9885b03dc546e64e27fcceea: **951 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.
- The workflow remains manual-only and has not yet generated a fresh artifact; no new APNA binary findings are claimed from this tool change.


## Cross-split DEX and manifest correlation — 2026-11-28

- Added apk_dex_set.py and inspect_apk_dex_set.py to inspect every APK in a base/split package set with the local Android SDK apkanalyzer.
- The analyzer verifies consistent package names, unions manifest-declared VPN services, scans each split's readable DEX, and reports the APK(s) that actually define each service class.
- Method-level process/native-loader evidence is retained per APK. Aggregate class counts are explicitly totals across splits, not deduplicated unique-class counts.
- This is offline static analysis only; it does not install or execute the APK and does not require an Android device.
- Added cross-split regression tests, including the case where the manifest service class is absent from base.apk but defined in a feature split.
- GitHub Actions run [46110514246](https://github.com/meicamghe/ApnaWin/actions/runs/46110514246) passed on head 36a671dded230f2b960ba987c3c1777ea0afc14c: **955 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.
- Added /analysis/ to .gitignore so local extraction reports and native binaries are not accidentally committed.
- Rechecked GoReSym v3.4.1 and current upstream master: the moduledata scanner's ignored-first-match behavior remains unfixed upstream. Exact failure mode and regression cases are documented in libudpqtwo-stomped-pclntab.md.


## All-split native protocol fingerprint analyzer — 2026-11-28

- Added tools/analyze_native_fingerprints.py. It verifies every extracted native file against native-libs/manifest.json (relative path, size and SHA-256) before scanning.
- It emits occurrence counts only for allowlisted protocol-family, Go-runtime and known-engine markers across every ABI and APK split. Arbitrary strings, credentials, raw bytes and code are never included.
- Added tests for protocol/runtime marker counts, secret-string exclusion, hash tampering, symlinked parent paths and unsafe manifest paths.
- Wired native-fingerprints.json into the manual all-split extraction artifact and documented interpretation limits: marker hits are leads, not proof of active protocol use.
- This extends offline static analysis only; it does not load or execute any native library and does not require an Android device.


## Exact DEX-to-native name correlation — 2026-11-28

- Tightened method-level DEX inspection so System.loadLibrary arguments are captured only when the exact string register is passed to that call; unrelated string constants in the same method are not promoted to library names.
- The analyzer separately retains exact lib*.so basenames (including basenames extracted from absolute paths) and System.loadLibrary name arguments.
- Cross-split aggregation now emits native_library_literal_references and system_load_library_references with APK split, class, method ordinal and invocation kind. The conventional lib{name}.so mapping is explicitly labeled as inferred from Android API naming convention.
- Added regression tests for exact register correlation, arbitrary-string exclusion, and cross-split DEX/native reference aggregation.


## GoReSym moduledata patch prepared — 2026-11-28

- Added tools/patches/GoReSym-v3.4.1-moduledata-scan.patch against the exact v3.4.1 moduledata_scan implementation.
- The patch iterates successive occurrences within the current section, skips ignored VAs without jumping to the next section, preserves section-size bounds and includes five focused Go regression cases (including rejection of a pointer signature that crosses the current section boundary).
- Documented clean-checkout application and validation commands. This is a prepared upstream-tool patch only; it has not been applied to GoReSym or run against the APNA binary.
- It fixes the independently confirmed ignored-first-match bug, not the separate unreadable ftab pointer in the suspected APNA moduledata candidate.
- DEX linkage reports now include exact string-register correlation for System.loadLibrary and accurate invocation-site counts (not merely methods containing a call).


## Dynamic secondary-DEX loader evidence — 2026-11-28

- The bounded DEX smali scan now records the exact loader type (`DexClassLoader`, `PathClassLoader`, or `InMemoryDexClassLoader`) and correlates direct String-register path arguments for file-backed loaders.
- Colon-separated direct-literal archive paths retain only allowlisted `.dex`, `.apk`, and `.jar` extensions; the path itself is never emitted. In-memory loaders are explicitly identified as ByteBuffer constructors with no file-path argument.
- Computed paths, aliases, reflection, invoke-range arguments and protected DEX remain unresolved.
- Split aggregation preserves APK/class/method references for these loader callsites. A loader constructor reference is not proof that the target archive was decrypted, accepted, loaded or executed.
- The regression suite includes wrong-register and non-literal boundaries; no fresh APK extraction artifact has been produced by the manual workflow.


## Latest validation of parallel static-analysis changes — 2026-11-28

- GitHub Actions run [46111339042](https://github.com/meicamghe/ApnaWin/actions/runs/46111339042) passed on head 20fa3c581e89717728b82b8766e64d14b35255e3: **961 passed, 1 skipped, 1 warning**.
- The new checks cover verified allowlisted native fingerprint scanning, exact System.loadLibrary register correlation, accurate per-invocation DEX counts, cross-split DEX/native linkage aggregation and the prepared GoReSym patch artifact's repository-side integrity.
- The build-windows job was skipped by the reverse-engineering gate.
- PR #8 remains open and unmerged. The manual APK extraction workflow has not been dispatched, so there is still no fresh native inventory artifact or new binary-level discovery.

## APK reverse-engineering handoff — 2026-11-28

- Active branch: `re/apk-native-extract`; PR #8 remains open and must not be
  merged without explicit user approval.
- Latest DEX linkage changes passed CI run
  [46117207738](https://github.com/meicamghe/ApnaWin/actions/runs/46117207738):
  **964 passed, 1 skipped, 1 warning**. The warning is the intentional
  duplicate-ZIP-entry fixture. The Windows packaging job was skipped by its
  explicit gate; no product build was performed.
- DEX callsite analysis now correlates exact argument registers for
  `System.loadLibrary`, `System.load`, `Runtime.exec(String/String[])`,
  and `ProcessBuilder(String[])`. Fully enumerated `filled-new-array`
  string arrays followed by `move-result-object` are supported. The
  cross-split report retains APK, class, method ordinal, basename and evidence
  basis. See [apk-analysis.md](apk-analysis.md) for the exact scope and
  unsupported data-flow cases.
- This remains bounded static analysis. `filled-new-array/range`,
  `new-array`/`aput-object`, general register aliases/moves, reflection,
  interprocedural values and protected/obfuscated DEX remain unresolved.
- The manual native extraction workflow now inventories every native member
  and computes allowlisted native fingerprints, including StarUDP/QUIC,
  Go-runtime, config-key and transport-dependency markers. **It has not yet
  been dispatched against the committed APK set in this handoff**, so no
  fresh artifact-level fingerprint result is claimed.
- GoReSym v3.4.1 scanner patch remains prepared but not built or validated
  against APNA's `libudpqtwo.so`. The unreadable moduledata `ftab` pointer
  remains unresolved; no Go symbol recovery is claimed.
- The APNA `libudpqtwo.so` candidate remains a high-confidence
  StarUDP/Hysteria-v1-derived QUIC family lead, not proof of APNA's exact
  server handshake, ALPN, credentials, configuration or successful
  provider connection.
- SSH remains on hold. Do not add connection activation, TUN/DNS routing,
  Android builds, Windows builds or Linux builds. Keep Connect disabled.

- Follow-up hardening: DEX `invoke-*/range` callsites are still counted, but
  are deliberately excluded from argument correlation because the compressed
  register range must be expanded before choosing the first argument. A
  regression test prevents false `Runtime.exec` / `System.loadLibrary`
  associations from the range endpoints. Cross-split CLI now accepts all APK
  inputs and writes JSON with `--output`; the documented example names the
  actual six APK files currently committed in `APNA-APKs/`.
- GoReSym scanner patch was tightened so the entire pointer signature must
  fit inside the section, with a fifth boundary regression case. Patch hunk
  counts were checked for consistency; it remains unapplied/unbuilt against
  upstream and the APNA binary.
- CI run [46118622215](https://github.com/meicamghe/ApnaWin/actions/runs/46118622215)
  passed on head `efaab7db6869c13293eae94a4416cdb76a6d77b4`:
  **965 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.

- The DEX candidate filter now includes the known `com.liapp.*` protector
  namespace and prioritizes those classes after exact manifest VPN services.
  This lets the bounded scan record readable LIAPP loader callsites without
  attempting to decrypt or bypass protected DEX. A regression test covers
  both candidate inclusion and priority under the 64-class scan cap.

- Final CI for this batch: run [46118934143](https://github.com/meicamghe/ApnaWin/actions/runs/46118934143)
  passed on head `7ac87797161b358aad4056000d1d24dbec16d57f`: **967 passed,
  1 skipped, 1 warning**. The Windows build job remains skipped by the
  reverse-engineering gate. This includes the new LIAPP candidate/priority
  tests and invoke-range false-link regression test.


## Final validation — 2026-11-28

- Dynamic DEX loader reporting now retains the exact constructor type for `DexClassLoader`, `PathClassLoader`, and `InMemoryDexClassLoader`.
- Direct literal colon-separated archive lists are reduced to allowlisted `.dex`, `.apk`, and `.jar` extensions only. Split aggregation distinguishes in-memory ByteBuffer callsites from file-backed loaders with unresolved literal archive extensions.
- Regression coverage includes multiple archive extensions in one path, loader-type attribution, unrelated-register exclusion and in-memory constructor boundaries.
- GitHub Actions run [46123931854](https://github.com/meicamghe/ApnaWin/actions/runs/46123931854) passed on head `e125dfdbcf8c5ff9d9c249053573743c3ca3cd09`: **975 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.
- The GoReSym v3.4.1 patch file has normalized unified-diff headers and four hunk counts matching their declared sizes. It remains prepared only; it has not been applied to upstream GoReSym or validated against APNA's binary.
- The manual APK extraction workflow has not been dispatched. No fresh native inventory/fingerprint artifact or Go symbol recovery is claimed. PR #8 remains open and unmerged.


## Parallel reverse-engineering update — 2026-11-28

- DEX smali linkage now also tracks direct `new-array` allocations of
  `[Ljava/lang/String;` and literal `aput-object` writes into the same
  register. It reports only allowlisted native-library basenames for
  `Runtime.exec(String[])` / `ProcessBuilder(String[])` argument matching.
- The array tracker is bounded by **256 writes per array**, including
  duplicate writes. Register overwrites invalidate the tracked array and its
  write counter. Non-string arrays, aliases, `move-object`, computed values,
  reflection and unresolved register ranges are not followed.
- Tests cover direct array construction, non-string arrays, array-register
  overwrite, multiple literal values, and the 256-write bound including
  repeated identical values.
- GoReSym v3.4.1 patch review found and fixed a missing closing brace in the
  fifth section-boundary regression test. All four unified-diff hunk counts
  now match; all five embedded Go tests have balanced braces. A Python
  regression test now validates patch hunk counts and completeness.
- GitHub Actions run [46125152362](https://github.com/meicamghe/ApnaWin/actions/runs/46125152362)
  passed on code head `984b5a764913319dd863615edf28a2d66f5c4dd6`:
  **980 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.
- A documentation/test-only follow-up commit adds the GoReSym patch artifact
  validator. The patch itself remains unapplied to upstream GoReSym and has
  not been tested against APNA's `libudpqtwo.so`; no Go symbols are claimed
  recovered. The manual native extraction workflow remains undispatched.
- PR #8 remains open and unmerged. No Windows/Linux build, Android build,
  connection activation, or routing implementation was performed.


## Final CI for this batch — 2026-11-28

- Final PR head at validation: `c869bb4a71c4a7d37dd0dec32d58a3bf56a30a6a`.
- GitHub Actions run [46125299993](https://github.com/meicamghe/ApnaWin/actions/runs/46125299993) passed: **982 passed, 1 skipped, 1 warning**. The Windows build job was skipped by the explicit reverse-engineering gate.
- This run includes the bounded String[] DEX tracker tests and the GoReSym patch-artifact integrity tests (unified-diff hunk counts, five embedded test functions, and balanced braces).
- No APNA APK extraction artifact was generated. The GoReSym patch remains prepared only, and no Go symbol recovery or provider handshake is claimed.

## DEX linkage hardening follow-up — 2026-11-28

- Extended regression coverage to `Runtime.exec(String[])` for both direct
  `new-array`/`aput-object` construction and `filled-new-array` captured by
  the immediately following `move-result-object`.
- Static parser review found stale-register false-linkage cases: a destination
  register overwritten by `move-result-object`, `new-array`, or a captured
  `filled-new-array` could retain an earlier string literal. Destination
  invalidation now clears those stale string facts before later callsite
  correlation. This is conservative register-local invalidation, not general
  DEX data-flow analysis.
- Added regression tests for each stale-fact case and for `Runtime.exec`
  String[] linkage. The documentation now reflects the implemented
  `new-array` support and no longer lists it as unsupported.
- Latest source/test commits: `37643e6`, `c963daf`, `d1a8502`, `654fa2f`;
  preceding test/docs commits: `07b0a76`, `ff92fc5`.
- Final CI run [46125957108](https://github.com/meicamghe/ApnaWin/actions/runs/46125957108)
  passed on head `f229f6b84cbf78dc18bbd99e429f6568f276e3a1`:
  **986 passed, 1 skipped, 1 warning**. The Windows build job was skipped
  by the reverse-engineering gate. An earlier run failed because four new
  fixtures contained escaped literal `\\n` sequences instead of newline
  characters; the fixtures were corrected and the final run passed.
- No fresh APK extraction, native fingerprint artifact, GoReSym execution
  against the sample, Go symbol recovery, provider handshake, or live traffic
  validation is claimed. PR #8 remains open and unmerged; all product builds
  and connection activation remain gated off.

## DEX alias and process-start evidence follow-up — 2026-11-28

- The bounded DEX scanner now follows direct `move-object`, `move-object/from16`,
  and `move-object/16` copies for known string literals and tracked `String[]`
  references within one method. String[] aliases share one mutable evidence
  state and one 256-write budget; exceeding the budget invalidates every alias
  of that array.
- Added separate `ProcessBuilder.start()` invocation counts instead of treating
  constructor creation as proof that a child process starts. Split-set reports
  aggregate these counts by APK/class/method and explicitly do not associate a
  constructor instance with a particular `start()` call.
- Added regression tests for direct string aliases, String[] aliases, shared
  alias write limits, stale-register invalidation, and ProcessBuilder
  constructor-versus-start distinctions.
- Final CI run [46127388033](https://github.com/meicamghe/ApnaWin/actions/runs/46127388033)
  passed on head `e48ebfb661ef46ee0336bb40a575db3460d36938`: **992 passed,
  1 skipped, 1 warning**. Windows build remained skipped by the reverse-engineering
  gate. Intermediate regression failures in this batch were corrected before
  this final passing run.
- The parser remains conservative: no general register/data-flow analysis,
  computed values, array index reasoning, reflection, or protected-DEX access.
  Static constructor/start counts are not proof of runtime process creation.
- No fresh APK extraction artifact or native fingerprint output was produced;
  no GoReSym sample execution, Go symbol recovery, APNA provider handshake,
  or live traffic is claimed. PR #8 remains open/unmerged; product builds and
  connection activation remain gated off.


## Native fingerprint input hardening — 2026-11-28

- Hardened the extracted-native fingerprint reader against oversized or malformed
  manifests, non-object JSON roots, traversal-like ABI/library path components,
  symlink escapes and paths resolving outside the extraction root.
- Manifest size is capped at 4 MiB before JSON parsing. ABI directory names and
  native library basenames are now validated against distinct allowlists.
- Added regression cases for dot/dot-dot components, non-library filenames,
  malformed/non-object JSON and manifest size limits.
- These changes improve the offline analysis boundary only; they do not produce
  a new APK extraction artifact or add protocol/runtime evidence.

- Final validation for this hardening batch also rejects boolean values where an
  integer byte size is required and converts deeply nested JSON parser failures
  into a bounded validation error.


- Final CI for the native fingerprint manifest-hardening batch: run
  [46128039334](https://github.com/meicamghe/ApnaWin/actions/runs/46128039334)
  passed on head `2b132cde198dbfd9f43f733529686d60df29243e`:
  **1002 passed, 1 skipped, 1 warning**. The Windows packaging job was
  skipped by the reverse-engineering gate.


## APK native inventory path-safety follow-up — 2026-11-28

- Inventory rejects symlinked APK inputs, repeated input paths, and ambiguous
  duplicate basenames before scanning ZIP contents.
- CLI report output rejects symlinks and any destination resolving to one of
  the APK source files, preventing accidental source-archive overwrite.
- Added regression tests, including platform-aware skips where symlink creation
  is unavailable. This is static tooling hardening; no fresh APK artifact was
  generated and no native library was executed.

- Final CI for APK inventory path-safety hardening: run
  [46129520043](https://github.com/meicamghe/ApnaWin/actions/runs/46129520043)
  passed on code head `5d7573e7ab6f64a6614ae2b7a8e7a189c15cc410`:
  **1007 passed, 1 skipped, 1 warning**. Windows packaging remained skipped.


## Windows connectivity milestone — 2026-11-28

The user has now explicitly authorized moving from reverse-engineering-only work toward a Windows build when the connection path is genuinely ready. This supersedes the earlier instruction not to build Windows until reverse engineering was complete. It does **not** authorize claiming APNA compatibility without evidence or enabling a false-positive Connected state.

### Share-link to TUN configuration path

- Added `services/xray_tun_config.py`: compose strict dual-stack TUN JSON from a parsed VLESS, VMess, Trojan, Shadowsocks or Hysteria2 share link.
- The generated config uses the strict existing Windows TUN policy (IPv4/IPv6 default routes, explicit DNS, physical-interface binding for Xray's own outbound and both WFP leak filters).
- The parsed proxy is the only outbound. No direct/freedom fallback is generated.
- Added `services/proxy_profile_import.py`: bounded batch parse, collision checks, encrypted config writes, one metadata commit and cleanup attempts on failure. Cleanup failures remain explicit.
- Added desktop **Import server links…** action. Imported secrets are stored through the existing current-user DPAPI config store; metadata exports remain credential-free.
- Tests cover the builder, supported outbound families, no-direct-fallback policy, transactional failure cleanup and desktop import wiring.

### Remaining connection gates

- The desktop Connect button is still disabled. The elevated helper can start Xray and waits for stable Wintun adapter, dual-stack routes and configured DNS, but the desktop does not yet own a production connection engine/lifecycle.
- Stable route/DNS readiness is not the same as successful end-to-end traffic. Do not mark CONNECTED until a real authorized traffic probe succeeds through the tunnel.
- Need to wire `XrayTunnelSupervisor` to a production engine and asynchronous UI lifecycle; handle helper exit, cancellation, stop failures and cleanup ownership.
- Need Windows 10/11 tests for graceful disconnect, helper/desktop crash, forced termination, route/DNS restoration and WFP leak behavior.
- Generic Xray share-link compatibility is not evidence of APNA TUNNEL backend compatibility. APK native extraction artifact is still required to complete APNA protocol/launch-owner verification.
- No Windows artifact has been built for this new import path yet. Packaging remains opt-in via workflow_dispatch; do not call a desktop preview a connectable VPN build.
- PR #8 remains open and unmerged. SSH remains on hold.


## Asynchronous Windows Xray connection lifecycle — 2026-11-28

- Added `services/xray_connection_worker.py`: starts the fixed Program Files UAC helper on a Qt worker thread, handles cancel/stop requests, polls for unexpected helper exit, and never blocks the GUI while waiting for UAC or tunnel startup.
- Added `services/windows_tunnel_traffic_probe.py`: resolves a fixed HTTPS probe host, asks Windows `Find-NetRoute` which interface is selected for each candidate IP, requires the selected interface to match the ApnaWin TUN adapter, then completes a TLS-verified HTTP/1.1 request directly to that IP with the expected SNI/Host header.
- The desktop Connect action is enabled only for a selected XRAY profile with an encrypted config and a protected helper at `%ProgramFiles%\\ApnaWin\\ApnaWinElevator.exe`. It remains disabled for non-Windows development environments or when either prerequisite is absent.
- UI state transitions are asynchronous: Connect/Cancel during startup, Disconnect after traffic verification, and explicit failure/lost states. Profile mutation controls are locked during an active session.
- The UI does not report CONNECTED when the helper only signals adapter/routes/DNS readiness. It waits for the route-bound TLS/HTTP probe to pass; a probe failure requests helper shutdown.
- If graceful cleanup fails, the worker retains the supervisor handle, blocks reconnect, and asks the user to close the desktop. The helper watches the parent process handle and should unwind its Xray Job Object when the desktop exits.
- Added worker, traffic-probe and UI prerequisite tests. These are mocked/unit tests; they do not constitute live Windows network acceptance.
- Remaining release gates: run CI on this exact head; test on clean Windows 10 and Windows 11 x64 with an authorized Xray server; verify successful IPv4/IPv6 traffic, DNS behavior, endpoint route pinning, WFP leak prevention, normal disconnect and helper/desktop crash recovery. Verify the pinned Xray/Wintun runtime is present and signed as expected.
- No APNA TUNNEL protocol compatibility is claimed. The current path is generic Xray share-link connectivity only. APK native extraction and `libudpqtwo.so` ownership/revision analysis remain separate workstreams. PR #8 stays open/unmerged; SSH stays on hold.


## Windows CI validation artifact — 2026-11-28

- Enabled the Windows packaging job on pull requests, gated behind a successful full Windows test job. This is a validation artifact for the generic Xray client path, not an APNA-compatible product release or signed installer.
- Strengthened the traffic probe to require the configured DNS server routes and the HTTPS destination route to select the ApnaWin interface before issuing the TLS/HTTP request.
- Added a successful mocked TLS/HTTP probe test plus a DNS-route leak rejection test.
- The first full Windows CI attempt on head `4f19169710a195f836148556401621dc5e38d728` reported **1038 passed, 1 skipped, 1 failed**. The sole failure was a test observer connected with Qt's default queued delivery while the test blocked the main thread in `QThread.wait()`; the observer now uses an explicit direct connection. This was a test-harness issue, not a production worker failure.
- Next required result is a green Windows test job followed by the new `build-windows` job and its artifact. No claim of live VPN acceptance is made until the resulting executable is tested against an authorized server on Windows 10/11.


## APNA SSH backend port — 2026-11-28

- Created `feature/apna-ssh-backend-port` from the legacy-profile compatibility head `c023874e07ff6883da74833e89cab2a748fc235f`.
- Ported the APNA SSH stack from the older `vpn/dual-stack-egress-readiness` workstream: bounded catalog decoder/source, strict server/payload mapper, DPAPI-protected APNA profile store, payload socket adapters (direct/TLS/HTTP/WebSocket), Paramiko SSH session with host-key pinning, loopback SOCKS5 TCP forwarding, UDPGW framing/flow relay, APNA tunnel engine, and Xray/Wintun TUN composition.
- Ported the matching SSH/catalog/profile-store/egress/supervisor regression tests and restored the APNA import, host-key verification and connection UI integration from that workstream. The generic JSON profile import remains intentionally absent and Add remains hidden.
- Added Paramiko as an explicit runtime dependency. Existing legacy `apna_ssh` profile metadata is preserved by the base compatibility commits; encrypted connection settings are kept separately in the DPAPI-backed APNA profile store.
- The source workstream PR #6 is highly divergent from the current reverse-engineering branch (788 commits ahead and 352 behind at comparison time); it was **not merged**. Only the focused transport/UI files and tests were ported.
- This is a code integration checkpoint, **not a verified APNA connection**. No CI result is claimed for this new branch, and no authorized provider SSH host-key/authentication, UDPGW datagram, routed TCP/UDP/DNS, disconnect, or crash-recovery acceptance has been recorded. Connect remains dependent on a protected Windows helper installation and an imported APNA configuration with independently verified host identity.
- Next gates: run the full test suite on this exact branch; inspect and resolve integration failures; then test one authorized APNA profile on Windows 10/11 with provider-issued host-key verification and real TCP/UDP/DNS traffic. Do not enable a false-positive Connected state or publish a release before those gates pass.
