# Current active state — 2026-11-25

**Repository:** `meicamghe/ApnaWin`  
**Branch:** `vpn/dual-stack-egress-readiness`  
**PR:** [#6](https://github.com/meicamghe/ApnaWin/pull/6), open Draft, not merged.  
**Documentation reconciliation commits:** `a5096583c38768dcba913ecc8da089461c1b4535` and the subsequent README/architecture/triage updates (see branch history).

## Current implementation truth

- The Windows composition root always registers **APNA SSH** and **Xray** when the protected Program Files installation helper is valid.
- **UDPQ is conditionally registered** only when `Program Files/ApnaWin/engine/udpq-client.exe` and `runtime-manifest.json` validate against the pinned StarUDP source commit, reviewed redaction-patch hash and executable SHA-256. It is an experimental generic manual-profile path, not an APNA catalog mapping.
- UDPQ starts the pinned Windows x64 sidecar, verifies its loopback SOCKS5 listener, then composes it with the existing Xray/Wintun dual-stack tunnel. Disconnect shuts down Xray/Wintun before the sidecar.
- OpenVPN and standalone SOCKS enum values have no production engine registration.
- Xray protocol outbounds include VLESS, VMess, Trojan, Shadowsocks, Hysteria 2, WireGuard and MASQUE; these are not separate engine processes. HTTP/SOCKS outbounds are proxy modes, not encrypted VPN protocols.
- APNA Lite catalog mapping remains limited to the verified SSH-family categories `ocsws`, `ocscf`, `ocsnormal` and `ocshttp`. Other categories must not be mapped by name alone.
- APNA ARM64 and UDP Thunder 1.5 ARM32 `libudpqtwo.so` samples have matching StarUDP-family Go package/type/config fingerprints. This is strong static lineage evidence, not proof of exact source revision, APNA service ownership, runtime configuration, ALPN/auth/SNI values, or live-server compatibility.
- The protected LIAPP DEX has not been bypassed. Ordinary service/process diagnostics remain the acceptable route to establish native ownership and launch parameters.
- No live APNA SSH authentication, APNA UDPGW round-trip, APNA UDPQ handshake, or Windows routed APNA traffic has been established. Green CI and loopback tests do not change that.
- The pinned BadVPN Windows artifact remains research-only: its upstream Windows TUN backend targets TAP-Windows, not ApnaWin's Wintun path.

## Latest verified checkpoint — 2026-11-25 14:00 +03:30

Current branch HEAD: `a8825acfef763a2b169c6a27b9f8dd0d9828d81a`.

All three workflows on this exact HEAD completed successfully:
- [Windows tests and runtime checks](https://github.com/meicamghe/ApnaWin/actions/runs/45591387626): **1,576 passed, 31 skipped**, 2 warnings. Ruff, installer/runtime security, VPN readiness/egress and Xray compatibility checks passed.
- [UDPQ Sidecar Build](https://github.com/meicamghe/ApnaWin/actions/runs/45591387651): passed, including Windows x64 sidecar build and QUIC TCP+UDP loopback relay verification.
- [Windows x64 UDPQ test package](https://github.com/meicamghe/ApnaWin/actions/runs/45591387733): completed successfully; pinned StarUDP sidecar, desktop/elevated helper executables, portable-folder assembly and upload all passed.

Latest temporary artifact: [ApnaWin-Windows-x64-UDPQ-Test](https://github.com/meicamghe/ApnaWin/actions/runs/45591387733/artifacts/15010399805), ID `15010399805`, **298,488,930 bytes**, SHA-256 `fd12bb558f28c2f27748ba0420dfe7cd6575ffb8f3eddc2fb91fcd499692fb2a`, expires 2026-12-02. It is a test package, not a provider-accepted release.

The non-blocking live APNA catalog probe also succeeded and returned version `863`, 50 free servers, 646 payloads and zero premium/VIP/private servers. This establishes catalog reachability only; it does not establish APNA SSH authentication, UDPGW/UDPQ handshake, or provider-routed traffic.

The WebSocket close-frame validation and regression tests, including the corrected binary fixtures, are included in this tested HEAD. The CI queue-cleanup fix is also included. PR #6 remains open, Draft, unmerged and mergeable. Keep it Draft until real provider acceptance gates pass.

## Latest full CI-verified checkpoint

Commit `28d831cd3c0e15b1a5716480c814bdfd2e2c2201` (2026-11-25):
- [Windows tests and runtime checks](https://github.com/meicamghe/ApnaWin/actions/runs/45587012242): **1,563 passed, 31 skipped**, including **179 VPN runtime readiness/egress tests**; Ruff, installer/runtime security and pinned Xray compatibility checks passed.
- [UDPQ Sidecar Build](https://github.com/meicamghe/ApnaWin/actions/runs/45587011906): Windows x64 sidecar build and TLS 1.3/QUIC loopback SOCKS5 TCP + UDP relay test passed.
- [Windows x64 UDPQ test package](https://github.com/meicamghe/ApnaWin/actions/runs/45587011844): **completed successfully** after a rerun. Desktop and elevated-helper executables built, the portable test folder was assembled, and upload passed. Artifact: `ApnaWin-Windows-x64-UDPQ-Test` (ID `15009972594`, 298,490,768 bytes; SHA-256 `2ecceebe786d5cd8f93bd89e73c3dad143355b2a3e7579875d6bcc8908ff2872`; expires 2026-12-02). This is a temporary test package, not a provider-accepted release.

The full test and sidecar workflows validate automated code paths and loopback behavior only. They do **not** prove live APNA authentication, APNA UDPGW/UDPQ interoperability, or real provider-routed traffic. The earlier checkpoint `12c93ac15e55aaa7fc48136a4495d22fb29e123e` and its results are historical; the earlier package artifact is not evidence that the current package run completed.


## Latest CI and protocol-hardening update — 2026-11-25

The documentation-head rerun on commit `e60550f7dc8c3a97f94dbd38228a2f68df3745d2` is fully green:
- [Windows tests and runtime checks](https://github.com/meicamghe/ApnaWin/actions/runs/45589238424): passed; **1,563 passed, 31 skipped**.
- [UDPQ Sidecar Build](https://github.com/meicamghe/ApnaWin/actions/runs/45589238225): passed.
- [Windows x64 UDPQ test package](https://github.com/meicamghe/ApnaWin/actions/runs/45589238432): completed successfully; all build, portable-folder assembly and upload steps passed.
- New temporary artifact: [ApnaWin-Windows-x64-UDPQ-Test](https://github.com/meicamghe/ApnaWin/actions/runs/45589238432/artifacts/15009349155), ID `15009349155`, **298,490,545 bytes**, SHA-256 `55a2f1e0ddc67f0c0146e5ccdfd7ac525085f275b5c55701fc834618f2595755`, expires 2026-12-02. This is a test artifact, not a provider-accepted release.

After that green checkpoint, WebSocket close-frame validation was tightened in `src/apnawin/engines/websocket_stream.py`: reject reserved/invalid close status codes and strictly decode the optional UTF-8 reason before echoing the close frame. Regression tests cover reserved/out-of-range codes, malformed UTF-8, valid application code/reason, and an empty close payload. Commits: `aaed246244e5b6f5e278fbd5609bbb1abcf0635f` (implementation), `3dfe88d2e29eea512149b0c6a5d3f2e8bf66bd19` (tests). **These two commits are awaiting their own CI run; do not treat the earlier green runs as validation of this change.**

The new artifact is for Windows x64 test execution. It does not establish APNA SSH authentication, APNA UDPGW/UDPQ interoperability, or real provider-routed traffic.

## Next engineering gates

1. Establish which ordinary Android service/process loads `libudpqtwo.so`, without bypassing LIAPP.
2. Recover APNA-provided runtime configuration through an authorized diagnostic trace: ALPN, SNI, auth representation, rates, packet mode, obfuscation and hopping semantics.
3. Compare remaining Go function/type fingerprints against pinned StarUDP source and document exact match confidence.
4. Test generic UDPQ against an authorized StarUDP-compatible server; separately test APNA only when an authorized APNA endpoint/config is available.
5. Complete Windows 10/11 acceptance for SSH host-key verification, authentication, UDPGW, routed TCP/UDP/DNS, dual-stack egress/leak checks and disconnect/crash cleanup.
6. Keep PR #6 Draft and unmerged until provider acceptance gates pass.

## Documentation maintenance rule

This section is the single current handoff. The material below is a historical archive; its dated HEADs, CI statuses and implementation inventories are not current facts unless re-verified.

---

## Historical handoff archive (snapshots from 2026-11-23 and earlier)

## User acceptance target

A real Windows 10/11 connection to APNA TUNNEL LITE (`com.apnatunnel.lite`) with SSH host-key verification, successful authentication, and routed TCP/UDP/DNS traffic. Unit tests, mocked sockets, package builds and catalog decoding are not proof of provider connectivity. Do not call the build ready until this passes.

## Current implementation inventory

- Catalog: bounded Base64/modified-XXTEA decoder and APK asset reader; discovery-only live updater source. The supplied APK's actual `assets/janur.json` decodes to Version 580, 44 free servers and 623 payloads. No credentials were printed or added to fixtures.
- Profile import: Windows UI imports an APNA APK, lists supported SSH-category server/payload pairs, probes SSH host keys without authentication, and stores selected credentials/settings under current-user DPAPI. The UI dispatches `APNA_SSH` profiles to `ApnaTunnelEngine`.
- SSH: payload compiler, direct/TLS/HTTP payload socket connector, Paramiko authentication with known-hosts or explicit SHA-256 pin, and loopback-only SOCKS5 TCP forwarding.
- UDP: BadVPN-compatible PacketProto/UDPGW codec, flow-ID/LRU manager, SSH-carried UDPGW stream, and loopback SOCKS5 UDP ASSOCIATE gateway.
- TUN: `ApnaTunnelEngine` starts the SSH/UDPGW session, generates a strict dual-stack Xray TUN config whose only outbound is the loopback SOCKS5 gateway, starts the elevated Xray/Wintun supervisor, and performs UDP DNS egress probing before reporting connected.
- Native research: pinned BadVPN Windows x64 build workflow has passed in prior run [43887319339](https://github.com/meicamghe/ApnaWin/actions/runs/43887319339). This build uses TAP-Windows and is not wired into the product; Xray/Wintun remains the product TUN path.
- Payload compatibility: APNA primary DEX confirms ordered placeholder substitution, ISO-8859-1, `[instant_split]`, `[delay_split]`, and exactly 1000 ms delay. The related Android injector accepts HTTP 200 and does not reject 101 Upgrade; mapper now allows both for Upgrade payloads while requiring 200 for ordinary HTTP payloads.

## Verified APK and reverse-engineering boundary

- Base APK SHA-256: `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`.
- No ELF/.so entry is embedded in base.apk; an ABI split/native-library extraction is still needed.
- `assets/.bxdtcxfzx.dex` is a LIAPP stub: declared DEX file size 428 bytes, one `com.liapp` loader class, with 98,907 appended protected bytes. `assets/LIAPP.ini` identifies LIAPP 5.1.1.190. The protected `SalamanderService` implementation is not recoverable from the ordinary visible DEX inventory without the LIAPP runtime/decryption path.
- Actual embedded catalog snapshot has four SSH-compatible categories: `ocsws` (8 servers/469 payloads), `ocscf` (2/118), `ocsnormal` (2/1), `ocshttp` (4/1). Its server records in those categories contain `server_port=1194`, `ssl_port=443`, `server_udp_port=53`; these are snapshot values only.
- The runtime mapping of all catalog fields and exact protected service behavior is not fully verified. The profile mapper is a working hypothesis constrained to observed catalog fields; do not treat every method/category as provider-certified.

## Actual connectivity status and next gates

No real APNA SSH authentication, UDPGW session, or Windows application traffic has yet been demonstrated. The current container cannot resolve the embedded APNA hostnames (temporary DNS resolver failure), so it cannot perform live endpoint checks from this environment.

1. Obtain a usable live network path for DNS/TCP checks against a selected embedded APNA SSH endpoint; then run the host-key probe and compare the fingerprint with an independent provider source.
2. Attempt real SSH authentication using the APK-provided public catalog credentials only through the encrypted local profile flow; capture redacted handshake/auth result.
3. Verify the UDPGW stream on the selected server/port and DNS query/response over that stream.
4. Run the Windows x64 packaged app on a clean Windows 10/11 machine; verify Xray/Wintun TUN, IPv4/IPv6 TCP, UDP, DNS, disconnect and crash cleanup.
5. Keep APNA Connect disabled or fail closed wherever endpoint identity, credentials, UDPGW or TUN readiness is not validated. Never infer success from a green test suite.


## User acceptance target

The only meaningful product milestone is a real Windows 10/11 connection to the user's target APNA TUNNEL LITE service (package `com.apnatunnel.lite`), with authenticated handshake and verified routed traffic. A successful build, UI, Xray smoke test, catalog decode, mocked network test or green unit suite does **not** establish APNA compatibility. Keep APNA Connect disabled until real authorized endpoints and credentials/profile configuration are validated end-to-end.

## New APNA evidence and implementation since the older notes

- Supplied base APK SHA-256: `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`. Its primary DEX exposes Android VpnService/TUN, local SOCKS, SSH manager, XRay and SOCKS/HTTP service launch descriptors, and a separate UDPGW/DNS control path. The APK has no embedded ELF/.so entry; an ABI split or protected extraction path is still needed to inspect the exact native binary.
- Exact public JNI package match: `org.uproxy.tun2socks.Tun2SocksJni`; the related uProxy source describes TCP via SOCKS and UDP via a separate UDPGW endpoint.
- BadVPN UDPGW framing has been documented: 16-bit little-endian PacketProto frame length; 3-byte flags/connection-ID header; destination address and port; UDP payload. The client opens a SOCKS CONNECT stream to UDPGW; it is not SOCKS5 UDP ASSOCIATE. The inspected current CMake tree includes UDPGW client and Windows socket backends, but a real Windows build and UDPGW round-trip are still unverified.
- The exact method-name cluster `formatCustomPayload`, `injectSplitPayload`, `injectSimpleSplit`, `parseRotate` appears in public sibling implementations. A closer SecondVPN source explicitly recognizes `[instant_split]` and implements immediate write/flush boundaries, while `[delay_split]` sleeps 1,000 ms between chunks and `[rotate=...]` advances round-robin. The 1-second default is sibling evidence, not yet proven from APNA's protected method body.
- Added `src/apnawin/engines/apna_payload.py`: APNA-observed placeholder expansion, strict ISO-8859-1 encoding, split chunk generation, injectable delay and per-profile rotation. Added `tests/test_apna_payload.py`. **Historical status:** this was initially a standalone tested building block. Later commits wired it through `ApnaPayloadSocketConnector` into `ApnaSSHSession`; current source uses it in the SSH payload-stream setup. That local integration still does not prove real APNA authentication.
- New detailed evidence: `docs/apna-upstream-framework-comparison.md`, `docs/apna-lite-android-runtime-analysis.md`, `docs/apna-lite-integration-plan.md`, and `docs/apna-tunnel-lite-upstream-evidence.md`.

## Immediate next engineering gates

1. Recover all installed APNA split APKs and fingerprint the actual `libtun2socks` binary.
2. Trace the protected APNA selection path: server category → payload → SSH/XRay/SOCKS/direct mode, including semicolon host pools and the meaning of `Pulled`, `sslws`, `sausage`, `query`, `dothost`, and certificate fields.
3. Confirm APNA payload replacement order, `[protocol]` value, rotate state scope and delay timing from the protected method body or controlled traces.
4. Build the SSH transport adapter and integrate the payload compiler; implement HTTP proxy/SSL/WS modes only when their actual catalog mapping is known.
5. Build and test the Windows UDPGW client path, then connect the appropriate TUN-to-SOCKS/UDPGW forwarding runtime.
6. Test with an authorized real APNA profile on Windows 10/11; verify handshake, IPv4, IPv6, DNS, reconnect and cleanup. Do not report connection success before this passes.

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



## UDP DNS readiness validation — 2026-11-18

The APNA full-tunnel startup path runs a UDP DNS probe after Xray/Wintun has installed the TUN routes and before the engine reports CONNECTED. The probe uses the configured resolver IP literals, verifies the response source and transaction ID, requires an exact matching question and NOERROR response, and now parses every declared answer record to reject truncated or malformed DNS packets. Configured IPv4 and IPv6 resolver families must each pass. Regression coverage includes malformed compression pointers, truncated RDATA, invalid flags, wrong questions, duplicate resolvers, timeout validation and IPv6 failure.

This remains automated protocol validation, not a substitute for provider-side Windows acceptance. Validate actual DNS and leak behavior on clean Windows 10/11 hosts before changing PR #6 from Draft.


## APNA TLS compatibility and cleanup regression coverage — 2026-11-23

- The live Windows acceptance guide now distinguishes provider CA validation from the explicit per-profile TLS compatibility fallback. The fallback disables TLS chain/hostname verification, retains encryption and SNI, and does not bypass SSH host-key pinning or SSH authentication.
- Added UI regression coverage for enabling/disabling the selected profile's TLS compatibility option and preserving SNI.
- Fixed the UI rollback path: if encrypted profile persistence fails after a checkbox change, restore the previous visible selection instead of leaving the UI inconsistent with stored state. Added parameterized tests for both prior checkbox states.
- Added APNA tunnel-engine coverage for retrying encrypted Xray-config cleanup after a transient store-removal failure. The first disconnect must retain ERROR ownership state; a later disconnect retries only the remaining config cleanup and must not restart or re-stop already released network resources.
- UDPGW wire encoding now rejects scoped IPv6 literals (for example, `fe80::1%eth0`) because the BadVPN frame carries only the 16-byte IPv6 address and cannot preserve a local interface scope. Added a regression test; ordinary IPv6 literals remain supported.
- BadVPN native Windows x64 workflow succeeded on commit d03d0e85dfd6b077ceaced797dabc2332f99e4f6. The Windows tests/build workflow for that commit was still queued at last check. Commits after d03d0e8 require their own CI result; do not treat earlier green runs as validation of newer changes.
- Current work remains in PR #6, Draft. No live authorized APNA Windows endpoint acceptance has been performed; real SSH authentication, UDPGW datagram round-trip, routed IPv4/IPv6/DNS traffic and crash/disconnect restoration remain release gates.

## Latest verified checkpoint — 2026-11-25 14:10 +03:30

The branch head `b5182385255c8008de36e1d0ab257ca139a5d254` has now completed a fresh validation cycle. Unlike the earlier parent-only checkpoint, these runs target the exact current branch head:

- [Windows tests and runtime checks](https://github.com/meicamghe/ApnaWin/actions/runs/45595722797): all six jobs passed. The unit/integration job reports **1,576 passed, 31 skipped, 2 warnings**. Ruff, installer/runtime security, VPN readiness/egress and pinned Xray share-link compatibility also passed.
- [UDPQ Sidecar Build](https://github.com/meicamghe/ApnaWin/actions/runs/45595721017): passed. The Windows x64 sidecar build and Linux reference QUIC loopback test with SOCKS5 TCP CONNECT and UDP ASSOCIATE relay both passed.
- [Windows x64 UDPQ test package](https://github.com/meicamghe/ApnaWin/actions/runs/45595720692): all jobs passed, including sidecar build, desktop/elevated-helper build, portable-folder assembly and artifact upload.

Latest test artifact: [ApnaWin-Windows-x64-UDPQ-Test](https://github.com/meicamghe/ApnaWin/actions/runs/45595720692/artifacts/15012953411), artifact ID `15012953411`, size 298,489,227 bytes, SHA-256 `7dc07702a44fd71faf4e896c07e1f7655661e28db6b58a08b82a76be5f957afe`, expires 2026-12-02. This is a temporary test package, not a release.

The static evidence boundary is unchanged: APNA/UDP Thunder `libudpqtwo.so` fingerprints support a related StarUDP-family implementation lineage, but do not disclose APNA's effective ALPN, SNI, auth bytes, rate limits, packet mode, obfuscation, port hopping or protected launch/config handoff. The pinned StarUDP Windows sidecar remains generic/manual-profile only. No live APNA SSH authentication, APNA UDPGW datagram round-trip, APNA UDPQ handshake or real APNA-routed TCP/UDP/DNS traffic has been demonstrated.

PR #6 remains open, Draft and unmerged. Do not promote the PR or label the package APNA-compatible until the provider acceptance gates above pass.
