# APNA TUNNEL LITE integration plan

**Status (2026-11-16):** APNA profile import, live catalog retrieval, SSH/UDPGW session and Xray/Wintun TUN integration are implemented in code. No real APNA authentication or routed provider traffic has been verified; this is not release-ready.

**Target application:** APNA TUNNEL LITE, Android package `com.apnatunnel.lite`.

## Current implementation snapshot — 2026-11-16

This snapshot supersedes any older checklist statements below that describe the APNA source as discovery-only or the SSH/TUN integration as unwired.

- Windows UI: imports either the embedded APK catalog or the live updater catalog asynchronously. Live downloads use the observed `Dalvik/2.1.0` User-Agent, identity encoding, bounded retries, and HTTP Range resume for truncated responses. Only selected profile settings are persisted, encrypted with current-user DPAPI.
- Catalog evidence: supplied APK = Version 580, 44 free servers, 623 payloads. An independent third-party report observed live Version 850, 50 free servers, 644 payloads on 2026-11-13; not official provider documentation.
- Payload: primary DEX confirms ordered placeholder expansion, ISO-8859-1, Java split behavior and 1000 ms delayed split. HTTP Upgrade payloads accept 200 or 101 before SSH authentication.
- SSH: direct/TLS/HTTP payload connector, Paramiko authentication, strict known-hosts or explicit SHA-256 pin, and loopback-only SOCKS5 TCP forwarding.
- UDP: BadVPN-compatible PacketProto/UDPGW codec and flow tracking; UDPGW stream is carried through SSH direct-tcpip and exposed through SOCKS5 UDP ASSOCIATE.
- TUN: `ApnaTunnelEngine` is wired to the UI and starts a strict dual-stack Xray native TUN using Wintun with the loopback SOCKS5 gateway as its only outbound. UDP DNS is probed before reporting connected.
- Health: active APNA session refresh checks SSH authentication and local SOCKS5 listener health in addition to Xray helper health.
- Validation: Windows CI run 43890182547 passed Ruff, VPN readiness/egress, security and packaging; its full suite had 1129 passed, 1 skipped and one outdated empty-response assertion. That assertion was fixed in the current branch; a fresh full validation is still required.
- Blocker: no live APNA SSH authentication, UDPGW round-trip or Windows application traffic has been proven. The current container cannot resolve the APNA hostnames. A non-blocking live-catalog probe is included in Windows CI to check a different network vantage point without exposing credentials.

## 1. Evidence baseline

The project uses two inputs:

1. The user-provided APK already held in the ChatGPT Library. Its embedded `assets/janur.json` was decoded locally and matched the reported embedded-catalog fingerprint: version `580`, 44 free servers, 623 payloads.
2. The third-party reverse-engineering repository and its APNA decoder/README/report. These are research evidence, not official provider documentation:
   - Repository: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM
   - APNA decoder: `decoders/Python/apps/APNA_Tunnel_Lite/APNA_Tunnel_Lite.py`
   - APNA README: `decoders/Python/apps/APNA_Tunnel_Lite/README.md`
   - Report: `analysis/platform/supplied-integrations/2026-11-14/ANALYSIS.md`

See [upstream framework comparison](apna-upstream-framework-comparison.md), [upstream protocol evidence](apna-tunnel-lite-upstream-evidence.md) and [Android runtime static analysis](apna-lite-android-runtime-analysis.md) for the detailed observations and limitations.

## 2. Current implementation

| Component | State | Responsibility |
|---|---|---|
| `apna_lite_catalog.py` | Implemented | Base64 + modified-XXTEA decoding, bounded input, JSON duplicate-key rejection, schema checks and safe summary |
| `apna_lite_source.py` | Implemented; discovery-only | Fetch candidate updater endpoint over TLS with reported Android headers, finite timeout, redirect rejection and response-size limit |
| `test_apna_lite_catalog.py` | Implemented | Synthetic encryption/decryption and malformed-input tests |
| `test_apna_lite_source.py` | Implemented | Mocked HTTP transport, headers, timeout and safe-summary tests |
| `RemoteCatalogRefreshCoordinator` | Existing, provider-neutral | Single-flight refresh, last-known-good cache, freshness validation and bounded backoff |
| `HttpsCatalogProvider` | Existing, provider-neutral | Fetches the internal normalized catalog format; it is not the APNA adapter |
| `TunnelEngine` / `ConnectionController` | Existing | Engine-neutral lifecycle contract and fail-closed connection orchestration |
| `XrayTunnelEngine` | Existing | Windows Xray/Wintun engine; accepts XRAY profiles only |

The APNA source is deliberately **not** wired into the normalized catalog cache or the Connect button yet. APNA records contain credentials and engine-specific values, while the existing normalized catalog deliberately stores only non-secret display metadata. A conversion must not be guessed.

## 3. APNA data model observed in the supplied APK

The decoded document includes:

- `Version`
- `Free_servers`, plus optional premium/VIP/private server sections
- `Payloads`
- top-level `Username` and `Password`

Observed free-server fields are strings:
`server_name`, `server_host`, `server_port`, `server_udp_port`, `ssl_port`, `category`, `username`, `password`, `custom_cert`.

Observed payload fields are strings:
`friendly_name`, `category`, `host`, `port`, `method`, `payload`, `query`, `sslws`, `sausage`, `dothost`, `message`.

The sample includes payload methods `http`, `ssl`, `udp`, `direct`. Category names overlap between server and payload records. The sample also contains semicolon-delimited host pools, blank server port fields and payload port value `Pulled`. None of these should be interpreted as a complete connection specification until Android selection/runtime code is traced.

## 4. Parallel workstreams

### A. Catalog transport and refresh

- [x] Implement bounded embedded catalog decoder.
- [x] Add discovery-only HTTP source using the reported endpoint and request headers.
- [x] Reject redirects and oversized responses; keep platform TLS certificate validation enabled.
- [x] Require HTTP 200, identity content encoding, and matching bounded Content-Length; reject partial and truncated responses.
- [x] Add mocked transport and synthetic decoder tests.
- [ ] Verify the endpoint and headers against a fresh live response.
- [ ] Compare live and embedded schemas using redacted field/type/count metadata only.
- [ ] Add version-aware refresh policy and cache integration after upstream behavior is verified.

**Safety:** Never log, persist, commit, upload to CI, or place real top-level/server credentials in fixtures. Do not include raw decoded catalog in exception messages or diagnostics.

### B. Android behavior reconstruction

- [x] Identify exact package and app version from the supplied APK.
- [x] Identify the `OpenVPNClient` descriptor reference and LIAPP-protected asset; confirm the descriptor alone does not establish OpenVPN protocol use.
- [x] Trace the primary DEX-defined Android TUN stack: `VpnService`, `TunnelVpnManager`, `Tun2Socks`, `libtun2socks.so`, SSH manager and DNS helpers.
- [x] Confirm the TUN settings pass traffic to a configured SOCKS endpoint and expose separate DNS/UDP relay controls.
- [x] Confirm separate service launch paths for SSH, XRay and SOCKS/HTTP forwarders.
- [x] Identify custom-payload formatter and CR/LF/SSH placeholder token references; the primary DEX exposes `[instant_split]` and `[delay_split]`.
- [x] Add an isolated APNA payload compiler for host/port/protocol/SSH/line-ending tokens, ISO-8859-1 encoding, instant/delayed segment boundaries and `[rotate=...]`; tests cover chunk ordering, flushes, delays and rotation. The 1-second delay is a configurable sibling-source default, not yet confirmed from protected APNA bytecode.
- [x] Add a lower-level payload socket connector for direct TCP, HTTP payload injection, and TLS-before-payload; validate bounded HTTP 200 responses, preserve Dropbear no-response mode, and close sockets on all failures. This is a stream transport only, not SSH authentication.
- [ ] Verify APNA's protected service/mode selection and catalog-to-endpoint mapping before enabling any transport mode.
- [x] Add a Paramiko SSH session adapter with password/private-key authentication, strict known-hosts rejection, optional explicit OpenSSH SHA-256 host-key pinning, and a loopback-only SOCKS5 TCP CONNECT listener; tests use fake SSH transports and local sockets, so no real APNA authentication is claimed.
- [x] Expose authenticated SSH `direct-tcpip` channels for the separate UDPGW stream; actual APNA UDPGW endpoint/port is still unknown.
- [x] Add bounded UDPGW flow-ID allocation, first-packet REBIND, LRU reuse and response-to-flow validation; tests use synthetic packets only.
- [x] Implement and test the BadVPN-compatible UDPGW/PacketProto wire codec (IPv4/IPv6, DNS/REBIND/keepalive flags, little-endian framing and incremental stream parsing).
- [x] Implement a local SOCKS5 gateway: TCP CONNECT via the SSH SOCKS endpoint; UDP ASSOCIATE via a persistent UDPGW stream tunneled through SSH; bounded flow-ID/LRU lifecycle, keepalives, DNS policy and loopback-only listener. Tests exercise synthetic TCP and UDPGW round-trips.
- [x] Add `ApnaTunnelSession` orchestration: authenticate SSH, preflight the configured UDPGW endpoint through SSH SOCKS, start the loopback TCP/UDP SOCKS5 gateway, and close resources in reverse order while retaining handles on cleanup failure. This remains a user-mode transport, not a TUN connection.
- [x] Implement the APNA SSH/UDPGW session → loopback SOCKS5 gateway → generated Xray SOCKS outbound → existing protected Xray/Wintun TUN orchestration in `ApnaTunnelEngine`; the engine is wired into the Windows connection controller for `APNA_SSH` profiles. This is implementation evidence, not proof of provider compatibility.
- [ ] Verify real TCP, UDP and DNS traffic over an authorized APNA server on Windows 10/11. Do not use BadVPN's Windows TAP-Windows device path unless a separate TAP driver is deliberately selected.
- [x] Record server and payload fields, methods, categories and ambiguous values.
- [x] Implement strict server/payload category matching and mapping for the four supported SSH-family categories (`ocsws`, `ocscf`, `ocsnormal`, `ocshttp`), including `Pulled` endpoint handling and bounded host/port validation.
- [ ] Verify Android-equivalent server/payload selection order, semicolon-host fallback and unsupported catalog field semantics against protected runtime evidence.
- [x] Implement the SSH + payload-injection + local SOCKS forwarding topology, plus an encrypted APNA profile mapper/store and Windows app wiring. The mapped credentials originate from the embedded catalog decoder; exact live-provider acceptance and Android-equivalent selection semantics remain unverified.
- [x] Add a pinned-source Windows x64 BadVPN build workflow for `badvpn-tun2socks.exe` and `badvpn-udpgw.exe`; the upstream target includes `SocksUdpGwClient.c` and Windows socket backends. The workflow is build validation only. The upstream TUN device uses TAP-Windows (`BTap`), not Wintun, so these binaries are not yet part of the product path.
- [ ] Obtain every installed APNA split APK (especially the ABI-specific split) to recover and fingerprint the referenced libtun2socks.so; the supplied base.apk has no ELF/native-library entry.
- [ ] Determine how semicolon-delimited server hosts are selected.
- [ ] Determine the meaning and substitutions for `Pulled`, `sslws`, `sausage`, `query`, `dothost`, and `custom_cert`.
- [ ] Recover each category's runtime engine and exact launch contract.
- [ ] Recover certificate, credential, TLS, SNI, HTTP upgrade, UDP and port-selection behavior where applicable.

### C. Windows engine adapters

- [x] Keep the provider-neutral `TunnelEngine` contract and existing Xray/Wintun safety implementation.
- [ ] Do not implement an OpenVPN adapter from the `OpenVPNClient` name alone; first prove the protected class uses the OpenVPN wire protocol and recover its launch/configuration contract.
- [ ] Implement additional mode adapters only for modes confirmed by evidence.
- [ ] Ensure each adapter has bounded startup, process ownership, readiness checks, health supervision and reliable cleanup.
- [ ] Do not let a UI state say CONNECTED until the engine's real handshake and routed egress checks pass.

### D. End-to-end validation and release

- [x] CI validates decoder, source transport mocks, existing Windows packaging and runtime safety.
- [ ] Verify live updater refresh without disclosing catalog secrets.
- [ ] Validate generated profiles against authorized APNA endpoints.
- [ ] Test on Windows 10 and Windows 11 with a real tunnel handshake.
- [ ] Verify IPv4, IPv6, DNS, route ownership, reconnect, crash recovery and disconnect cleanup.
- [ ] Only then enable APNA Connect in the product UI and publish a release candidate.

## 5. Acceptance criteria

APNA compatibility is considered implemented only when all are true:

1. A fresh provider response is fetched and decoded successfully with strict size/schema handling.
2. Android-equivalent server/payload selection produces a valid engine configuration without guessed fields.
3. The correct engine starts and confirms a real handshake.
4. Windows traffic is routed through the tunnel; IPv4/IPv6/DNS behavior matches the intended policy.
5. Unexpected engine exit and disconnect restore routes, DNS and adapter ownership safely.
6. The same flow passes on supported Windows 10/11 systems.

Green unit tests, a successful build, or an artifact upload are necessary engineering checks but do not satisfy these acceptance criteria.

## 6. Current release decision

**Do not advertise APNA server connectivity yet.** The embedded catalog decode and discovery-only source are useful verified milestones, but profile generation and live Windows connectivity remain blocked on Android runtime reconstruction and real endpoint validation.


## 7. Windows CI evidence update — 2026-11-16

The following results are from the Windows/native workflow executions on this branch. They are build and local-runtime evidence only; they do not establish compatibility with an APNA provider endpoint.

- Native BadVPN workflow run [43888482478](https://github.com/meicamghe/ApnaWin/actions/runs/43888482478) completed successfully. It compiled `badvpn-tun2socks.exe` and `badvpn-udpgw.exe`, verified x64 PE headers and CLI startup, and uploaded artifact `apnawin-badvpn-windows-x64`.
- Artifact SHA-256: `d07e778fc6f2bcdb5801e55b4315e06997d95375c0b517d96c3fdb6c92651168`. The archive contains both executables, the BadVPN license, and a manifest pinning upstream repository `ambrop72/badvpn` at commit `07268f02706e78e282e19641b5d1d41e8e89bf31`. This build uses MinGW-w64 x86_64. The binaries are not yet integrated into the product tunnel path; upstream TUN uses TAP-Windows, not the product's Wintun adapter.
- Windows workflow run [43888482419](https://github.com/meicamghe/ApnaWin/actions/runs/43888482419): VPN readiness/egress checks, Ruff and installer/runtime security tests passed. The unit/integration job reported **1 failed, 1121 passed, 1 skipped**. The single failure was an inconsistent assertion in `test_cf_and_brand_catalog_tokens_are_expanded_before_rotation`: its input contains `[host]`, while its expected bytes incorrectly included an additional `:443` value. The implementation and other payload tests define `[host]` as hostname-only and `[host_port]`/`[ssh]` as host-plus-port.
- The current branch test now explicitly covers both `[host]` (hostname only) and `[host_port]` (hostname plus port) in the same formatted payload. The original failing run used an earlier revision; a fresh CI result for the corrected test is still required.
- Windows packaging reached a successful application/helper/runtime build and smoke test, but the artifact upload step was cancelled. No Windows application artifact from run `43888482419` is available for release.

**Next gates:** rerun the full Windows test/package workflow against the current branch revision; confirm a downloadable portable application artifact; integrate a verified provider-compatible transport into the Xray/Wintun path; then perform authorized APNA server authentication and real routed TCP/UDP/DNS tests on Windows 10/11. Until those gates pass, APNA connectivity remains unverified.


## 8. CI trigger correction — 2026-11-16

The Windows validation workflow now supports manual dispatch and push-triggered validation on `vpn/dual-stack-egress-readiness`, in addition to pull requests targeting `main`. This makes subsequent branch commits run the full Windows lint, test, security, VPN-readiness and packaging tracks. A trigger configuration change alone is not a passing test result; the new run must be inspected before treating the branch as green.
