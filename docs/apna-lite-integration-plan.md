# APNA TUNNEL LITE integration plan

**Status:** discovery and embedded-catalog decoding are implemented; live provider refresh, runtime semantics and APNA tunnel connection are not yet release-ready.

**Target application:** APNA TUNNEL LITE, Android package `com.apnatunnel.lite`.

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
- [x] Identify custom-payload formatter and CR/LF/SSH placeholder token references; the primary DEX exposes `[instant_split]` and `[delay_split]`, not the sibling source's `[split]` token.
- [x] Record server and payload fields, methods, categories and ambiguous values.
- [ ] Trace server/payload category matching and selection/fallback rules.
- [ ] Recover the Android SSH + payload-injection contract and local forwarding topology.
- [ ] Recover the Xray helper and UDP gateway contracts separately; DEX evidence now points to a BadVPN-style UDPGW stream, distinct from the TCP SOCKS path. The inspected BadVPN tree includes `udpgw_client` in the `tun2socks` target and has Windows socket backends, despite an older changelog note; verify an actual Windows build and UDPGW session before deciding whether a port is needed.
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
