# APNA TUNNEL LITE upstream protocol evidence

## Scope and source

This note records externally published reverse-engineering findings and direct, local APK observations for the exact Android application:

- Display name: APNA TUNNEL LITE
- Package: `com.apnatunnel.lite`
- APK metadata reported by the analysis: versionCode 51, versionName `APNA`
- External analysis repository: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM
- Decoder source: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/main/decoders/Python/apps/APNA_Tunnel_Lite/APNA_Tunnel_Lite.py
- Decoder notes: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/main/decoders/Python/apps/APNA_Tunnel_Lite/README.md
- External analysis report: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/main/analysis/platform/supplied-integrations/2026-11-14/ANALYSIS.md

These are third-party reverse-engineering sources, not official provider documentation. Their claims are leads to validate against the local APK and fresh responses. The external repository's own result report distinguishes structural integration tests from authenticated/live provider connection tests.

## Local APK observations (2026-11-16)

The existing Library APK was materialized and inspected without executing it:

- APK SHA-256: `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`
- `assets/janur.json`: 366,636 bytes; SHA-256 `1e69333f038cba74fb559c6a791ec5d29c2f3ad69f29adefc6eb58f36c3a472d`
- The archive contains `classes.dex` and `assets/.bxdtcxfzx.dex` (99,335 bytes).
- The primary DEX contains an `OpenVPNClient` type/string reference, but that descriptor is not defined among the primary DEX class definitions.
- The small secondary DEX asset exposes only a minimal LIAPP-related class stub in its DEX string/class tables; it does not expose the protected OpenVPN implementation as readable strings.

### Embedded catalog successfully decoded

The published decoder's exact key literal, `b"...|..."`, is **not** a placeholder for this APK sample. Applying the published Base64 + modified-XXTEA algorithm, delta `0x9E5729B1`, little-endian words and final-word plaintext length to the local `assets/janur.json` produces valid UTF-8 JSON. The result matches the independently reported embedded-catalog fingerprint:

- `Version`: `580`
- `Free_servers`: 44 records
- `Payloads`: 623 records
- `Premium_servers`, `Vip_servers`, and `Private_servers`: empty arrays

The JSON has top-level `Username` and `Password` values. They are credentials and must never be printed, logged, committed, placed in fixtures, or included in CI artifacts. Only redacted metadata was inspected.

The embedded record shapes are consistent across this sample:
- Each free-server record has string fields: `server_name`, `server_host`, `server_port`, `server_udp_port`, `ssl_port`, `category`, `username`, `password`, and `custom_cert`.
- Each payload record has string fields: `friendly_name`, `category`, `host`, `port`, `method`, `payload`, `query`, `sslws`, `sausage`, `dothost`, and `message`.
- The sample uses payload methods `http`, `ssl`, `udp`, and `direct`. The `ocsws` category contains both HTTP and SSL records; `ocscf` records are HTTP, `ocsudp` records are UDP, while `ocsshadow` records are direct and the `ocstrojanworker`, `ocsxray`, and `ocsv2ray` records are SSL. These labels are useful clues, not proof of the underlying tunnel engine.
- The payload port field contains the literal `Pulled` in many records. Its runtime meaning and substitution rules still need to be traced.
- `server_host` can contain a semicolon-delimited host pool rather than one hostname. In this APK sample, 26 of 44 server records contain multiple hosts.
- Only 16 of 44 free-server records have non-empty `server_port`, `server_udp_port`, and `ssl_port` values; the other 28 have all three blank. The app's rules for resolving the effective endpoint/port therefore matter.
- Server and payload category values overlap, which is evidence that the app associates records by category. The exact selection, fallback and connection logic remain to be verified.

This is a successful decode of the embedded APK asset, not yet a fresh live updater-response test and not proof that any listed endpoint currently accepts a connection. XXTEA here is obfuscation, not authenticated encryption; parsed JSON must still be treated as untrusted input.

## Evidence reported by the external analysis

The external decoder documents the following catalog pipeline:

1. A GET request to the fixed Lite updater URL:
   `https://paperonboard.com/updater/6aa1acd5d8b2b25e6884eae4483e57`
2. Request headers reported as:
   - `User-Agent: Dalvik/2.1.0`
   - `Accept-Encoding: identity`
3. Remove whitespace from the response body, decode standard Base64, then decrypt the modified XXTEA envelope.
4. The reported XXTEA delta is `0x9E5729B1`; words are little-endian 32-bit values and the final word stores the original plaintext length.
5. The decoded UTF-8 document is JSON. The top-level `Version` field is a string, and `Free_servers` and `Payloads` are arrays. The report also names optional `Premium_servers`, `Vip_servers`, and `Private_servers` arrays.
6. The APK's embedded catalog asset is `assets/janur.json`.

The external README reports a live catalog observation dated 2026-11-13 (version v850, 50 free servers and 644 payloads) and an embedded APK observation (v580, 44 free servers and 623 payloads). These are historical observations, not current availability guarantees.

The external analysis identifies an `OpenVPNClient` class. Direct inspection of the supplied APK shows that this descriptor is referenced but not defined in the primary DEX; the primary DEX instead defines a substantial `prince.open.vpn.service.vpn` stack built around Android `VpnService`, `TunnelVpnManager`, SSH management, `Tun2Socks`, and local DNS components. The name `OpenVPNClient` therefore must **not** be treated as proof of the OpenVPN wire protocol. See [Android runtime static analysis](apna-lite-android-runtime-analysis.md). Protected/dynamically loaded selection code remains to be recovered.

## Implementation decisions for ApnaWin

- The embedded catalog decoder is now reproducible for the supplied APK sample. Port the algorithm into a provider-specific module with strict bounds and schema validation; keep the key isolated from logs and never expose decoded credential fields to diagnostics.
- Keep the existing provider-neutral refresh coordinator and normalized catalog model. The upstream JSON is a provider-specific source format; adapt it only after the server/payload association and profile generation rules are established.
- Implement the APNA-specific HTTP provider using normal TLS certificate validation, finite connect/read timeouts, strict response-size limits, redirect rejection, and bounded retry/resume behavior. The reported request headers are a testable hypothesis for live requests; verify them before relying on them.
- Keep raw decrypted catalog content and all connection credentials out of logs, crash reports, screenshots, CI artifacts, fixtures, and committed files. Tests should use synthetic data and redacted metadata only.
- Never interpret `Free_servers` or `Payloads` as directly connectable profiles until their fields and the app's selection/combination logic are verified.
- Investigate the Android SSH + custom-payload + Tun2Socks path, Xray helper path, UDP forwarding path and direct mode separately, in parallel with the existing Windows TUN/route/DNS safety work. Do not remove Xray code or claim a category-to-engine mapping based solely on names.
- A green CI run can validate parsing, transport boundaries, process supervision and cleanup; it cannot certify that APNA accepts the generated profile. A real connection claim requires an authorized APNA profile, a Windows 10/11 run, successful tunnel handshake, verified routed traffic, DNS/IPv4/IPv6 checks and clean disconnect.

## Next evidence gates

1. Port the decoder and verify it against the embedded APK fixture using synthetic test keys/fixtures only; no real catalog credentials in tests.
2. Fetch a fresh bounded updater response using the reported headers and compare its decoded schema/counts without logging or storing secret fields.
3. Trace the app's server/payload category matching and selection logic, including the meaning of `Pulled`, `sslws`, `sausage`, and `query`.
4. Recover the exact runtime mode for each supported category, including SSH authentication/payload injection, Xray helper configuration, UDP gateway framing and direct-mode semantics.
5. Implement provider-specific normalization and the relevant Windows engine adapter(s) behind the existing `TunnelEngine` contract, with synthetic fixtures first.
6. Perform authorized Windows 10/11 end-to-end tests before enabling APNA Connect in the UI.

The catalog decryption gate is passed for the embedded APK. Live refresh, profile-generation semantics and Windows end-to-end connection remain unverified.
