# APNA TUNNEL LITE upstream protocol evidence

## Scope and source

This note records externally published reverse-engineering findings for the exact Android application:

- Display name: APNA TUNNEL LITE
- Package: `com.apnatunnel.lite`
- APK metadata reported by the analysis: versionCode 51, versionName `APNA`
- External analysis repository: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM
- Decoder source: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDMDM/blob/main/decoders/Python/apps/APNA_Tunnel_Lite/APNA_Tunnel_Lite.py
- Decoder notes: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDMDM/blob/main/decoders/Python/apps/APNA_Tunnel_Lite/README.md
- External analysis report: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDNDMDM/blob/main/analysis/platform/supplied-integrations/2026-11-14/ANALYSIS.md

These are third-party reverse-engineering claims, not official provider documentation. They are leads to validate against the APK already held in the project Library and against fresh responses. The external repository's own result report explicitly distinguishes structural integration tests from authenticated/live provider connection tests.

## Local APK observations (2026-11-16)

The existing Library APK was materialized and inspected without executing it:

- APK SHA-256: `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`
- `assets/janur.json`: 366,636 bytes; SHA-256 `1e69333f038cba74fb559c6a791ec5d29c2f3ad69f29adefc6eb58f36c3a472d`
- The archive contains `classes.dex` and `assets/.bxdtcxfzx.dex` (99,335 bytes).
- The primary DEX contains an `OpenVPNClient` type/string reference, but that descriptor is not defined among the primary DEX class definitions.
- The small secondary DEX asset exposes only a minimal LIAPP-related class stub in its DEX string/class tables; it does not expose the protected OpenVPN implementation or the catalog key as readable strings.

These observations are structural only. They do not reveal the embedded catalog plaintext or prove which connection path the app selects at runtime.

## Evidence reported by the external analysis

The external decoder documents the following catalog pipeline:

1. A GET request to the fixed Lite updater URL:
   `https://paperonboard.com/updater/6aa1acd5d8b2b25e6884eae4483e57`
2. Request headers reported as:
   - `User-Agent: Dalvik/2.1.0`
   - `Accept-Encoding: identity`
3. Remove whitespace from the response body, decode standard Base64, then decrypt a modified XXTEA envelope.
4. The reported XXTEA delta is `0x9E5729B1`; words are little-endian 32-bit values and the final word stores the original plaintext length.
5. The decoded UTF-8 document is JSON. The top-level `Version` field is a string, and `Free_servers` and `Payloads` are arrays. The report also names optional `Premium_servers`, `Vip_servers`, and `Private_servers` arrays.
6. The APK's embedded catalog asset is reported as `assets/janur.json`.

The external README reports a live catalog observation dated 2026-11-13 (version v850, 50 free servers and 644 payloads) and an embedded APK observation (v580, 44 free servers and 623 payloads). These are historical observations, not current availability guarantees.

The external analysis identifies an `OpenVPNClient` class and reports that its implementation resides in a secondary LIAPP-protected DEX. This makes OpenVPN a strong investigation lead for the Windows engine, but it does **not** establish the complete profile schema, authentication behavior, OpenVPN directives, certificate/key handling, or compatibility of a Windows OpenVPN binary. Do not treat the class name alone as an end-to-end protocol specification.

## Critical decoder limitation

The published Python decoder currently contains:

```python
KEY = b"...|..."
```

That is visibly a placeholder, not a usable production key. Therefore, the published script must **not** be copied into ApnaWin as a working decryptor, and its reported algorithm parameters do not yet make the live catalog decryptable. The key must be recovered independently from the APK's protected code or another authorized source, then verified against the APK's embedded `assets/janur.json` and a fresh response.

Do not guess, brute-force, hard-code a fabricated key, or silently accept undecoded bytes. A decoder must fail closed until a verified key is available.

## Implementation decisions for ApnaWin

- Keep the existing provider-neutral refresh coordinator and normalized catalog model. The upstream JSON is a provider-specific source format; it must be adapted into the internal model only after the real record schema has been established.
- Add an APNA-specific HTTP provider only after its request behavior has been independently checked. If implemented, use normal TLS certificate validation, finite connect/read timeouts, strict response-size limits, redirect rejection, and bounded retry/resume behavior. Do not disable TLS verification.
- Keep raw decrypted catalog content and all connection credentials out of logs, crash reports, screenshots, CI artifacts, fixtures, and committed files. Tests should use synthetic data and redacted metadata only.
- Never interpret `Free_servers` or `Payloads` as directly connectable profiles until their fields and the app's selection/combination logic are verified.
- Investigate OpenVPN as the first provider-specific engine candidate in parallel with the existing Windows TUN/route/DNS safety work. Do not remove Xray code or claim Xray compatibility based solely on APK library names.
- A green CI run can validate parsing, transport boundaries, process supervision and cleanup; it cannot certify that APNA accepts the generated profile. A real connection claim requires an authorized APNA profile, a Windows 10/11 run, successful tunnel handshake, verified routed traffic, DNS/IPv4/IPv6 checks and clean disconnect.

## Next evidence gates

1. Recover and independently verify the real XXTEA key from the protected APK code; confirm decryption of the embedded catalog without exposing its secrets.
2. Compare the embedded catalog schema with a fresh, bounded updater response; record only field names, types, counts and redacted examples.
3. Trace the app's server and payload selection logic to determine how a server record and payload become an OpenVPN configuration or other connection request.
4. Recover the exact OpenVPN launch/configuration contract, including authentication and certificate requirements, from authorized APK analysis.
5. Implement provider-specific normalization and an OpenVPN engine adapter behind the existing `TunnelEngine` contract, with synthetic fixtures first.
6. Perform authorized Windows 10/11 end-to-end tests before enabling APNA Connect in the UI.

Until gates 1–4 are complete, the APNA provider remains discovery-only and no APNA-compatible connection profile may be fabricated.
