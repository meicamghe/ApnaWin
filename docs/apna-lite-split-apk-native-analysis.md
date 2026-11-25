# APNA TUNNEL LITE v51 split APK and native-library analysis

**Input archive:** user-provided `APNA-APKs.zip`  
**Archive SHA-256:** `693749cf63c3363d21fe78cd52eb970bd0e45a67d1493e99958781c706107130`  
**Inspection:** offline ZIP integrity, binary AndroidManifest.xml parsing, ELF headers/dependencies/exports, Go build metadata and static strings. No APK or native library was executed.

## 1. Archive and package identity

The ZIP contains six APKs: one base APK, one ABI split, three language splits and one density split. `ZipFile.testzip()` returned no corrupt member.

| APK member | Size (bytes) | SHA-256 |
|---|---:|---|
| `base.apk` | 20,419,648 | `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d` |
| `split_config.arm64_v8a.apk` | 22,193,156 | `deedea9fa7fc05da53dac8b904ba9f843f72535c455bbce0ed7f5e52e56c9b64` |
| `split_config.de.apk` | 33,177 | `63ff78ff9bc46451a1ed68eacc86f81e18ac9e15a0b13763fc164421a082d6ff` |
| `split_config.en.apk` | 57,753 | `f1ae44b8d1d733fbbd8036d5cf586358259aa5cb3e6adb5745274fa7ee1da07f` |
| `split_config.fa.apk` | 37,273 | `c6b0f8f184da69adb5abc524565959d6ba4f37e10b6250bbf31f05c10a936632` |
| `split_config.xxhdpi.apk` | 162,872 | `c472f7d7b798c856a5d724b8b1a39cbc8d2429fdc3223fae794a4de789534403` |

The base APK hash exactly matches the previously analyzed v51 sample; this ZIP supplies the previously missing ABI split rather than a different base release.

Decoded base manifest metadata:
- Package: `com.apnatunnel.lite`
- `versionCode=51`, `versionName=APNA`
- `minSdkVersion=24`, `targetSdkVersion=36`
- `application` class: `com.liapp.x`
- Declares `TunnelVpnService` with `android.permission.BIND_VPN_SERVICE`.
- Declares service descriptors `SalamanderService`, `PInjectorService`, `SocksDNSService`, `XRayDNSService` and a proxy service. The service descriptors alone do not reveal their protected implementations or category-selection logic.

The ABI split contains nine ELF shared libraries, all under `lib/arm64-v8a/`. No x86 or x86_64 native split is present in this archive. APK signature-related META-INF entries are present, but this static inspection did not cryptographically verify the APK signing certificate.

## 2. Native library inventory

All nine libraries identify as ELF64 / AArch64.

| Library | Size (bytes) | SHA-256 (prefix) | Static identification |
|---|---:|---|---|
| `libbxdtcxfzx.so` | 688,364 | `5f07e0de11d59bf6` | JNI library; exports `JNI_OnLoad`; opaque/obfuscated purpose |
| `libdatastore_shared_counter.so` | 7,112 | `d3e48717c9aa147e` | AndroidX DataStore native shared-counter JNI functions |
| `libpdnsd.so` | 215,632 | `e5e7cfa0488a1a9f` | pdnsd 1.2.9a-par DNS proxy/cache |
| `libputils.so` | 3,193,912 | `5bf2023360f8ed31` | Native utility library with OpenSSL and archive/ZIP symbols |
| `libsalamander.so` | 8,352,128 | `8c31a6010807bde1` | Go native binary; SSH protocol structures and client/server version strings |
| `libtoolChecker.so` | 5,512 | `8b8e358b836ce358` | RootBeer root-detection JNI functions |
| `libtun2socks.so` | 160,232 | `60564578b9a1c164` | BadVPN tun2socks 1.999.127 |
| `libudpqtwo.so` | 17,924,504 | `a3dea2c032fe01cf` | Go native binary; QUIC, DTLS, SOCKS5 and HTTP-proxy code signatures |
| `libxray.so` | 32,740,552 | `e796e24eece84ab2` | Xray-core Go executable |

Full SHA-256 values:
- `libbxdtcxfzx.so`: `5f07e0de11d59bf6e0d67c655330ab23e838daeec7c32622d7c9a29e67ef070b`
- `libdatastore_shared_counter.so`: `d3e48717c9aa147e0ab21063ba0e8e0211cabf8bf40b222640829519edbf58e1`
- `libpdnsd.so`: `e5e7cfa0488a1a9faf93a294c865f3ece1675183aa03f1c36cc16c390992c43c`
- `libputils.so`: `5bf2023360f8ed317890cd165c0d98f00d948076b1d836e70fd07e913f2e61ab`
- `libsalamander.so`: `8c31a6010807bde170d237119ea98187855e03f2e853b437ca8ce05b3f571ab5`
- `libtoolChecker.so`: `8b8e358b836ce35835d40bc0bc1b935c34633e535eb7c7642c9762e2f27cb683`
- `libtun2socks.so`: `60564578b9a1c164fd8f27288d84fa04851a122b12e5ff16d72378ee69526b4e`
- `libudpqtwo.so`: `a3dea2c032fe01cf335246a53e0b5d0035acc64cca3e66c67ba64fd46baa47b3`
- `libxray.so`: `e796e24eece84ab28ab9e20710a8581fbcb1044c6720db5f9c79fecc839f68b5`

## 3. Important protocol/runtime evidence

### 3.1 Salamander is an SSH implementation candidate

`libsalamander.so` exports Go `main.main` and contains SSH wire-protocol structures, `ClientVersion`, `ServerVersion`, SSH packet/MAC error strings, channel and authentication-related types. This is strong evidence that the protected Salamander service has a native Go SSH implementation available in the ARM64 split.

It does **not** reveal the full service contract: host/port selection, username/password/key handling, host-key verification, payload socket handoff, local SOCKS bind address, keepalive or reconnect policy remain unconfirmed. Static strings are not a substitute for a runtime trace or method-level call graph.

### 3.2 tun2socks is exactly BadVPN-compatible and includes UDPGW

The native library reports `BadVPN tun2socks 1.999.127` and contains:
- `SocksUdpGwClient`
- `--socks-server-addr`
- `--udpgw-remote-server-addr`
- `--udpgw-transparent-dns`
- UDPGW connection and packet handling strings.

This independently corroborates the existing DEX evidence for a SOCKS + optional UDPGW TUN forwarding design. The Android binary itself is AArch64 and is not a Windows executable.

### 3.3 The bundled pdnsd is IPv4-only

The pdnsd binary identifies as `1.2.9a-par` and explicitly contains runtime/build messages stating that it was compiled without IPv6 support; IPv6-only options are ignored and its IPv4/IPv6 mode is unavailable. This is a real limitation of this DNS helper build. It does not by itself prove that the outer Android TUN or every other resolver path is IPv4-only.

For ApnaWin, do not copy this helper's limitation into the Windows DNS design. Preserve the Windows dual-stack DNS/e-gress checks and test provider DNS behavior separately.

### 3.4 Xray is a full Xray-core binary, not a guessed protocol label

`go version -m` identifies `libxray.so` as `github.com/xtls/xray-core/main`, built with Go 1.26.2 for Android/ARM64. Module metadata includes Xray Reality, QUIC, sing/Shadowsocks and WireGuard dependencies. Binary strings include Xray package/config symbols for VLESS, VMess, Trojan, Shadowsocks, WireGuard, Hysteria, SOCKS and HTTP.

This establishes that the bundled Xray runtime contains code for these families. It does **not** prove APNA maps any specific catalog category to one of them or that every feature is enabled in the app's UI. The Go build metadata also reports a modified working tree and an old VCS timestamp; do not treat that timestamp as a reliable release date.

### 3.5 udpqtwo remains unidentified at the product-protocol level

`libudpqtwo.so` is a large Go/ARM64 binary. Static strings show QUIC, Pion DTLS, SOCKS5 request/datagram types, HTTP proxy/goproxy, transparent-proxy interfaces, DNS and configuration libraries. Its Go module build information is unavailable through `go version -m`, and its protected service call sites were not reconstructed here.

It is therefore a candidate for one of the protected proxy/UDP services, but this inspection does not justify calling it Hysteria, TUIC, a particular UDP protocol, or assigning it to `SocksDNSService` / `PInjectorService`. That requires runtime/service binding evidence.

## 4. Consequences for ApnaWin

1. The protected SSH service is no longer an entirely unknown black box: the complete split set contains a native Go SSH implementation candidate named `libsalamander.so`. The next task is to recover its JNI/service entry points and the settings passed from the app, without bypassing LIAPP protections.
2. The DEX + native library evidence independently confirms BadVPN-style tun2socks and UDPGW. ApnaWin's separate UDPGW codec/flow tests are aligned with the observed protocol family, but real endpoint interoperability is still unproven.
3. The Android pdnsd build is IPv4-only. Windows must retain its own strict dual-stack DNS implementation and validate it against real provider behavior.
4. The Android Xray binary contains a broad protocol set. Keep the existing explicit Xray share-link adapters, but do not auto-map APNA catalog categories until the protected selector and service configuration are traced.
5. The native binaries are Android/ARM64 only. They cannot be copied into the Windows x64 package; use the findings to guide native Windows-compatible implementations and test contracts.
6. Do not infer a product protocol from `libudpqtwo.so`'s filename. Its exact purpose remains an open reverse-engineering item.

## 5. Remaining evidence gates

- [ ] Trace the protected service calls that load/start `libsalamander.so`; determine arguments, local listeners, authentication and host-key behavior.
- [ ] Identify the `libudpqtwo.so` exported entry points and which manifest service owns it.
- [ ] Recover APNA category/payload-to-service selection using an authorized runtime trace or redacted service configuration.
- [ ] Verify whether `libpdnsd.so` is actually selected in the active v51 path and how the app handles IPv6 DNS.
- [ ] Run an authorized APNA profile on Windows 10/11 and verify SSH handshake, UDPGW datagram round-trip, routed TCP/UDP, DNS, IPv4/IPv6 egress and cleanup.

No credentials, decoded catalog content, server hostnames or private payloads are included in this analysis.


## 6. ApnaWin non-SSH protocol implementation update — 2026-11-24

The active Windows branch now uses the pinned Xray 26.11.9 runtime for the independently validated outbound families below. This is a runtime/configuration compatibility statement, not evidence that a particular APNA catalog category selects the same protocol.

| Xray outbound / transport | ApnaWin import path | Boundary |
|---|---|---|
| VLESS | Standard share link | TCP, WS, gRPC, HTTPUpgrade, XHTTP, mKCP; TLS/REALITY constraints validated |
| VMess | Standard Base64 JSON share link | AEAD-only; supported transports validated |
| Trojan | Standard share link | TLS/REALITY and supported transports |
| Shadowsocks | SIP002 share link | Supported AEAD and 2022 ciphers; SIP003 plugins rejected |
| Hysteria 2 | `hysteria2://` / `hy2://` | TLS verification required; unsupported obfuscation/ECH/pinning options rejected |
| WireGuard | Standard `.conf` file | Multiple peers, keys, addresses, DNS, MTU and AllowedIPs |
| MASQUE | Single Xray MASQUE outbound JSON | CONNECT-IP over verified TLS with HTTP/2 or HTTP/3 ALPN; no Mux |
| HTTP proxy | `http://` / `https://` URI | TCP only; plaintext HTTP is not encrypted |
| SOCKS5 proxy | `socks://` / `socks5://` URI | TCP only; not a standalone encrypted VPN |
| XHTTP | Xray VLESS/VMess/Trojan link | Bounded extra headers, padding, XMUX and verified-TLS downloadSettings |
| mKCP | Xray link `type=kcp` / `type=mkcp` | Current kcpSettings and legacy `mkcp-legacy` UDP FinalMask translation |

The pinned-runtime CI job executes `xray run -test` against generated configs for the new outbound and transport cases. The full unit suite and all five CI jobs passed on the implementation commit; this does not replace an authenticated connection to a real endpoint.

Xray's local-only outbounds such as `freedom`, `blackhole`, DNS and `loopback` are not exposed as selectable remote VPN profiles. In particular, a direct/freedom outbound would violate ApnaWin's full-tunnel no-leak policy.

### 6.1 Remaining native-library evidence gate

`libudpqtwo.so` remains a QUIC/DTLS/SOCKS5/HTTP Go binary candidate, not a proven named protocol. Its product-level role and owning Android service are still unknown. The static evidence available here does not include a recovered Go call graph, owning service entrypoint, protocol handshake contract or an authorized runtime trace. It therefore does not justify relabeling it as TUIC, Hysteria, or another protocol, nor implementing a guessed server wire format.

The Android ABI split supplies ARM64 libraries only; those binaries cannot be reused in the Windows x64 application. The implemented Hysteria 2 and MASQUE paths cover documented Xray QUIC-based tunnel protocols, but they are not asserted to be the private `libudpqtwo.so` protocol.

To close this last reverse-engineering item, collect a fresh authorized trace of the Android service that loads/starts `libudpqtwo.so` (method arguments, service ownership, socket setup and handshake metadata) or provide the exact ARM64 split archive in an accessible project source. No LIAPP bypass or automatic APNA category mapping is authorized by this evidence.

## 7. Reconciliation of the UDPQ source-lineage evidence

The separate `docs/libudpqtwo-linux-triage.md` records a stronger cross-sample comparison: APNA's ARM64 `libudpqtwo.so` and UDP Thunder 1.5's ARM32 binary contain matching StarUDP-style Go wire-structure names, serialization tags and client-config JSON tags. This supports a **StarUDP/Hysteria-v1-derived implementation lineage** as the leading static hypothesis for the binary's networking code.

That finding does not conflict with the product-level boundary in section 6.1:

- **Supported by static evidence:** the binary embeds a distinctive protocol/config structure fingerprint matching the pinned public StarUDP source family.
- **Not established:** whether APNA invokes this binary for a user-selectable VPN mode, which Android service owns it, whether the binary was modified beyond the matching structures, or which ALPN, SNI, credentials, rates, packet mode, obfuscation and port-hopping values APNA supplies.
- **Not demonstrated:** a successful handshake with an authorized APNA server or real routed TCP/UDP/DNS traffic using this binary's settings.

Accordingly, ApnaWin's StarUDP-derived Windows sidecar remains an experimental reference implementation. Do not map APNA catalog categories to it or label it as APNA-compatible until the protected launch/configuration contract and an authorized live-server handshake are independently verified. The LIAPP-protected DEX remains out of scope for bypass; ordinary service/process diagnostics are the next acceptable evidence source.
