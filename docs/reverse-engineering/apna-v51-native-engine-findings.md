# APNA v51 native engines: evidence and completion gates

**Scope:** static analysis of the committed APNA v51 APK set and prior controlled reference-engine tests. This document separates facts established from binary/DEX evidence from hypotheses and live-provider acceptance. It does not authorize bypassing LIAPP, extracting credentials, or executing APK-native code in CI.

## Executive finding

The APNA v51 ARM64 split contains a file named `libudpqtwo.so` that is **not an ordinary JNI shared library**. The inspected file is an Android ARM64 Go PIE executable packaged with a `.so` suffix:

- ELF64, AArch64, `ET_DYN`, non-zero entry point `0x1be520`.
- ELF interpreter: `/system/bin/linker64`.
- No exported `JNI_OnLoad` or `Java_*` JNI entry points.
- Its Go build-info version is `unknown`, and the module-info string is empty.

The strongest protocol-family identification is **StarUDP / Hysteria-v1-derived QUIC**, based on matching Go wire-structure names, serialization tags, and JSON configuration-field fingerprints against the public StarUDP source. This is substantially stronger than a filename or dependency-only match, but it is not proof of APNA's exact source revision or live-server compatibility.

The readable primary DEX exposes separate `pdnsd` and `tun2socks` child-process paths. It does not expose the `libudpqtwo.so` launch site. LIAPP-protected secondary DEX content remains opaque and has not been bypassed. Consequently, the exact APNA service owner, process arguments, effective JSON config and credentials are still unknown.

## 1. Binary identity and protocol evidence

The prior direct comparison used these samples:

| Property | APNA v51 | UDP Thunder 1.5 reference |
|---|---:|---:|
| ABI | ARM64 / AArch64 | ARM32 / ARM |
| `libudpqtwo.so` size | 17,924,504 bytes | 17,206,308 bytes |
| SHA-256 | `a3dea2c032fe01cf335246a53e0b5d0035acc64cca3e66c67ba64fd46baa47b3` | `650a3b96995e3b4576157915e66e1ef50725090c0043a9c543b8c89de229d660` |
| Go build-info version | `unknown` | `unknown` |

Both binaries contain matching fingerprints for:

- Go types `clientHello`, `serverHello`, `clientRequest`, `serverResponse`, and `udpMessage`.
- Serialization tags such as `sizeof=Auth`, `sizeof=Host`, `sizeof=Message`, and `sizeof=Data`.
- Configuration keys including `server`, `protocol`, `auth`, `alpn`, `server_name`, `insecure`, `socks5`, `tun`, `up`, `down`, `obfs`, `fast_open`, and `lazy_start`.
- Dependencies/fingerprints including quic-go HTTP/3, Pion DTLS, txthinking SOCKS5, goproxy, routedns, and tproxy.

A previous broad Go string/function-token comparison found 5,175 common tokens out of 5,203 APNA tokens and 5,225 UDP Thunder tokens. This is a heuristic similarity result, not proof of identical source.

### Source-correlated protocol shape

The matching public StarUDP source uses control protocol version 3 and the following sequence:

1. QUIC over UDP with TLS 1.3 and a configured ALPN.
2. A control stream beginning with protocol version byte `3`.
3. A `clientHello` carrying upload/download rate values and authentication bytes.
4. A `serverHello` response indicating acceptance/rejection.
5. TCP forwarding over per-destination QUIC streams.
6. UDP forwarding using QUIC DATAGRAM messages, session IDs and fragmentation fields.

The public source defaults ALPN to `hysteria`, but that literal was not found in the APNA binary. **Do not assume APNA uses this default.** The exact ALPN, SNI, server/port, authentication bytes, packet mode, obfuscation and port-hopping settings remain unknown.

The source's struct tags and default big-endian `struc` serialization support a concrete candidate frame layout. That layout is source-correlated, not yet confirmed by an APNA packet capture.

## 2. DEX ownership and native linkage

The readable primary DEX inspection established:

- `prince.open.vpn.service.vpn.Pdnsd.run()` invokes `Runtime.exec` with a `libpdnsd.so` path and pdnsd arguments.
- `prince.open.vpn.service.vpn.Tun2Socks.run()` invokes `Runtime.exec` with `libtun2socks.so`, `sock_path` and `--udpgw-transparent-dns`.
- The primary DEX string pool inspected did not contain `libudpqtwo.so`, `udpqtwo`, `starudp` or `hysteria`.
- Readable `System.loadLibrary` references include `datastore_shared_counter`.
- LIAPP class `com.liapp.x` contains obfuscated `System.load` / `System.loadLibrary` call sites and encoded protected-DEX references.

**Interpretation:** pdnsd and tun2socks have readable primary-DEX process ownership. `libudpqtwo.so` has no exported JNI entrypoint and looks like a standalone PIE child executable. A protected LIAPP path is a plausible launch owner, but this has not been proven. Do not attribute UDPQ ownership to the pdnsd/tun2socks classes.

The protected secondary DEX must not be decrypted or bypassed. The acceptable next evidence is ordinary Android process/service diagnostics while APNA is used normally, plus the manifest and readable DEX from every committed split.

## 3. Other engine and protocol leads

| Component / lead | Evidence | Current conclusion |
|---|---|---|
| `libudpqtwo.so` | Go PIE + StarUDP/Hysteria-v1 wire/config fingerprints | High-confidence protocol-family identification; APNA runtime settings and owner unknown |
| `libtun2socks.so` | Explicit primary-DEX `Runtime.exec` call with SOCKS socket and UDPGW transparent-DNS arguments | Confirmed tun2socks child-process path |
| `libpdnsd.so` | Explicit primary-DEX `Runtime.exec` call with pdnsd arguments | Confirmed DNS-helper child-process path |
| `libudpq.so` | Seen in a separate UDP Thunder sample, not evidence of an APNA library | Keep separate; do not conflate with APNA's `libudpqtwo.so` |
| VLESS / VMess / Trojan / Shadowsocks / Hysteria2 | Generic Xray share-link parser/runtime support in ApnaWin | Implemented generic import/runtime protocol paths; not proof that APNA's protected app uses these exact backends |

Do not treat HTTP/SOCKS proxy modes, DNS helpers, tun2socks, or an Android VPN service as separate encrypted wire protocols. A complete protocol inventory requires correlating each actual engine/process with its transport and configuration.

## 4. Validation already performed versus APNA acceptance

A pinned public StarUDP reference client/server was previously tested in a loopback-only environment:

- QUIC handshake over UDP with TLS verification enabled.
- SOCKS5 TCP CONNECT relayed to a local HTTP server.
- SOCKS5 UDP ASSOCIATE relayed a UDP echo datagram over QUIC DATAGRAM.
- A Windows x64 reference client build and CLI help smoke test passed in an earlier PR workflow.

These tests validate the public reference implementation and the generic SOCKS5-to-Xray integration shape. They do **not** validate APNA credentials, APNA's ALPN/config values, or an APNA provider endpoint.

No APNA provider handshake, authenticated session, or routed APNA TCP/UDP/DNS traffic is claimed.

## 5. Required work to close the four outstanding items

### A. Complete `libudpqtwo.so` analysis

- Re-run extraction against the exact committed ARM64 split and record its current SHA-256.
- Inspect the entire Go pclntab/function table and moduledata using a fresh extracted artifact.
- Recover and compare Go function/type fingerprints against the pinned StarUDP source.
- Keep the suspected stomped-pclntab fallback guarded by exact candidate metadata; never disable general GoReSym validation.
- Inspect all imports, relocations, executable entrypoint, interpreter and dynamic dependencies.
- Report confidence per recovered symbol/function group; do not infer protocol fields solely from dependency strings.

### B. Resolve DEX-to-process ownership without bypassing LIAPP

- Inspect manifest and every readable DEX in base and split APKs.
- Correlate native library names, process execution APIs, service lifecycle, permissions and child-process paths.
- Use ordinary Android diagnostics on a test device during a normal APNA session to record process start/exit, parent-child relationship, service lifecycle and loader errors.
- Do not decrypt/bypass protected DEX, dump secrets, or infer ownership from co-presence.

### C. Complete the internal protocol inventory

- Inventory every `lib/<abi>/*.so` across all APK splits, not just `libudpqtwo.so`.
- Classify each file as JNI library, standalone PIE executable, helper binary, or unknown using ELF headers, interpreter, entrypoint, exports and DEX/process references.
- Correlate protocol-family fingerprints with code paths and configuration sources.
- Distinguish confirmed protocols from dependency-only candidates and generic Xray capabilities.

### D. Run real acceptance for each discovered engine

For each engine, record the exact app version, APK hashes, device/Android version, process evidence, transport metadata and redacted diagnostics. On an authorized test account/server only, verify authentication/handshake, TCP, UDP, DNS, IPv4/IPv6 behavior, disconnect and abnormal-process cleanup. A loopback test is not provider acceptance.

This final gate requires an ordinary APNA session on an Android test device and an authorized APNA endpoint/account. Static repository analysis cannot manufacture those runtime facts.

## Safety and project constraints

- Never bypass LIAPP or extract protected credentials.
- Never execute the Android native binaries in CI.
- Never contact third-party endpoints without authorization.
- Do not enable Connect or route/DNS/TUN activation based on static fingerprints.
- Do not start a new Windows build until APK reverse engineering is complete.
- PR #8 remains open and must not be merged without explicit user approval.
