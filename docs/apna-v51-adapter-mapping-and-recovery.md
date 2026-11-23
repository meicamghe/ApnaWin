# APNA v51 service-to-Windows adapter evidence matrix

**Updated:** 2026-11-18  
**Scope:** `com.apnatunnel.lite` v51, supplied six-APK split set, and the ApnaWin Windows implementation.  
**Rule:** a native-library string, catalog category name, or Android service descriptor is not sufficient evidence to assign a protocol adapter.

## 1. Evidence summary

| Item | Confirmed evidence | Not yet established | Windows consequence |
|---|---|---|---|
| `libsalamander.so` | ELF64/AArch64 Go binary; Go `main.main`; SSH packet, MAC, channel, client/server-version and authentication-related symbols/strings | Exact exported ABI, JNI entrypoint, arguments, input/output channels, auth fields, host-key policy, listener address/port, payload handoff, keepalive and reconnect | Keep the current SSH adapter as a separately implemented protocol client; do not copy the ARM64 .so or claim byte-for-byte behavioral equivalence |
| `libudpqtwo.so` | ELF64/AArch64 Go binary; QUIC, Pion DTLS, SOCKS5 request/datagram, HTTP proxy, transparent-proxy and DNS code signatures | Owning Android service, exported entrypoints, protocol negotiation, wire format, config schema, whether QUIC/DTLS are active or just linked dependencies | No standalone UDP/QUIC adapter may be selected from this evidence alone |
| `libtun2socks.so` | BadVPN tun2socks 1.999.127; `SocksUdpGwClient`, `--socks-server-addr`, `--udpgw-remote-server-addr`, transparent-DNS option | Exact active invocation and all provider-side UDPGW settings | Confirms the Android TUN-to-SOCKS/optional-UDPGW topology; Windows implementation must retain its own Wintun-compatible backend |
| `libxray.so` | Go build metadata identifies Xray-core; binary contains VLESS, VMess, Trojan, Shadowsocks, WireGuard, Hysteria, SOCKS and HTTP code signatures | Which APNA categories select Xray and the protected config schema used by those services | Keep explicit Xray share-link import; do not infer APNA category mapping from protocol symbols |
| `libpdnsd.so` | pdnsd 1.2.9a-par build reports IPv6 support is absent | Whether this helper is selected in the active v51 path | Do not port its IPv4 limitation into Windows; keep dual-stack DNS and test real provider behavior |

All supplied native libraries are Android ARM64. None is a Windows x64 runtime.

## 2. `libsalamander.so`: input/output contract still to recover

The evidence supports the conclusion that Salamander is the SSH implementation used or intended by a protected APNA service. It does not expose a safe, complete callable contract.

The recovery worksheet is therefore:

| Boundary | Input to capture | Output/observable behavior | Current status |
|---|---|---|---|
| Service launch | Intent action/component, extras, Bundle values, service start/bind order | Started/bound service, lifecycle result | Service descriptor `SalamanderService` is referenced by DEX; implementation unavailable in visible primary DEX |
| Native loading | Library load call, class loader, JNI registration, symbol resolution | Loaded module, registered native methods | Go SSH evidence confirmed; exact loader/ABI unconfirmed |
| Configuration | Server host/port, username, password/key reference, payload bytes, TLS/SNI/proxy settings | Accepted/rejected config and normalized values | Unknown; do not log secrets |
| Socket handoff | Existing socket FD, local/remote endpoint, stream direction | SSH banner, key exchange, authenticated transport | Unknown |
| Local proxy | Bind address/port, SOCKS/HTTP mode, authentication | Listener lifecycle and accepted client sessions | Unknown |
| Session lifecycle | Keepalive interval, reconnect triggers, stop/cancel signal | State transitions, exit status, cleanup | DEX exposes start/stop/reconnect control methods; native service details unknown |

### Safe analysis sequence

1. Inspect ELF program headers, dynamic symbols, relocations, Go build metadata and all exported symbols; record exact tool versions and hashes.
2. Extract the manifest `application android:name` and every declared service class, then inspect those exact defined DEX classes for native method declarations and literal `System.loadLibrary`/`Runtime.load` arguments. The combined APK report wires both component lists into DEX analysis with a 128-service bound and class-code caching. This remains a targeted scan: it does not discover reflection, dynamic strings, `dlopen`, JNI registration, or process launches. Search DEX references to those paths and service launch extras/Binder calls separately; do not assume the filename is the library's load name.
3. Correlate service lifecycle events with library load and socket creation using an authorized test device and redacted logs.
4. Capture only metadata and protocol boundaries: argument types/lengths, socket endpoints, SSH banner/key-exchange milestones, listener lifecycle and exit codes. Never collect passwords, private keys, session tokens or decrypted private payloads.
5. Compare the observed behavior with ApnaWin's Paramiko implementation and add compatibility tests for confirmed semantics only.

The report exposes each declared service's resolved class, whether it is defined in DEX, its native-method count, and literal native-library load arguments found in that service class; the Application class is reported separately. A service declaring or loading a library is stronger static evidence, but does not by itself prove runtime ownership or invocation. Static string extraction alone cannot answer the input/output question. If no JNI or dynamic loader call is found, investigate whether the library is launched as a process or loaded by a protected component rather than inventing an ABI.

## 3. `libudpqtwo.so`: role and Android service ownership

The name `udpqtwo` is not a protocol specification. QUIC and DTLS symbols can be present because a binary statically links libraries even when a particular feature is unused.

Known service descriptors in the v51 manifest/DEX include `SalamanderService`, `PInjectorService`, `SocksDNSService`, `XRayDNSService`, and a proxy service. DEX helper methods explicitly target:
- `startSsh` → `SalamanderService`
- `startXRay` → `XRayDNSService`
- `startSocksHttp` → `SocksDNSService`

No equivalent proven binding currently assigns `libudpqtwo.so` to `PInjectorService`, `SocksDNSService`, or the proxy service.

Required evidence before assigning an adapter:
- exported symbol list and ELF init/fini behavior;
- exact DEX/native load references and service class ownership;
- process name, service start/bind lifecycle and native thread creation;
- redacted config keys and value types;
- outbound socket type and destination metadata (TCP/UDP/QUIC/DTLS);
- a successful protocol handshake and repeatable packet exchange.

Until then, classify it as **unidentified protected proxy runtime**, not Hysteria, TUIC, a generic UDP transport, or a proven SOCKS implementation.

## 4. APNA catalog categories versus runtime engines

The current ApnaWin SSH mapper admits exactly `ocsws`, `ocscf`, `ocsnormal`, and `ocshttp`, and requires server and payload category equality. It supports the payload methods `direct`, `http`, and `ssl`. This is an implemented, deliberately narrow compatibility rule; it is **not yet a fully verified reconstruction of the protected v51 category selector**.

| Catalog value/family | Current ApnaWin handling | Evidence status |
|---|---|---|
| `ocsws`, `ocscf`, `ocsnormal`, `ocshttp` | Candidate SSH + payload mapper; exact category-specific semantics still need live comparison | Implemented mapping; protected service/category selection not proven end-to-end |
| payload method `direct` | Direct socket to selected SSH server endpoint, then SSH | Implemented SSH socket mode; not Windows direct-internet/bypass |
| payload method `ssl` | TLS socket to configured payload/server endpoint, then SSH | Implemented TLS-direct SSH mode |
| payload method `http` | HTTP proxy/payload injection, optionally TLS-wrapped, then SSH | Implemented HTTP payload mode |
| payload method `udp` / category `ocsudp` | Rejected by SSH mapper | No standalone APNA UDP adapter verified |
| `ocsv2ray`, `ocsxray` | Not automatically mapped; user can import an explicit supported Xray share link | Xray-core exists in Android split; category/config contract unknown |
| `ocstrojan`, `ocstrojanworker` | Not automatically mapped | Trojan exists in Xray binary; APNA category mapping unknown |
| `ocsshadow` | Not automatically mapped | Shadowsocks exists in Xray binary; APNA category mapping unknown |
| Any other/unknown category | Must remain unsupported/visible-only | No evidence-based adapter assignment |

Important separation:
- Xray containing a protocol implementation does not prove that an APNA category selects it.
- A `udp` payload method does not prove the remote service is a standalone UDP tunnel; the observed tun2socks path separately supports an optional UDPGW stream.
- `UDP Connected` in UI strings is not proof of a successful UDPGW handshake.
- The existing UDPGW codec and stream path are an implementation based on the BadVPN PacketProto family, not proof of compatibility with a live APNA gateway.

## 5. Windows adapter inventory — implementation, not UI labels

| Windows component | Actual implementation | What it currently covers | Remaining gap |
|---|---|---|---|
| APNA SSH adapter | Paramiko SSH client, host-key verification, password/key auth, payload socket connector, loopback SOCKS5 TCP forwarder | SSH over direct/TLS/HTTP payload modes | Match Salamander's exact service contract and prove provider authentication |
| APNA UDPGW path | PacketProto/UDPGW codec, flow tracking, SOCKS5 UDP ASSOCIATE, UDPGW TCP stream through SSH `direct-tcpip` | UDP datagrams when the SSH server exposes a compatible UDPGW endpoint | Real datagram round-trip, provider flags/endpoint semantics, loss/rebind/keepalive behavior |
| Xray adapter | Xray share-link parser + Xray-core process + Wintun TUN supervisor | Explicit VLESS/VMess/Trojan/Shadowsocks links in supported modes | APNA catalog category-to-config mapping and live endpoint acceptance |
| Windows TUN | Wintun-backed Xray TUN and elevated lifecycle supervisor | Dual-stack routes, DNS and egress readiness checks | Clean-host Windows 10/11 end-to-end provider acceptance |
| BadVPN native build | Separate pinned-source Windows build artifact | Build/reference material only | Not integrated: upstream Windows TUN backend targets TAP-Windows, not this product's Wintun interface |
| `libudpqtwo` adapter | None | Nothing enabled | Must wait for service ownership and protocol handshake evidence |

No protocol should be added to the UI as supported until it has a real adapter, validated configuration, lifecycle cleanup and transport-specific tests.

## 6. Real Windows acceptance plan

Run only against a provider endpoint and account the user is authorized to test. CI is not a substitute for this plan.

1. Independently verify the SSH host key/fingerprint, then complete SSH authentication.
2. Record the SSH banner, negotiated algorithms and authentication result without recording credentials.
3. Verify loopback SOCKS5 CONNECT to a controlled TCP echo endpoint.
4. Open the configured UDPGW channel and verify a nonce-bearing UDP datagram round-trip; test multiple flow IDs, DNS flag, IPv4/IPv6 destination handling, keepalive, idle timeout and rebind.
5. Route a controlled TCP request and UDP request through Wintun; verify the observed public egress address is the expected provider egress.
6. Test DNS over UDP, TCP fallback if supported, IPv4 and IPv6 queries, and leak behavior while connected and during startup failure.
7. Disconnect normally, kill the UI/helper in separate runs, reboot, and verify no stale process, route, DNS override, Wintun adapter or firewall rule remains.
8. Repeat on a clean Windows 10 and Windows 11 host; attach redacted logs, OS/build, artifact SHA-256, test endpoint class and result.

Release remains blocked until these tests pass. Current GitHub CI validates code, test doubles, packaging and smoke startup; it does not demonstrate a real APNA account handshake or provider traffic.

## 7. Next execution order

1. Recover Salamander load/service/socket contract from DEX references plus authorized runtime traces.
2. Recover `libudpqtwo.so` service ownership and handshake before implementing any adapter.
3. Validate the current SSH category allow-list against redacted server/payload pairs and runtime selection observations.
4. Implement only confirmed adapters; keep Xray share-link support separate from APNA catalog conversion.
5. Execute the Windows acceptance plan and keep the release gate closed until evidence is attached.


### Static DEX loader-to-APK filename correlation

The combined report joins literal arguments from the exact JVM loader calls `System.loadLibrary`, `System.load`, `Runtime.loadLibrary` and `Runtime.load` (including DEX `/range` invocation forms) in manifest Application/Service classes to exact native-library basenames in the same APK. `loadLibrary` values are normalized to `lib*.so`; `load` paths contribute only their `.so` basename. Each row reports matching ABI directories and labels the evidence exact_filename_only. Missing filenames are reported as not_found, not inferred from engine-name substrings. This join does not prove that the loader executes, that the library initializes successfully, or that the service owns its runtime. JNI_OnLoad exports and native-method declarations remain separate evidence; dynamic JNI registration, reflection, process launches and protected loaders require additional analysis.


## 7. Follow-up engineering audit — 2026-11-23

This section records a source-level audit of the current ApnaWin implementation against the v51 native-library inventory. It intentionally separates **a reusable forwarding component** from **an implementation of a remote protocol**.

### 7.1 What the current code actually implements

| Code area | Verified implementation | What it does not establish |
|---|---|---|
| `apna_ssh_session.py` | Paramiko SSH authentication, optional pinned host key, loopback SOCKS5 TCP CONNECT forwarding | Compatibility with the protected Salamander SSH handshake, its cipher/KEX policy, or its native socket handoff |
| `apna_payload_socket.py` / `apna_payload.py` | Direct/TLS/HTTP payload socket setup and DEX-derived payload expansion | Every protected payload mode or every server-side payload grammar |
| `udpgw_protocol.py`, `udpgw_stream.py`, `udpgw_flows.py`, `socks5_gateway.py` | BadVPN PacketProto framing, flow IDs, UDPGW-over-TCP stream and local SOCKS5 UDP ASSOCIATE bridge | A successful round-trip against a real APNA provider UDPGW endpoint |
| `apna_tunnel_engine.py`, `apna_xray_config.py`, `xray_process.py` | Starts an SSH-backed local SOCKS bridge, then configures a separate Xray process as a dual-stack TUN frontend whose only outbound is that local SOCKS bridge | A remote Xray outbound for VLESS/VMess/Trojan/Shadowsocks/WireGuard/Hysteria; those are separate adapters/configuration paths |
| `multi_transport.py`, `transport_router.py` | Lifecycle dispatch across registered `Transport` engines | Automatic discovery or registration of every protocol found in Android native binaries |

**Important correction for implementation planning:** the existing Xray integration is a TUN/packet-routing frontend over the SSH SOCKS bridge. It is not yet an APNA Xray-protocol client. The Android `libxray.so` code inventory therefore represents additional remote-protocol capability that has not been wired into ApnaWin's profile model or engine registry.

### 7.2 Current v51 versus historical v27 OpenVPN evidence

The v51 primary DEX references `prince.open.vpn.activities.OpenVPNClient`, but the referenced class is not defined in the inspected primary DEX. This is not enough to claim a current v51 OpenVPN implementation. The independent v27 dynamic report did observe an OpenVPN runtime/configuration in that older release. Therefore:

- OpenVPN remains in the compatibility investigation backlog.
- Do not reuse v27 endpoints, credentials, generated configuration, or assumptions as v51 values.
- Recover the v51 split/protected implementation or a redacted runtime trace before defining the exact APNA OpenVPN adapter contract.
- A generic OpenVPN engine may be developed as an independent importable transport, but it must not be presented as a verified v51 catalog mapping.

### 7.3 QUIC/DTLS and `libudpqtwo.so`

The current source has no dedicated QUIC or DTLS transport engine registered in `Transport`. The Android native inventory establishes that the ARM64 Go binary contains QUIC, Pion DTLS, SOCKS5, HTTP proxy and DNS-related code signatures. It does not reveal a stable configuration schema or which service owns the binary.

The next implementation gate is not to guess a protocol from the filename. Recover and document:

1. ELF build metadata, exported/dynamic symbols, imports, relocations and init/fini behavior for the exact split-library hash.
2. DEX service launch and native-loading paths for `PInjectorService`, `SocksDNSService`, `XRayDNSService` and the proxy service.
3. Any process arguments, JNI registration names, Binder/Intent extras and configuration key/type pairs (redacted values only).
4. Socket metadata and a repeatable handshake/packet exchange from an authorized test installation.

After the contract is known, implement QUIC and DTLS as separate transport adapters if the evidence shows distinct handshakes. Do not treat SOCKS5 as a remote VPN protocol: it is a proxy interface which may be carried by another transport.

### 7.4 Implementation sequence

1. Keep the SSH + payload + SOCKS + UDPGW path isolated and add provider-independent protocol conformance tests; never weaken SSH algorithms merely to make an endpoint appear compatible.
2. Separate the Xray TUN frontend from remote Xray outbound profiles. Add a typed remote-outbound model and per-protocol config builders only with required credential/security fields and validation.
3. Add independent engine contracts for QUIC and DTLS after recovering `libudpqtwo.so` ownership and wire/config behavior.
4. Add OpenVPN as an independently testable engine; mark APNA v51 catalog selection as unresolved until v51 evidence exists.
5. Register each engine explicitly in the multi-transport router, then test lifecycle, cancellation, resource ownership, IPv4/IPv6, TCP/UDP, DNS and leak protection.
6. Keep all statuses evidence-based: process started, handshake complete, authenticated, proxy reachable, routed egress verified and disconnected must remain distinct states.

### 7.5 Scope and release boundary

This audit changes the engineering plan and does not claim a successful live connection. No Windows installer, portable release, new product build, or PR merge is authorized by this work. PR #6 remains open, Draft and unmerged.
