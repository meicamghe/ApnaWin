# APNA Tunnel Lite upstream framework comparison

**Purpose:** record the additional public GitHub source comparison performed on 2026-11-16. This document separates APNA-specific APK evidence from behavior found in a related, publicly available SSH/TUN framework. It is research evidence, not an assertion that the APNA APK contains byte-for-byte identical source.

## 1. Sources inspected

### APNA catalog research

- Repository: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM
- APNA Lite decoder at inspected commit b66fd18dce1a51d932a32776696ca4a190a3eaac: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/tree/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite
- Decoder README: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite/README.md
- Decoder implementation: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite/APNA_Tunnel_Lite.py
- External integration report: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/analysis/platform/supplied-integrations/2026-11-14/ANALYSIS.md

### Additional sibling service implementation

- Repository: https://github.com/justinaxie911/SpeedLiteVpn
- Inspected commit: 4833190b14f9b8b21b366c4cc5314787a13d440c
- [SocksDNSService.java](https://github.com/justinaxie911/SpeedLiteVpn/blob/4833190b14f9b8b21b366c4cc5314787a13d440c/app/src/main/java/com/jvinjector/jenrri/service/SocksDNSService.java)
- [TunnelManagerThread.java](https://github.com/justinaxie911/SpeedLiteVpn/blob/4833190b14f9b8b21b366c4cc5314787a13d440c/app/src/main/java/com/jvinjector/jenrri/tunnel/TunnelManagerThread.java)
- [UDPTunnel.java](https://github.com/justinaxie911/SpeedLiteVpn/blob/4833190b14f9b8b21b366c4cc5314787a13d440c/app/src/main/java/com/jvinjector/jenrri/tunnel/UDPTunnel.java)
- [V2Tunnel.java](https://github.com/justinaxie911/SpeedLiteVpn/blob/4833190b14f9b8b21b366c4cc5314787a13d440c/app/src/main/java/com/jvinjector/jenrri/tunnel/V2Tunnel.java)
- [DNSTunnelThread.java](https://github.com/justinaxie911/SpeedLiteVpn/blob/4833190b14f9b8b21b366c4cc5314787a13d440c/app/src/main/java/com/jvinjector/jenrri/tunnel/DNSTunnelThread.java)

### BadVPN UDP gateway implementation

- Repository: https://github.com/shirokhorshid/shirokhorshid-android
- Inspected commit: 2c719306c2340938cbafcb3dc59c8e03173bcf8c
- [UDP gateway wire header](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/protocol/udpgw_proto.h)
- [UDP gateway client](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/udpgw_client/UdpGwClient.c)
- [SOCKS-to-UDPGW bridge](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/tun2socks/SocksUdpGwClient.c)
- [UDPGW server](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/udpgw/udpgw.c)
- [tun2socks command-line implementation](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/tun2socks/tun2socks.c)
- [BadVPN changelog](https://github.com/shirokhorshid/shirokhorshid-android/blob/2c719306c2340938cbafcb3dc59c8e03173bcf8c/app/src/main/jni/badvpn/ChangeLog)

This repository also uses a different Java package and app identity. Its same-named SocksDNSService is a comparative lead only; it is not evidence that its bytecode is the implementation referenced by APNA.

### Related SSH/TUN framework source

A public source repository contains the same uncommon method names seen in the APNA primary DEX, including startClienteSSH, startForwarder, formatCustomPayload, injectSplitPayload, and the TunnelVpnSettings SOCKS/DNS fields:

- Repository: https://github.com/sauceisgood/sockshttp
- Inspected source commit: ab177ac896896c592caed750d74100518c230b62
- [TunnelManagerThread.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/TunnelManagerThread.java)
- [TunnelUtils.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/TunnelUtils.java)
- [HttpProxyCustom.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/HttpProxyCustom.java)
- [Tunnel.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/vpn/Tunnel.java)
- [TunnelVpnSettings.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/vpn/TunnelVpnSettings.java)
- [TunnelVpnManager.java](https://github.com/sauceisgood/sockshttp/blob/ab177ac896896c592caed750d74100518c230b62/service/src/main/java/com/slipkprojects/ultrasshservice/tunnel/vpn/TunnelVpnManager.java)

The public framework uses package com.slipkprojects.ultrasshservice, whereas the inspected APNA DEX uses prince.open.vpn. The matching method names and data-flow shape are strong evidence of a shared framework lineage or close adaptation, but they do **not** prove identical implementation, configuration defaults, service wiring, or version. The public source is therefore used as a behavioral cross-check only.

## 2. SSH-to-TUN flow corroborated by the public source

The related TunnelManagerThread implements this sequence:

1. Read SSH host, port, username, password/key path and local forwarder port from its settings object.
2. Create an SSH connection, optionally attach an HTTP proxy transport, then connect with finite connection/read timeouts.
3. Authenticate using password and/or a configured public key.
4. Create a dynamic local SOCKS port forwarder using the SSH connection.
5. Start the Android TUN service, passing the local SOCKS endpoint and DNS/UDP resolver settings.
6. During shutdown, stop TUN routing and close the local SOCKS forwarder before closing the SSH connection.

This closely matches the APNA primary-DEX evidence: startClienteSSH, startForwarder(int), TunnelVpnSettings.mSocksServer, separate DNS/UDP resolver fields, and the TUN-to-SOCKS handoff. It raises confidence in the broad architecture:

**APNA server/proxy endpoint -> optional HTTP payload handshake -> SSH transport -> local SOCKS forwarder -> TUN-to-SOCKS packet bridge**

**Still unproven for APNA:** the exact settings source, whether all APNA SSH categories use this path, the local listener address/port, service implementation identity, credential selection, and whether the APK's protected service diverges from this public framework.

## 3. Custom payload grammar found in the related source

The public TunnelUtils.formatCustomPayload(hostname, port, payload) expands these tokens:

| Token | Related-source expansion |
|---|---|
| [method] | CONNECT |
| [host] | target hostname |
| [port] | target port |
| [host_port] | hostname and port joined as host:port |
| [protocol] | HTTP/1.0 |
| [ssh] | target hostname and port joined as host:port |
| [crlf] | CRLF |
| [cr] | CR |
| [lf] | LF |
| [lfcr] | LF followed by CR |
| \\n, \\r | literal escaped newline/carriage-return sequences |
| [ua] | platform HTTP agent, or a fallback browser user-agent |

The same source recognizes:

- [split]: write each segment and flush it immediately, without a deliberate delay.
- [delay_split]: write and flush each segment, sleeping one second between segments.
- [rotate=a;b;...]: cycle through the supplied alternatives.
- [random=a;b;...]: select one alternative randomly.

The public HttpProxyCustom connects to a configured proxy host/port, expands the payload using the SSH target host/port, writes it as ISO-8859-1 bytes, and flushes. In its non-Dropbear path it reads the proxy's HTTP response before allowing the SSH transport to continue. The Dropbear path returns the socket after writing the payload. These details are valuable hypotheses for test design, not yet APNA-confirmed behavior.

The APNA DEX independently confirms the formatter/injector method names, the five core token strings [ssh], [crlf], [cr], [lf], [lfcr], and ISO-8859-1 output writes. The expanded token set and one-second delay behavior need to be confirmed against APNA's actual method bytecode or controlled runtime traces before implementing them as APNA compatibility requirements.

## 3B. Exact uProxy JNI package match and missing native split

The APNA primary DEX references the exact Java class descriptor org/uproxy/tun2socks/Tun2SocksJni and the library names libtun2socks and libtun2socks.so. A public repository, UWNetworksLab/cordova-plugin-tun2socks, contains that exact package/class:

- [Tun2SocksJni.java](https://github.com/UWNetworksLab/cordova-plugin-tun2socks/blob/9b686fb3bad6792142425931799b8f7690a932eb/android/java/org/uproxy/tun2socks/Tun2SocksJni.java)
- [Tunnel.java](https://github.com/UWNetworksLab/cordova-plugin-tun2socks/blob/9b686fb3bad6792142425931799b8f7690a932eb/android/java/org/uproxy/tun2socks/Tunnel.java)
- [JNI/native bridge](https://github.com/UWNetworksLab/cordova-plugin-tun2socks/blob/9b686fb3bad6792142425931799b8f7690a932eb/android/jni/tun2socks/tun2socks.c)
- [Plugin manifest and declared license](https://github.com/UWNetworksLab/cordova-plugin-tun2socks/blob/9b686fb3bad6792142425931799b8f7690a932eb/plugin.xml)

The public JNI method signature is:

`runTun2Socks(fd, mtu, vpnIpAddress, vpnNetMask, socksServerAddress, udpRelayAddress, dnsResolverAddress, transparentDNS)`

Its source comment explicitly describes TCP being routed through the SOCKS proxy and UDP being sent to a separate UDPGW server. The native JNI bridge maps those arguments to the native SOCKS address, UDP relay address, DNS resolver address and transparent-DNS setting. The public Tunnel wrapper passes the TUN descriptor, interface MTU/address/netmask and those endpoints to the native method.

The exact class/package match plus the APNA DEX's UDPGW fields is strong evidence that APNA uses this uProxy/BadVPN-derived native TUN bridge or a close fork. It does not identify the precise native commit or prove the APNA argument values.

**Important APK packaging gap:** the supplied file is named base.apk. A full ZIP scan of its 1,479 entries found no .so entry and no entry beginning with the ELF magic bytes. The DEX nevertheless references libtun2socks.so. This does not prove the installed app lacks the library: Android App Bundle delivery can put ABI-specific native libraries in a separate split APK (for example, an arm64-v8a split), or the protected app may extract/load it by another mechanism. The native implementation therefore cannot be audited from the supplied base.apk alone. A complete installed-package pull, including every split APK, is needed to recover the exact binary and version.

The Cordova plugin is an Android/JNI integration and is not itself a Windows runtime. Its plugin manifest declares Apache 2.0, while individual Java/native source files carry Psiphon/BadVPN notices. Audit the exact file-level notices and transitive dependencies before reuse. For ApnaWin, the Windows side must implement an equivalent TUN-to-SOCKS plus UDPGW bridge with Windows-native TUN/Wintun handling; the Android JNI binary cannot simply be loaded on Windows.

## 3A. UDP gateway path — strong framework match, APNA endpoint still unknown

The APNA primary DEX string table contains all of the following exact identifiers:

- mUdpResolver and mUdpDnsRelay in the VPN settings contract.
- mUdpgwServerAddress and mUdpgwTransparentDNS in the TUN-to-SOCKS layer.
- The native command option --udpgw-transparent-dns.
- The native library name libtun2socks.so.

The related sockshttp source contains the same mUdpgwServerAddress/mUdpgwTransparentDNS fields in Tun2Socks. Its TunnelVpnSettings carries mUdpResolver and mUdpDnsRelay, TunnelVpnManager passes those values into Tunnel.startTunneling, and Tunnel.routeThroughTunnel passes them to Tun2Socks. The command builder then adds:

- --socks-server-addr for the local SOCKS endpoint.
- --udpgw-remote-server-addr when a UDP gateway endpoint is configured.
- --udpgw-transparent-dns when the boolean is enabled.
- --dnsgw when a separate local DNS relay is configured.

This is a much stronger match than a generic TUN/SOCKS resemblance. It supports the following interpretation of the APNA fields: mUdpResolver is the UDP gateway endpoint and mUdpDnsRelay controls transparent DNS forwarding through that gateway. The separate mDnsForward/mDnsResolver path can start a local Pdnsd resolver and pass its address as --dnsgw. Exact APNA constructor argument order and runtime values still need verification against the protected implementation.

The BadVPN implementation shows that UDPGW is **not** SOCKS5 UDP ASSOCIATE. SocksUdpGwClient establishes a SOCKS stream to the configured remote UDPGW endpoint and attaches UdpGwClient to that stream. UdpGwClient uses PacketProto framing and a custom UDPGW record: a 3-byte header (flags plus 16-bit connection ID), followed by an IPv4 or IPv6 remote-address/port structure and the UDP payload. Flags identify keepalive, rebind, DNS and IPv6 records. The server maintains per-client UDP connections and sends received datagrams back over the framed stream.

This means the APNA path likely has two independent transports after the TUN interface: TCP through the local SOCKS endpoint and UDP through a BadVPN-style UDP gateway reached through that SOCKS stream. This is the best current explanation for the separate UDP settings and transparent-DNS flag; the actual APNA native library/version and endpoint are not yet verified.

**Windows implication:** the inspected BadVPN changelog (version 1.999.128) explicitly notes that transparent DNS forwarding was added but that there was no Windows support on the UDPGW side. Do not assume that building the Android tun2socks source for Windows will provide this feature. A Windows client may need a separately implemented compatible UDPGW client or a different provider-confirmed UDP engine. This is a compatibility risk to resolve before claiming UDP support, not proof that Windows support is impossible.

The BadVPN C files carry a BSD-style license notice; the Android Java wrappers and Psiphon-derived components have separate notices. Audit every native and Java dependency before reuse. The current work uses this source only to understand the protocol shape and does not copy its implementation.

## 4. Security and licensing findings — do not copy blindly

The related public TunnelManagerThread.verifyServerHostKey implementation returns true unconditionally after computing a fingerprint. That accepts an unverified SSH host key and is not an acceptable security design for ApnaWin. The Windows implementation must use strict host-key verification or an explicit, user-approved trust-on-first-use/pinning flow; never copy this permissive callback.

The related Tunnel.java source carries a GPL-3.0-or-later notice. Other files and bundled dependencies may have separate terms. This research does not authorize copying or porting code. Before any source reuse, perform a file-by-file license and dependency audit and decide whether the project's distribution model is compatible. For now, only independently implement behavior supported by APNA evidence and use the public code as a comparison reference.

The first comparison repository names its service SocksHttpService. The second repository contains a same-named SocksDNSService class, but under a different package and application identity. In that second source, SocksDNSService is a service wrapper: it starts a DNSTunnelThread for its SlowDNS setting and also starts TunnelManagerThread. That manager selects separate UDP, V2Ray, or SSH paths according to its own settings. This demonstrates why the service name alone cannot establish APNA's engine mapping. No matching public implementation for APNA's SalamanderService or XRayDNSService descriptors was found. APNA's own service class definitions remain absent from the inspected primary DEX.


## 4A. What the sibling SocksDNSService source adds

In the inspected SpeedLiteVpn source, SocksDNSService.onStartCommand starts a worker that:

1. Reads its own tunnel-type preference.
2. Starts DNSTunnelThread when that preference is SlowDNS.
3. Starts TunnelManagerThread for the main connection lifecycle.

That sibling TunnelManagerThread branches among three distinct modes: UDP starts UDPTunnel, V2Ray starts V2Tunnel with a stored JSON config, and the default branch starts the SSH client. The separate DNSTunnelThread launches a native libdns process with a DNS server, public-key value, nameserver and a local 127.0.0.1:2222 endpoint.

The sibling UDPTunnel builds a local SOCKS5 listener configuration at 127.0.0.1:1080 and launches a native client binary with a JSON configuration. Its sample configuration includes an insecure TLS setting and a repository-specific certificate. Those values and that binary are specific to the sibling project and must not be copied or treated as APNA protocol data. The V2Tunnel path launches a separate V2Ray service and supplies a stored JSON config.

This gives us concrete comparison questions for the APNA DEX: does its protected TunnelManagerThread branch on equivalent mode constants; does its UDP path create a local SOCKS listener; does XRayDNSService accept a JSON config; and does SalamanderService own SSH, DNS-over-SSH, or another forwarder? None of these answers is established by the sibling repository alone. APNA's server/payload mapping must still be traced from APNA call sites or runtime observations.

The SpeedLiteVpn repository's own license page describes a mixture of components and inherited SSH Tunnel/Trilead code; it does not provide a single clear license grant for every project-authored file. Together with the different project identity, this is a research reference only, not a source-code reuse authorization.

## 5. Catalog downloader: discrepancies and freshness

The external APNA decoder's README reports a live observation dated 2026-11-13: catalog version 850, 50 free servers and 644 payloads. The external 2026-11-14 integration report explicitly says APNA's integration path had no new remote verification in that delivery. These statements are compatible: the README records an earlier observation, while the later integration pass did not repeat it.

The external script adds a ranged-download fallback after ordinary GET attempts fail. Its own comments describe this as a downloader workaround because the host sometimes truncates bodies. It is **not** evidence that the Android app sends Range headers. The script itself says the app makes a plain GET; its retry/resume behavior belongs to the research tool unless separately verified.

The external notes describe Dalvik/2.1.0 and Accept-Encoding: identity as the effective request headers, while also explaining that the app does not set custom authentication/signature headers and that the Dalvik agent is the platform default. Treat these as reported effective headers, not proof that the Android app explicitly adds both headers in source code. The local APK's protected updater implementation was not fully recovered.

A live request attempted from this environment on 2026-11-16 failed before HTTP because DNS resolution for paperonboard.com failed. HTTP status was 000; no response body was received. This is an environment DNS failure, not evidence that the provider endpoint is offline. The current live catalog version/counts remain unverified.

The ApnaWin discovery-only HTTP source has since been hardened to require HTTP 200, reject non-identity content encoding, enforce the declared Content-Length against the configured size limit, and reject truncated bodies. The tests for these checks use mocked responses; they do not imply a successful live fetch.

## 6. Consequences for ApnaWin implementation

- Keep the APNA catalog adapter in discovery-only mode until a fresh response and schema are validated.
- Do not port the external script's Range fallback as if it were Android behavior. If a Windows downloader later needs resume support, design it as a separate reliability feature with strict Content-Range/ETag/length checks and independent tests.
- Add a provider-neutral SSH/payload engine boundary only after the APNA call sites establish the required fields and sequencing.
- Implement payload expansion as a deterministic, testable component; add only tokens proven in APNA bytecode or runtime traces.
- Test split timing and response handling with synthetic local proxy fixtures; never use embedded catalog credentials in tests.
- Keep SSH host-key verification strict. The permissive callback in the comparison source is specifically rejected.
- Do not map ocsws, ocscf, ocsudp, ocsshadow, ocstrojanworker, ocsxray, or ocsv2ray to an engine based only on their names.
- Do not claim APNA compatibility until a real Windows 10/11 session completes the provider handshake, routes traffic, verifies DNS/IPv4/IPv6 behavior, and cleans up routes/adapters on disconnect.

## 7. Next reverse-engineering work

1. Trace every APNA call site into formatCustomPayload, injectSplitPayload, and injectSimpleSplit; recover argument sources and exact substitution order.
2. Recover the protected SSH service's SSH library, authentication flow, host-key verification, proxy type, keepalive and reconnect behavior.
3. Trace the APNA startXRay and startSocksHttp service paths independently; identify their configuration inputs and local listener endpoints.
4. Trace UDP resolver setup and framing independently from TCP/SSH.
5. Recover server/payload matching, host-pool rotation, Pulled port resolution, and meanings of sslws, sausage, query, dothost, and custom_cert.
6. Obtain a fresh catalog response from a network where DNS works; compare only redacted schema/count metadata and never log credentials.
7. Build a synthetic local integration test that exercises payload -> SSH proxy handshake -> local SOCKS -> Wintun routing without requiring a real APNA credential.
