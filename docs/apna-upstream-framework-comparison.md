# APNA Tunnel Lite upstream framework comparison

**Purpose:** record the additional public GitHub source comparison performed on 2026-11-16. This document separates APNA-specific APK evidence from behavior found in a related, publicly available SSH/TUN framework. It is research evidence, not an assertion that the APNA APK contains byte-for-byte identical source.

## 1. Sources inspected

### APNA catalog research

- Repository: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM
- APNA Lite decoder at inspected commit b66fd18dce1a51d932a32776696ca4a190a3eaac: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/tree/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite
- Decoder README: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite/README.md
- Decoder implementation: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/decoders/Python/apps/APNA_Tunnel_Lite/APNA_Tunnel_Lite.py
- External integration report: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/blob/b66fd18dce1a51d932a32776696ca4a190a3eaac/analysis/platform/supplied-integrations/2026-11-14/ANALYSIS.md

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

## 4. Security and licensing findings — do not copy blindly

The related public TunnelManagerThread.verifyServerHostKey implementation returns true unconditionally after computing a fingerprint. That accepts an unverified SSH host key and is not an acceptable security design for ApnaWin. The Windows implementation must use strict host-key verification or an explicit, user-approved trust-on-first-use/pinning flow; never copy this permissive callback.

The related Tunnel.java source carries a GPL-3.0-or-later notice. Other files and bundled dependencies may have separate terms. This research does not authorize copying or porting code. Before any source reuse, perform a file-by-file license and dependency audit and decide whether the project's distribution model is compatible. For now, only independently implement behavior supported by APNA evidence and use the public code as a comparison reference.

The public repository's service is named SocksHttpService; it is not evidence that APNA's referenced SalamanderService, XRayDNSService, or SocksDNSService have the same implementation. No exact public implementation for those APNA service descriptors was found in this search.

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
