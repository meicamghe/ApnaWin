# APNA TUNNEL LITE Android runtime static analysis

**Target:** APNA TUNNEL LITE, package `com.apnatunnel.lite`  
**APK inspected:** user-provided Library APK, SHA-256 `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`  
**Date:** 2026-11-16  
**Method:** offline ZIP/Dex inspection and DEX string/type/method/class-definition analysis; the APK was not executed.

## 1. Important correction: OpenVPNClient is not proof of the OpenVPN wire protocol

The primary DEX contains a method/type reference to:

`prince.open.vpn.activities.OpenVPNClient`

However, the inspected DEX class-definition table does not define that class. The name alone does not prove that the app uses the OpenVPN protocol. It appears to be an activity/client class name in a third-party VPN framework namespace. The protected/loaded runtime code that owns the UI and connection selection remains incompletely recovered.

The primary DEX does define substantial VPN infrastructure under `prince.open.vpn.service.vpn`. That infrastructure provides stronger evidence about the actual tunnel architecture than the activity name.

## 2. Confirmed DEX-defined VPN components

The primary DEX class-definition table includes:

- `TunnelVpnService`, `TunnelVpnManager`, `TunnelVpnSettings`
- `Tunnel`, `TunnelManagerThread`, `TunnelManagerHelper`, `TunnelState`
- `TunnelUtils`, `VpnUtils`
- `Tun2Socks`, `Tun2SocksJni`
- `Pdnsd`
- `SalamanderService`, `SocksDNSService`, `XRayDNSService`

The existence of these classes and their method references is direct static evidence. It does not establish that every class is selected for every APNA server category.

## 3. Reconstructed TUN data path

The following call relationships and Android API references are present in DEX code:

1. `TunnelVpnManager` creates a `Tunnel` and invokes `startTunneling`.
2. `Tunnel` obtains an Android `VpnService.Builder`.
3. The builder is configured with a private VPN address, DNS server(s), MTU, routes, session label and optional allowed/disallowed application lists.
4. The service calls `VpnService.Builder.establish()` and retains the resulting `ParcelFileDescriptor`.
5. The `Tun2Socks` worker launches `libtun2socks.so` from the app's private data directory.
6. The worker passes the TUN file descriptor to the native process using an Android local socket and `setFileDescriptorsForSend`.
7. The tunnel stop path terminates Tun2Socks, joins its worker, stops DNS support and closes the TUN descriptor.

This is a conventional Android userspace VPN architecture: Android creates the TUN interface, and a userspace forwarding engine moves packets between that interface and one or more proxy transports. The Windows port must reproduce the forwarding/proxy semantics, not the Android `VpnService` API itself.

## 4. SSH and custom payload evidence

The primary DEX contains the following methods in `TunnelManagerThread`:

- `startClienteSSH`
- `closeSSH`
- `reconnectSSH`
- `startForwarder`
- `stopForwarder`
- `startTunnelVpnService`
- `stopTunnelVpnService`

The reconnect worker closes and restarts the SSH client when network availability or tunnel state changes. The status strings include `SSH_AUTHENTICATING`, `SSH_CONNECTED`, `SSH_CONNECTING`, and `SSH_DISCONNECTED`. The manager also emits `UDP Connected` as a status string.

`TunnelUtils` includes `formatCustomPayload`, `injectSplitPayload`, `injectSimpleSplit`, `parseRotate`, and `restartRotate`. The method bytecode references token strings:

- `[ssh]`
- `[crlf]`
- `[cr]`
- `[lf]`
- `[lfcr]`

The payload-writing routines use `ISO-8859-1` byte conversion and write/flush to an output stream. This strongly indicates that payload strings are transformed into bytes and injected into a socket stream as part of the proxy handshake. The exact full grammar, substitution order, TLS/WS behavior, and how catalog fields feed this formatter still need tracing.

## 5. Multiple forwarding modes are present, but their mapping is not yet proven

The primary DEX references service helpers named:

- `startSsh` / `stopSsh`
- `startXRay` / `stopXRay`
- `startSocksHttp` / `stopSocksHttp`

It also defines `SalamanderService`, `SocksDNSService`, and `XRayDNSService`. The presence of these symbols shows that more than one service/forwarding path exists. It does not yet prove which APNA `category` or `method` selects which service.

Do not infer that a payload whose category contains `xray` is directly an Xray JSON config. It may select a local forwarding helper, a SOCKS endpoint, a DNS component, or a protected runtime class. Likewise, `UDP Connected` is not sufficient to determine whether UDP is carried by an SSH UDP gateway, a custom datagram forwarder, or another engine.

## 6. Implications for the Windows architecture

The existing ApnaWin `TunnelEngine` abstraction is still the right boundary. The next provider-specific work should be split into distinct adapters rather than forcing every APNA mode through Xray:

1. **SSH + payload adapter:** recover SSH authentication, host/port resolution, payload formatting, injection timing, keepalive and reconnect semantics. Reproduce the verified protocol with a Windows SSH process/library and a local SOCKS/TUN forwarding chain.
2. **Xray adapter:** trace the exact `startXRay` implementation and configuration contract before mapping any APNA catalog record to the existing Xray/Wintun engine.
3. **UDP adapter:** trace the `udp` method, UDP gateway address/port and the `UDP Connected` state transition; implement only after its framing and authentication are known.
4. **Direct adapter:** establish whether `direct` means direct TCP/HTTP(S), direct proxying, or a special bypass mode. Do not equate it with a no-tunnel Windows route until confirmed.
5. **TUN adapter:** retain the current Windows Wintun lifecycle, but connect it to the correct local proxy/forwarder for each verified mode.

The Android TUN layer and Windows Wintun layer solve the packet-capture/route problem. They do not replace SSH, payload injection, Xray, UDP gateway or SOCKS forwarding. Both layers are needed for a complete port.

## 7. Next reverse-engineering tasks

### Track A — payload and SSH

- [ ] Recover the method signatures and all call sites for `startClienteSSH`, `startForwarder`, `formatCustomPayload`, `injectSplitPayload` and `injectSimpleSplit`.
- [ ] Trace how the selected server record and payload record populate the SSH client and forwarder settings.
- [ ] Determine the exact `[ssh]` placeholder substitution and CR/LF token behavior.
- [ ] Identify the SSH library/service implementation and its authentication/host-key policy.
- [ ] Determine local SOCKS/HTTP listener ports and which listener receives TUN traffic.

### Track B — Xray and UDP

- [ ] Recover `TunnelManagerHelper.startXRay` and its configuration source.
- [ ] Trace `SalamanderService`, `SocksDNSService` and `XRayDNSService` responsibilities.
- [ ] Determine UDP gateway setup, framing and mode selection.
- [ ] Compare each result against the APNA category/method fields without logging credential values.

### Track C — app selection and protected code

- [ ] Locate the runtime-loaded or protected class definitions for `OpenVPNClient` and the connection-selection UI.
- [ ] Trace category filtering, server/payload matching, fallback, host-pool rotation and port resolution.
- [ ] Recover the meaning of `Pulled`, `sslws`, `sausage`, `query`, `dothost` and `custom_cert`.
- [ ] Cross-check every inferred rule against a second APK version or a controlled runtime observation.

## 8. Evidence boundaries

- The class and method references above come from the supplied APK's primary DEX. They are not guessed from server names.
- The protected runtime and dynamically loaded class definitions are not fully reconstructed.
- No real server credentials or raw decrypted catalog records are included in this document.
- This static analysis does not prove that any current APNA endpoint is online or accepts a connection.
- CI success and a Windows artifact do not prove APNA compatibility. Real Windows handshake, routed traffic, DNS/IPv4/IPv6 and disconnect tests remain mandatory.
