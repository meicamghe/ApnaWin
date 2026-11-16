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

The primary DEX also references service descriptors named `SalamanderService`, `SocksDNSService`, and `XRayDNSService`; those names are not class definitions in the inspected primary DEX.

The existence of these classes and their method references is direct static evidence. It does not establish that every class is selected for every APNA server category.

## 3. Reconstructed TUN data path

The following call relationships and Android API references are present in DEX code:

1. `TunnelVpnManager` creates a `Tunnel` and invokes `startTunneling`.
2. `Tunnel` obtains an Android `VpnService.Builder`.
3. The builder is configured with a private VPN address, DNS server(s), MTU, routes, session label and optional allowed/disallowed application lists.
4. The service calls `VpnService.Builder.establish()` and retains the resulting `ParcelFileDescriptor`.
5. The `Tun2Socks` worker references a native tun2socks executable and an ABI/file-loading path. DEX strings include `TUN2SOCKS_BIN`, `fileTun2Socks`, `tun2SocksProcess`, `SUPPORTED_ABIS`, `nativeLibraryDir`, `sourceDir`, and `getFilesDir`. A related public implementation checks `nativeLibraryDir`, then extracts `lib/<abi>/tun2socks.so` or `jni/<abi>/tun2socks.so` to the app files directory and executes it. The supplied `base.apk` has no `.so`/ELF entry, so the exact native binary is likely in an ABI split or another protected loading path; the active JNI-vs-process path still needs call-graph confirmation.
6. The worker passes the TUN file descriptor to the native process using an Android local socket and `setFileDescriptorsForSend`.
7. The `Tunnel.startTunneling` method accepts a SOCKS server string, a DNS resolver string array, boolean settings and additional routing parameters. `TunnelVpnSettings` contains explicit fields for `mSocksServer`, `mDnsResolver`, `mUdpResolver`, `mUdpDnsRelay`, `mDnsForward`, `mExcludeIps`, `mFilterApps`, `mEnableFilterApps`, `mFilterBypassMode`, `bypass`, and `mTetheringSubnet`. This confirms the TUN layer is configured to hand traffic to a local SOCKS endpoint and has separate DNS/UDP relay controls. Additional primary-DEX strings include `mUdpgwServerAddress`, `mUdpgwTransparentDNS`, and `--udpgw-transparent-dns`, strongly indicating an optional BadVPN-style UDP gateway and transparent DNS flag in the native tun2socks path. The tunnel stop path terminates Tun2Socks, joins its worker, stops DNS support and closes the TUN descriptor.

This is a conventional Android userspace VPN architecture: Android creates the TUN interface, and a userspace forwarding engine moves packets between that interface and one or more proxy transports. The Windows port must reproduce the forwarding/proxy semantics, not the Android `VpnService` API itself.

## 3A. Direct method-table inspection: where the SSH implementation is missing

The APK primary DEX was re-parsed at the method/code-item level (not just with `strings`). This resolves an important ambiguity in the earlier call-graph summary:

- `TunnelManagerThread.startClienteSSH()` (method index 50445) updates the displayed status to `CONNECTED` / `UDP Connected` and invokes `startTunnelVpnService()`. It does **not** itself perform SSH socket connect or authentication.
- `TunnelManagerThread.startForwarder(int)` (50446) starts the VPN service and launches an inner worker thread. The visible primary-DEX code still does not expose a Trilead/JSch SSH handshake.
- The actual SSH engine is referenced through service descriptors `prince.open.vpn.service.SalamanderService`, `SocksDNSService`, and `XRayDNSService`. These descriptors are not present in the primary DEX type table or class-definition table. The corresponding service implementations are therefore not recoverable from the supplied base DEX as ordinary classes; they may be supplied by protected/dynamic loading, another installed split, or another runtime mechanism. The base APK alone does not establish which.
- `TunnelVpnManager.onStartCommand()` receives the parcelled `TunnelVpnSettings`, validates the SOCKS endpoint and DNS resolver inputs, then starts the VPN worker. `Tunnel.routeThroughTunnel()` creates the local DNS helper and starts `Tun2Socks` with the SOCKS endpoint, optional UDPGW endpoint, DNS resolver, and transparent-DNS flag.
- The exact native JNI bridge class is defined as `org.uproxy.tun2socks.Tun2SocksJni`, with native declarations `runTun2Socks(...)` and `terminateTun2Socks()`. The primary DEX also defines a separate process-based `prince.open.vpn.service.vpn.Tun2Socks` worker which constructs the `libtun2socks.so` command line and sends the Android TUN file descriptor over a local Unix socket. The existence of both paths means the active JNI-vs-process selection must be established from the protected settings/runtime, not guessed.

**Engineering consequence:** the missing blocker is now narrowed to the protected SSH service / dynamic module and its configuration handoff. Porting only the visible `TunnelManagerThread` class would not recreate APNA's SSH transport. The next evidence needed is the installed split APK/runtime payload that defines `SalamanderService` (and related service classes), or a controlled trace from a running APNA Lite installation. Until then, catalog-to-SSH mode selection and SSH credentials/host mapping remain unconfirmed.

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

`TunnelUtils` includes `formatCustomPayload`, `injectSplitPayload`, `injectSimpleSplit`, `parseRotate`, and `restartRotate`. The primary DEX string table contains these payload-related tokens/patterns:

- `[host]`, `[host_port]`, `[port]`, `[protocol]`, `[ssh]`
- `[crlf]`, `[cr]`, `[lf]`, `[lfcr]`
- `[delay_split]` and `[instant_split]`
- a rotate-expression pattern (`[rotate=...]`)

The related public framework uses `[split]`, but APNA's visible DEX uses `[instant_split]`; do not substitute the sibling token without checking APNA's method bytecode. The inspected primary DEX does not expose the sibling's `[method]`, `[ua]`, or `[random=...]` tokens. The protected secondary asset remains a separate evidence gap.

The payload-writing routines use `ISO-8859-1` byte conversion and write/flush to an output stream. This strongly indicates that payload strings are transformed into bytes and injected into a socket stream as part of the proxy handshake. The exact full grammar, substitution order, TLS/WS behavior, and how catalog fields feed this formatter still need tracing. The `startSsh` helper explicitly launches `SalamanderService`, while `startXRay` launches `XRayDNSService`; this ties the app's visible SSH and XRay control paths to separate Android services.

## 5. Multiple forwarding modes are present, but their mapping is not yet proven

The primary DEX defines the following explicit static helper methods on `TunnelManagerHelper`, each taking an Android `Context`:

- `startSsh` / `stopSsh`
- `startXRay` / `stopXRay`
- `startSocksHttp` / `stopSocksHttp`
- `restartSocksHttp`

The start methods create an explicit service `Intent` and invoke `Context.startService`; the DEX type references map the targets: `startSsh` → `SalamanderService`, `startXRay` → `XRayDNSService`, and `startSocksHttp` → `SocksDNSService`. The stop methods send broadcasts. **Important boundary:** these service descriptors are referenced by the visible primary DEX but their class definitions are not present in its class-definition table. Their implementations therefore remain unavailable in the inspected visible DEX and may be protected, dynamically supplied or external; the helper-to-service mapping is confirmed, but the service internals are not.

These referenced service descriptors show that more than one service/forwarding path is intended. Their implementations are not available in the inspected primary DEX, and the APNA `category`/`method` to service mapping is not yet proven.

Do not infer that a payload whose category contains `xray` is directly an Xray JSON config. It may select a local forwarding helper, a SOCKS endpoint, a DNS component, or a protected runtime class. The explicit UDPGW fields and `--udpgw-transparent-dns` flag now make a BadVPN-style UDP gateway the leading explanation for the TUN UDP path. The actual APNA UDPGW endpoint, protocol version and protected service that supplies it remain unverified; `UDP Connected` alone does not establish that the gateway handshake succeeds.

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

- [x] Recover method signatures for `startClienteSSH`, `startForwarder(int)`, `formatCustomPayload(String, int, String)`, `injectSplitPayload(String, OutputStream)` and `injectSimpleSplit(String, OutputStream)`.
- [ ] Recover all call sites and trace the arguments that populate those methods.
- [ ] Trace how the selected server record and payload record populate the SSH client and forwarder settings.
- [ ] Determine the exact `[ssh]` placeholder substitution and CR/LF token behavior.
- [ ] Identify the SSH library/service implementation and its authentication/host-key policy.
- [x] Confirm the Android TUN settings explicitly carry a SOCKS endpoint, DNS resolver/forwarding controls, UDP gateway endpoint and transparent-DNS flag.
- [ ] Determine local SOCKS/HTTP listener ports and which listener receives TUN traffic.
- [x] Map explicit service launch targets: SSH → `SalamanderService`, XRay → `XRayDNSService`, SOCKS/HTTP → `SocksDNSService`.

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
- The protected runtime and dynamically loaded class definitions are not fully reconstructed. In particular, `OpenVPNClient`, `SalamanderService`, `SocksDNSService`, and `XRayDNSService` are referenced by descriptors but are not defined in the inspected primary DEX class table.
- No real server credentials or raw decrypted catalog records are included in this document.
- This static analysis does not prove that any current APNA endpoint is online or accepts a connection.
- CI success and a Windows artifact do not prove APNA compatibility. Real Windows handshake, routed traffic, DNS/IPv4/IPv6 and disconnect tests remain mandatory.
