# APNA Tunnel Lite primary-DEX connection and payload findings

Date: 2026-11-16  
APK: `com.apnatunnel.lite`, supplied `base.apk`, SHA-256 `b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d`

## Payload formatter recovered from the primary DEX

Class/method: `prince.open.vpn.service.vpn.TunnelUtils.formatCustomPayload(String, int, String)`.

The method body was decoded from the supplied primary `classes.dex`, not inferred solely from a sibling project.

Observed operations:
- Creates an ordered `ArrayMap` of placeholder substitutions.
- Reads the runtime HTTP user-agent with `System.getProperty("http.agent")`; if absent, uses the Chrome 44 / Windows 8.1 fallback string visible in the DEX.
- Contains literal map keys `[ssh]`, `[crlf]`, `[cr]`, `[lf]`, `[lfcr]`, escaped `\\n` and `\\r`.
- Other map keys/values are fetched through LIAPP-obfuscated string accessors. The method's constant/register flow and exact signature match the public SecondVPN formatter implementation. The high-confidence mapping is `[method] -> CONNECT`, `[host] -> hostname`, `[port] -> decimal port`, `[host_port] -> hostname:port`, `[protocol] -> HTTP/1.0`, and `[ua] -> runtime/fallback user-agent`.
- Replaces keys in map insertion order, lowercasing the key before calling `String.replace`.
- Calls `parseRotate` only after placeholder replacement.

The compiler at `src/apnawin/engines/apna_payload.py` now follows this order, includes the method/user-agent tokens, leaves unobserved `[ip]` and `[vpn]` aliases out, and applies rotation after host/port expansion.

## Split injection verified from DEX bytecode

- `injectSimpleSplit(String, OutputStream)` checks its obfuscated split token, uses `Pattern.quote` and Java `String.split`, writes each segment using `ISO-8859-1`, and flushes after each segment. The corresponding literal `[instant_split]` is present in the DEX string table.
- `injectSplitPayload(String, OutputStream)` splits on its obfuscated delay token, calls `injectSimpleSplit` for each segment, and otherwise writes/flushed raw segments using `ISO-8859-1`. The corresponding literal `[delay_split]` is present in the DEX string table.
- Immediately before `Thread.sleep(long)`, the method loads `const-wide/16 1000`. Therefore the inter-segment delay is exactly **1000 ms in this APK**, not merely a sibling-derived default.
- Java `String.split` discards trailing empty segments; the Python compiler now mirrors that behavior.
- `parseRotate` uses a regex matcher, resets its index map when the formatted payload changes, splits the rotate values on semicolon, and replaces matching expressions. The Android implementation uses `String.replace`, so identical rotate expressions are replaced together.

## Actual tunnel composition in the APK

The primary DEX identifies these components and fields:

1. `TunnelManagerHelper.startSsh(Context)` constructs an Intent for `prince.open.vpn.service.SalamanderService`.
2. `TunnelManagerHelper.startSocksHttp(Context)` starts `SocksDNSService`; `startXRay(Context)` starts `XRayDNSService`. Their class descriptors exist, but their implementations are not defined in the inspected primary DEX.
3. `TunnelVpnSettings` contains `mSocksServer`, `mDnsResolver`, `mDnsForward`, `mUdpResolver`, and `mUdpDnsRelay`.
4. `TunnelVpnManager.runTunnel` passes those values to `Tunnel.startTunneling(String, String[], boolean, String, boolean)`.
5. `Tunnel.startTunneling` calls `routeThroughTunnel`. That path creates a local `Pdnsd` resolver using an available port starting at 8091, then creates/starts `Tun2Socks`.
6. The `Tun2Socks` class contains `mSocksServerAddress`, `mUdpgwServerAddress`, `mDnsResolverAddress`, and `mUdpgwTransparentDNS`. Its process command construction contains the literal `--udpgw-transparent-dns`.
7. A separate `Tunnel$2` path calls `org.uproxy.tun2socks.Tun2SocksJni.runTun2Socks` with TUN fd, MTU, VPN address/netmask, SOCKS endpoint, UDP relay endpoint, DNS resolver and transparent-DNS options. This JNI entry point is present even though the normal `startTunneling -> routeThroughTunnel` path creates the process-based `Tun2Socks` runner.

**Implication for ApnaWin:** a TCP-only SSH dynamic forwarder is not sufficient for full APNA compatibility. The Windows runtime needs the local SOCKS TCP endpoint, the separate UDPGW stream when `mUdpResolver` is configured, and the DNS resolver/transparent-DNS behavior. The current Paramiko adapter supplies only authenticated SSH TCP forwarding; the UDPGW codec/flow manager are separate building blocks and are not yet connected to a live TUN path.

## Remaining unknowns

- The protected `SalamanderService` implementation, SSH authentication/key handling, local SOCKS port selection and SSH reconnect policy.
- Exact APNA catalog field-to-`TunnelVpnSettings` mapping for `mSocksServer`, `mUdpResolver`, `mUdpDnsRelay` and DNS resolver values.
- Whether the active service chooses SOCKS5 UDP or UDPGW for each server/profile type.
- The actual server-side UDPGW host/port and transparent-DNS policy for a valid APNA profile.
- The ABI split/native binary used by the APK. The supplied base APK has no ELF `.so`; its native library path is resolved at runtime through `ApplicationInfo.nativeLibraryDir` / extracted app data.

No server address, port, username or password has been guessed. The next implementation gate is recovering the protected service/catalog mapping and building a Windows UDPGW-capable data path, then testing it with an authorized real profile.
