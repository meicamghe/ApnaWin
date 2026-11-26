# Windows full-tunnel path using Xray TUN

## Decision

Use Xray-core's native `tun` inbound on Windows rather than implementing a second Wintun packet engine and separate route/DNS stack in Python. The upstream Windows implementation already creates/reuses a Wintun adapter, starts its ring session, reads and writes packets, configures interface addresses and MTU, applies routes and DNS, binds Xray's own outbound sockets to the physical interface, and can install Windows Filtering Platform leak filters.

This removes duplicate networking code and keeps packet routing, tunnel stack, and Xray's outbound engine in one process. A Python-level Wintun FFI must not be used alongside Xray's own TUN inbound.

## Required runtime layout

- `xray.exe`: separately installed, pinned Windows x64 Xray-core build with TUN support.
- `wintun.dll`: matching Windows x64 Wintun library located beside `xray.exe`, as required by Xray's Windows TUN implementation.
- Xray JSON config: one `tun` inbound plus the authorized server outbound(s).

The Windows build now downloads pinned Xray-core v26.11.9 and Wintun 0.14.1 archives through `scripts/Install-VpnRuntime.ps1`, verifies both archive SHA-256 values, checks both PE files are AMD64, validates the Wintun Authenticode signature/publisher, checks the Xray version, and includes the upstream license notices plus a generated runtime manifest. Xray's archive SHA-256 is pinned to `1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`; Wintun's official archive SHA-256 is `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`. The executable and DLL are still not signed by ApnaWin; the runtime manifest records the verified file hashes.

## Strict config policy implemented in the runner

The runner accepts exactly one supported inbound. For TUN mode it requires:
- `protocol: "tun"`, with `port` omitted or set to zero and no listen socket;
- a bounded adapter name and description;
- MTU in the range 576–9000;
- one usable IPv4 gateway prefix and one usable IPv6 gateway prefix;
- one to eight unique DNS server addresses;
- both `0.0.0.0/0` and `::/0` in `autoSystemRoutingTable`;
- `autoOutboundsInterface: "auto"` to prevent Xray's own server connections looping into the tunnel;
- exactly `autoSystemWfpBlockLeak: ["allexceptlan", "dns"]`, which includes DNS leak blocking and blocks non-LAN traffic from escaping outside the TUN while preserving local-LAN traffic;
- the first outbound must be a supported remote proxy protocol (`vless`, `vmess`, `trojan`, `shadowsocks`, `socks`, `http`, `wireguard`, `hysteria` or `masque`); direct `freedom`, local `loopback`, unsupported protocols and any later direct outbound are rejected. `blackhole` is allowed only as a non-primary auxiliary outbound. The special `dns` outbound is rejected until its resolver detour can be validated against the no-leak policy.

The full config is then checked by Xray's own `run -test -c` command. The Python validator is deliberately stricter than the general Xray schema: it rejects partial/split-tunnel configurations and unsafe leak-protection settings for this product's full-tunnel mode.

The `allexceptlan` WFP policy is strict and can affect captive portals, other VPNs, virtual machines and local networks using non-standard address ranges. It must not be silently weakened if WFP installation fails.

## Lifecycle and cleanup

The upstream Windows TUN implementation's graceful close path unregisters route/interface callbacks, restores outbound-interface guard settings, flushes IPv4/IPv6 routes, addresses and DNS, closes WFP filters, restores resolver state, wakes any pending packet reader, ends the Wintun session and closes the adapter. Startup errors in the TUN handler call the close path.

Forced process termination is different: it bypasses Go cleanup code. The upstream WFP documentation states its filters are removed when Xray exits, but route/address/DNS and adapter state after an abrupt kill must be validated on Windows rather than assumed. Required tests:
1. graceful disconnect restores the pre-connection route/DNS/interface snapshot;
2. terminate Xray during each TUN startup phase and inspect routes, DNS, WFP and adapter state;
3. kill the desktop or helper while Xray remains active;
4. restart the helper and reconcile stale ApnaWin-owned resources only;
5. reboot after forced termination and verify no persistent route or DNS damage;
6. verify the physical interface is used for Xray's own outbound sockets and no routing loop occurs;
7. test DNS, IPv4 and IPv6 leak paths while connected and when the TUN fails.

## Privilege boundary

Creating a Wintun adapter and modifying Windows routes, DNS and WFP requires an elevated execution context. The Xray runner checks `IsUserAnAdmin` and refuses to start TUN without an elevated token. The desktop remains medium-integrity and launches a fixed-path helper from Program Files through the UAC `runas` flow. The helper validates the installed runtime hashes, decrypts only the selected current-user DPAPI config, and supervises Xray in a kill-on-close Job Object. The parent can request graceful shutdown; forced termination is only a timeout fallback. The helper performs a certificate-validated IPv4 TLS egress probe through the system TUN route before signaling ready. This is a basic data-plane smoke test, not a provider-specific traffic test or proof of IPv6 egress. The Windows desktop is now wired to this supervisor; Connect is enabled only when the protected helper and an encrypted imported TUN profile are available. Connected means local readiness checks passed, not that APNA-specific service traffic has been accepted. Xray's native WFP leak filters are process-owned and are removed when Xray exits; ApnaWin does not yet provide an independent persistent kill switch. Forced termination bypasses Xray cleanup, so route, DNS and adapter recovery still require clean-machine Windows acceptance. Do not describe the release as leak-free or APNA-compatible until IPv4/IPv6/DNS leak tests, abrupt-exit and reboot recovery, and authorized APNA traffic tests pass on Windows 10/11.

## Binary provenance

- Xray v26.11.9 Windows x64 release: https://github.com/XTLS/Xray-core/releases/tag/v26.11.9
- Xray v26.11.9 package hash reference: https://github.com/ScoopInstaller/Main/blob/master/bucket/xray.json
- Wintun 0.14.1 official release and archive SHA-256: https://www.wintun.net/

## References

- Xray TUN configuration: https://xtls.github.io/en/config/inbounds/tun.html
- Xray Windows TUN implementation: https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows.go
- Xray TUN lifecycle handler: https://github.com/XTLS/Xray-core/blob/main/proxy/tun/handler.go
- Xray TUN Windows WFP implementation: https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows_wfp.go
- Wintun deployment guidance: https://github.com/WireGuard/wintun


The separate `dns` filter is intentional in addition to `allexceptlan`: Xray's WFP implementation leaves local-LAN destinations open under `allexceptlan`, and its own source explicitly notes that a router DNS resolver may remain reachable there. Adding `dns` applies the DNS block to those LAN exceptions as well, preventing the physical-interface DNS path from bypassing the TUN.
