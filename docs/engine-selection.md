# Windows transport engine assessment

## Current implementation — 2026-11-25

The Windows desktop composition root creates the live connection controller only when the protected Program Files installation helper is present and safe.

- **APNA SSH** → `ApnaTunnelEngine`.
- **Xray** → `XrayTunnelEngine`; this engine runs Xray-core with Wintun for the full-tunnel path and supports explicit imported Xray outbound configurations.
- **UDPQ** → `UdpqTunnelEngine`, conditionally registered only when the Windows x64 sidecar, runtime manifest, pinned StarUDP source commit, reviewed redaction-patch hash and executable SHA-256 all validate. This is an experimental generic manual-profile path, not an APNA catalog mapping.
- **OpenVPN** and standalone **SOCKS** enum values remain metadata only; no production engine is registered for them.

### Xray runtime

`scripts/Install-VpnRuntime.ps1` pins Xray-core v26.11.9 and Wintun 0.14.1. The importer supports VLESS, VMess, Trojan and Shadowsocks share links; the Xray runtime also has explicitly modeled WireGuard, Hysteria 2 and MASQUE outbound paths. HTTP/SOCKS outbounds are proxy modes, not encrypted VPN protocols.

### UDPQ / libudpqtwo evidence boundary

Static comparison of APNA v51 ARM64 and UDP Thunder 1.5 ARM32 `libudpqtwo.so` samples found matching StarUDP-family Go wire-structure and JSON-config fingerprints. This strongly supports a StarUDP/Hysteria-v1-derived code lineage.

It does **not** establish APNA's service ownership, exact source revision, effective ALPN/SNI/auth/rate/packet-mode/obfuscation/hopping settings, or a successful APNA handshake. The Windows sidecar is therefore deliberately labeled generic and experimental. Do not automatically map APNA catalog categories to UDPQ.

### APNA category mapping

Only the four SSH-family categories `ocsws`, `ocscf`, `ocsnormal` and `ocshttp` are mapped by the APNA SSH importer. Categories such as `ocsv2ray`, `ocsxray`, `ocstrojan`, `ocsshadow` and UDP-labelled categories remain unmapped until the protected v51 selection/configuration contract is independently verified.

### Other engine families

- **BadVPN:** separate pinned Windows native research build; not integrated because its upstream TUN backend targets TAP-Windows rather than ApnaWin's Wintun interface.
- **Android native libraries:** ARM64 ELF files cannot be reused as Windows x64 runtimes.

## Acceptance gates

1. Independently verify an authorized APNA provider's SSH host key and complete authentication.
2. Verify an actual APNA UDPGW datagram round-trip.
3. Verify routed TCP, UDP and DNS traffic through Wintun, including IPv4 and IPv6.
4. Verify DNS leak protection, startup rollback, disconnect and abnormal-process cleanup.
5. Test generic UDPQ separately against an authorized StarUDP-compatible server; do not treat that as APNA acceptance.
6. Repeat relevant acceptance on clean Windows 10/11 hosts with redacted diagnostics and recorded runtime hashes.

CI success, config validation, process startup and local UDPQ loopback tests are not substitutes for live provider authentication and routed traffic. Keep PR #6 Draft and unmerged until APNA acceptance gates pass.
