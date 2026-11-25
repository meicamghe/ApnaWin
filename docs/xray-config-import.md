# Importing an authorized Xray TUN configuration

The single **Import…** menu exposes all import paths: ApnaWin metadata JSON, APNA encrypted catalog/APK, live APNA catalog fetch, and Xray JSON for a selected XRAY profile. The Xray JSON path accepts a complete Xray TUN configuration. The importer requires the strict dual-stack, DNS and WFP policy validated by `inspect_tun_inbound`; it does not accept partial-route or SOCKS-only configs as VPN profiles.

## Secret handling

- The imported JSON is validated in memory and encrypted with Windows DPAPI using the current-user scope and application-specific optional entropy.
- The encrypted store is written atomically to the same per-user AppData directory as profile metadata. It contains profile-name keys and base64 DPAPI ciphertext only; credentials and private keys are not stored in plaintext by ApnaWin.
- DPAPI uses `CRYPTPROTECT_UI_FORBIDDEN` and does not use the machine-wide scope. Another Windows user cannot decrypt the stored config.
- Renaming a profile moves its encrypted record. Removing a profile removes its encrypted config.
- Exporting profile metadata intentionally excludes the encrypted config. The user must separately retain their original authorized config source.

The raw JSON file selected by the user remains wherever the user originally stored it; ApnaWin does not delete or overwrite that source file. The import process reads it with a 16 MiB cap and stores only the DPAPI ciphertext.

## Validation limits

The importer rejects duplicate JSON keys, non-finite constants, invalid UTF-8, malformed TUN settings, incomplete IPv4/IPv6 default routes, missing DNS servers, unsafe outbound-interface binding, missing WFP leak-protection filters, direct `freedom`/`loopback` outbounds, unsupported outbound protocols, and a non-proxy primary outbound. At connection start, the elevated helper runs Xray's `run -test -c`, verifies the pinned runtime hashes, checks effective routes/DNS, and requires a certificate-validated external TLS egress probe. It still does not prove provider-specific application traffic or credentials beyond the Xray runtime test and actual egress probe.

Historical note: an earlier checkpoint had Connect disabled and only an IPv4 egress probe. That status is superseded. Current Windows implementation wires Connect/Disconnect to the supervised Xray TUN engine for imported XRAY profiles with validated encrypted configs. The fixed-path, Program Files-installed helper validates the protected Xray/Wintun runtime manifest and Xray config, refuses to reuse an existing adapter, and checks the adapter, effective IPv4/IPv6 default routes and configured DNS. Before reporting ready, it requires certificate-validated external TLS egress probes through the TUN for both IPv4 and IPv6; it monitors local readiness and egress and gracefully stops Xray after repeated failures. These probes establish generic dual-stack tunnel egress from the test process, not provider-specific authentication/application traffic or exhaustive leak-proof behavior. Clean-machine Windows 10/11 acceptance for WFP leak behavior, crash/reboot cleanup and real provider traffic remains a separate release gate.

## Share-link import contract

The separate share-link parser in `src/apnawin/engines/xray_share_link.py` accepts VLESS, VMess, Trojan and Shadowsocks URI forms and converts them into the same encrypted TUN-profile path. Supported stream transports are TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP; TLS and the supported TCP/gRPC/XHTTP REALITY combinations are validated before config creation.

Import is deliberately strict:
- Duplicate query parameters and duplicate VMess JSON keys are rejected rather than silently selecting one value.
- TLS certificate verification cannot be disabled through a share link. TLS SNI, ALPN, REALITY fields and transport paths are bounded and checked for control characters.
- Trojan credentials must be one URL user-info value; a literal colon in the password must be percent-encoded. Shadowsocks passwords reject control characters and invalid UTF-8 credential encodings.
- Unrecognized URL paths on authority-based VLESS/Trojan links are rejected instead of being silently ignored.
- VMess non-zero `alterId`, unsupported cipher methods, unsupported transports and SIP003 Shadowsocks plugins are rejected.
- REALITY public keys and short IDs are structurally validated. A structurally valid link is not proof that the remote endpoint is reachable or that its credentials are correct.

WireGuard `.conf` import additionally enforces one Interface, bounded peer count, unique peer public keys, unique AllowedIPs within and across peers, usable unique DNS addresses, and both IPv4 and IPv6 default routes. This matches the product's full-tunnel dual-stack policy; ambiguous multi-peer routing and split-tunnel-only profiles are rejected rather than silently producing partial connectivity.

The importer does not enable legacy SSH/Xray cryptography, infer APNA catalog category mappings, or claim a connection based on successful parsing. The pinned Xray executable's `run -test` is the configuration compatibility gate; a real tunnel still requires endpoint reachability and routed-traffic acceptance.

## User workflow

1. Add or select an XRAY profile.
2. Open **Import…** and choose **Xray JSON**.
3. Select a complete, authorized Xray JSON configuration with one TUN inbound.
4. ApnaWin validates and encrypts it for the current Windows user.
5. The profile details show that an encrypted TUN config is present. This does not mean the VPN is connected.

The Xray runtime supports protocol outbounds including VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard, Hysteria and MASQUE when the installed Xray build supports the supplied configuration. The actual runtime `run -test` remains authoritative. UDP is protocol/transport-dependent: APNA profiles remain visible when the catalog omits `server_udp_port`; those profiles can carry TCP traffic, while UDP forwarding and transparent DNS require a published UDPGW endpoint. Standalone APNA catalog categories such as `ocsudp`, Trojan, V2Ray and Xray are not guessed into credentials or transport settings from their category labels.

No APNA endpoint, credential, server list or authentication format is inferred from the profile's host and port fields.

## Non-SSH live Windows acceptance matrix — 2026-11-24

The imported Xray-family profiles use the same supervised Windows TUN, dual-stack route and WFP leak-protection path. Validate each imported profile independently; a successful Xray `run -test` proves configuration compatibility only.

| Profile family | Protocol-specific evidence required | Important boundary |
|---|---|---|
| VLESS / VMess / Trojan | Successful server handshake and authenticated HTTPS request through the tunnel; exercise the selected TCP/WS/gRPC/HTTPUpgrade/XHTTP/mKCP transport | A valid share link and Xray config test do not prove the server accepts its UUID/password, TLS/REALITY identity or transport path |
| Shadowsocks | Successful encrypted session using the selected supported cipher, then routed TCP and UDP tests where the endpoint supports UDP | SIP003 plugins are rejected; verify the server's actual cipher and password |
| Hysteria 2 | Successful QUIC session, authenticated traffic, packet-loss/reconnect behavior and non-DNS UDP round-trip | The importer requires verified TLS and rejects unsupported obfuscation, ECH and pinning options |
| WireGuard | Successful peer handshake, transfer counters increasing in both directions, and routed IPv4/IPv6 traffic | Verify peer AllowedIPs, endpoint, keys and DNS from the provider-issued config; multiple peers must be tested with the intended routing policy |
| MASQUE | Successful CONNECT-IP session over the configured verified TLS/HTTP/2 or HTTP/3 path, followed by routed IPv4/IPv6 traffic | The current importer accepts one outbound, no Mux, and only the validated TLS subset |
| HTTP / HTTPS proxy | Successful authenticated or unauthenticated TCP request through the proxy | These are TCP proxy outbounds, not encrypted VPN protocols; plain HTTP is unencrypted and UDP tunneling is not claimed |
| SOCKS5 | Successful authenticated or unauthenticated TCP request through SOCKS5 | This importer path is TCP-only and is not a standalone encrypted VPN protocol |

For every profile, record separately: imported protocol and transport, Xray runtime validation, server handshake, HTTPS over IPv4, HTTPS over IPv6, DNS resolver and physical-interface leak observations, a controlled non-DNS UDP flow where the protocol supports it, disconnect, and route/DNS restoration. Do not use a successful DNS query as a substitute for a non-DNS UDP test.

The UI's generic startup egress probes establish that the helper can reach independent IPv4 and IPv6 TLS endpoints through the configured TUN path. They do not independently prove that the selected provider accepted the profile or that every application protocol is forwarded correctly. Profiles that cannot carry a required traffic class must be documented as limited; they must never fall back to direct physical-interface routing.

