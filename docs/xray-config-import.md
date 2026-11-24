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

The Connect button remains disabled. A fixed-path, Program Files-installed UAC helper and desktop-side process supervisor are now implemented. Before signaling ready, the helper verifies the protected Xray/Wintun runtime manifest, validates the TUN config with Xray, refuses to reuse an existing adapter, and waits for the adapter, effective IPv4/IPv6 default routes and configured DNS to remain healthy. It continues monitoring those local conditions and gracefully stops Xray after repeated failures. The helper additionally requires a certificate-validated TLS handshake to one of two independent public endpoints through the system TUN route before reporting ready. This proves basic IPv4 egress from a non-Xray process through the configured tunnel; it does not prove APNA-specific application traffic, IPv6 egress, or all leak cases. The desktop Connect flow is now wired to the supervised Xray TUN engine. The current UI enables Connect only for imported XRAY profiles with stored validated configs, runs connection work off the UI thread, reports the helper's verified readiness state, and exposes Disconnect for CONNECTED/ERROR states. The historical statement above about the UI not being wired is superseded by the 2026-11-24 implementation. Clean-machine Windows 10/11 acceptance for WFP leak behavior, crash/reboot cleanup, and real provider application traffic remains a separate release gate.

## Share-link import contract

The separate share-link parser in `src/apnawin/engines/xray_share_link.py` accepts VLESS, VMess, Trojan and Shadowsocks URI forms and converts them into the same encrypted TUN-profile path. Supported stream transports are TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP; TLS and the supported TCP/gRPC/XHTTP REALITY combinations are validated before config creation.

Import is deliberately strict:
- Duplicate query parameters and duplicate VMess JSON keys are rejected rather than silently selecting one value.
- TLS certificate verification cannot be disabled through a share link. TLS SNI, ALPN, REALITY fields and transport paths are bounded and checked for control characters.
- Trojan credentials must be one URL user-info value; a literal colon in the password must be percent-encoded. Shadowsocks passwords reject control characters and invalid UTF-8 credential encodings.
- Unrecognized URL paths on authority-based VLESS/Trojan links are rejected instead of being silently ignored.
- VMess non-zero `alterId`, unsupported cipher methods, unsupported transports and SIP003 Shadowsocks plugins are rejected.
- REALITY public keys and short IDs are structurally validated. A structurally valid link is not proof that the remote endpoint is reachable or that its credentials are correct.

The importer does not enable legacy SSH/Xray cryptography, infer APNA catalog category mappings, or claim a connection based on successful parsing. The pinned Xray executable's `run -test` is the configuration compatibility gate; a real tunnel still requires endpoint reachability and routed-traffic acceptance.

## User workflow

1. Add or select an XRAY profile.
2. Open **Import…** and choose **Xray JSON**.
3. Select a complete, authorized Xray JSON configuration with one TUN inbound.
4. ApnaWin validates and encrypts it for the current Windows user.
5. The profile details show that an encrypted TUN config is present. This does not mean the VPN is connected.

The Xray runtime supports protocol outbounds including VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard, Hysteria and MASQUE when the installed Xray build supports the supplied configuration. The actual runtime `run -test` remains authoritative. UDP is protocol/transport-dependent: APNA profiles remain visible when the catalog omits `server_udp_port`; those profiles can carry TCP traffic, while UDP forwarding and transparent DNS require a published UDPGW endpoint. Standalone APNA catalog categories such as `ocsudp`, Trojan, V2Ray and Xray are not guessed into credentials or transport settings from their category labels.

No APNA endpoint, credential, server list or authentication format is inferred from the profile's host and port fields.
