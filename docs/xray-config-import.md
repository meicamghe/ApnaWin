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

The Connect button remains disabled. A fixed-path, Program Files-installed UAC helper and desktop-side process supervisor are now implemented. Before signaling ready, the helper verifies the protected Xray/Wintun runtime manifest, validates the TUN config with Xray, refuses to reuse an existing adapter, and waits for the adapter, effective IPv4/IPv6 default routes and configured DNS to remain healthy. It continues monitoring those local conditions and gracefully stops Xray after repeated failures. The helper additionally requires a certificate-validated TLS handshake to one of two independent public endpoints through the system TUN route before reporting ready. This proves basic IPv4 egress from a non-Xray process through the configured tunnel; it does not prove APNA-specific application traffic, IPv6 egress, or all leak cases. The desktop UI is not yet wired to the supervisor, and clean-machine WFP leak plus crash/reboot cleanup acceptance tests are still pending.

## User workflow

1. Add or select an XRAY profile.
2. Open **Import…** and choose **Xray JSON**.
3. Select a complete, authorized Xray JSON configuration with one TUN inbound.
4. ApnaWin validates and encrypts it for the current Windows user.
5. The profile details show that an encrypted TUN config is present. This does not mean the VPN is connected.

The Xray runtime supports protocol outbounds including VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard, Hysteria and MASQUE when the installed Xray build supports the supplied configuration. The actual runtime `run -test` remains authoritative. UDP is protocol/transport-dependent: APNA full-tunnel profiles require a catalog-provided UDPGW port; records without `server_udp_port` are rejected during mapping rather than imported as profiles that cannot connect. Standalone APNA catalog categories such as `ocsudp`, Trojan, V2Ray and Xray are not guessed into credentials or transport settings from their category labels.

No APNA endpoint, credential, server list or authentication format is inferred from the profile's host and port fields.
