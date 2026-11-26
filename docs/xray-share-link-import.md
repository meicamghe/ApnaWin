# Xray share-link parsing milestone

## Scope

`src/apnawin/services/proxy_share_link.py` parses individual share links for VLESS, VMess, Trojan and Shadowsocks into Xray outbound objects. It is a protocol-import foundation only; it is not connected to the UI or connection lifecycle yet.

Supported inputs:
- `vless://` links with TCP/RAW, WebSocket or gRPC; TLS or REALITY; user ID, encryption and flow.
- `vmess://` Base64 JSON links with TCP/RAW, WebSocket or gRPC and optional TLS.
- `trojan://` links with TLS or REALITY and TCP/RAW, WebSocket or gRPC.
- `ss://` SIP002 Base64 user-info, plaintext SIP002 user-info and legacy whole-payload Base64 links for the supported Xray cipher set.

The parser rejects duplicate and unknown query parameters, unsupported transports, non-zero legacy VMess alterId, Trojan without transport security, unsupported Shadowsocks plugins/ciphers, malformed Base64, invalid ports and oversized input. It does not silently discard URI extensions it does not understand.

## Security boundaries

- Parsed objects hide credential-bearing fields from their repr; do not log raw links or outbound dictionaries.
- to_outbound() returns secrets in memory because Xray requires them. The caller must store the resulting configuration only in the existing current-user DPAPI-protected config store.
- The parser does not fetch subscription URLs, follow redirects, resolve hostnames, contact servers, verify credentials, or infer provider-specific API formats.
- It does not enable Connect, create a TUN inbound, change routes or DNS, or claim that a profile works.
- UI integration and full-tunnel configuration composition remain pending.

## Deliberate limits

The first slice supports common RAW/TCP, WebSocket and gRPC links. XHTTP, mKCP, HTTPUpgrade, plugin-based Shadowsocks and vendor-specific URI parameters are rejected until their exact Xray schema and security implications have dedicated tests. REALITY requires sni, fp and pbk; the parser does not guess missing parameters. VLESS without transport security remains parseable because VLESS Encryption and trusted private-peer cases exist, but the connection layer must validate the selected mode before use.

## Upstream schema references

- Project X VLESS outbound: https://xtls.github.io/en/config/outbounds/vless.html
- Project X VMess outbound: https://xtls.github.io/en/config/outbounds/vmess.html
- Project X Trojan outbound: https://xtls.github.io/en/config/outbounds/trojan.html
- Project X Shadowsocks outbound: https://xtls.github.io/en/config/outbounds/shadowsocks.html
- Project X transport settings: https://xtls.github.io/en/config/transport.html

These links are used as the source of truth for the current outbound configuration shape. The parser intentionally does not claim compatibility with private APNA TUNNEL subscription/catalog formats.

## Multi-profile text import foundation

`parse_proxy_links()` accepts a plain UTF-8 text document containing one supported share link per line. Blank lines and full-line `#` comments are ignored. Parsing is all-or-nothing: one malformed or unsupported line rejects the batch with its line number, without echoing the credential-bearing link. Input is capped at 1 MiB and 500 profiles; each individual link retains the 16 KiB cap.

This is not a subscription downloader or provider API client. Base64-wrapped subscription responses, remote URLs, provider-specific metadata and unknown URI extensions are not guessed or decoded. Those formats need evidence from authorized provider samples before support is added.

## Additional validation

- Server names are checked with the same IP/IDNA hostname validator used by stored profile metadata.
- TLS/REALITY-only parameters cannot be silently supplied with `security=none`; REALITY requires `sni`, `fp` and `pbk` and is limited to RAW/TCP or gRPC in this first slice.
- WebSocket and gRPC parameters are accepted only with their matching transport; unsupported gRPC modes are rejected.
- Legacy Shadowsocks whole-payload Base64 links preserve standard Base64 path characters such as `/`.

## Verification

CI run [45795956357](https://github.com/meicamghe/ApnaWin/actions/runs/45795956357) passed 888 tests, with 1 skipped and 1 warning. Windows packaging was skipped by the reverse-engineering gate. The parser still has no UI integration and does not enable Connect.
