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
- Credential and header/path values reject all Unicode control characters, including C1 controls, not only ASCII CR/LF/TAB.
- TLS/REALITY-only parameters cannot be silently supplied with `security=none`; REALITY requires `sni`, `fp` and `pbk` and is limited to RAW/TCP or gRPC in this first slice.
- WebSocket and gRPC parameters are accepted only with their matching transport; unsupported gRPC modes are rejected.
- Legacy Shadowsocks whole-payload Base64 links preserve standard Base64 path characters such as `/`.

## Verification

The full-suite run [45798144029](https://github.com/meicamghe/ApnaWin/actions/runs/45798144029) passed 907 tests, with 1 skipped and 1 warning on PR #8 head `6db562a7d0363551868c5053abc4f7358ae2c434`, including the VLESS ID and Vision-flow regression tests. Windows packaging was skipped by the reverse-engineering gate. The parser still has no UI integration and does not enable Connect.


## Strict decoding and JSON types

The parser rejects incomplete/non-hex percent escapes before URL parsing and rejects percent-encoded byte sequences that are not valid UTF-8. This applies to credentials, query values and profile fragments; malformed escapes are never silently preserved or replacement-decoded. VMess textual fields are type-checked as JSON strings rather than coerced with `str()`, preventing arrays, objects and booleans from becoming plausible-looking transport settings.


## VLESS identifier and Vision-flow validation

The current Xray VLESS outbound contract accepts a valid UUID or a custom user ID of fewer than 30 UTF-8 bytes. Longer non-UUID values are rejected before an outbound object is produced. Vision flow is restricted to the documented `xtls-rprx-vision` and `xtls-rprx-vision-udp443` values and requires TCP/RAW plus TLS or REALITY in this parser's supported transport subset. Unknown flow strings, Vision over WebSocket/gRPC, and Vision without transport security fail closed.

References: [Xray VLESS outbound](https://xtls.github.io/en/config/outbounds/vless.html) and [Xray transport compatibility](https://xtls.github.io/en/config/transport.html).


## VMess link version gate

- VMess JSON links default a missing `v` field to version `2`, matching the commonly emitted v2 share-link format.
- Explicit version values other than `2` are rejected rather than interpreted using an unknown schema.
- Regression tests cover absent version and unsupported/empty explicit versions.


## Hysteria2 share links

- Added `hysteria2://` and `hy2://` parsing, with optional authentication, default port 443, IPv4/IPv6 host handling, SNI, TLS ALPN `h3`, and Salamander UDP obfuscation.
- Maps to the current Xray Hysteria v2 outbound (`protocol: hysteria`, `settings.version/address/port`, `streamSettings.method: hysteria`, TLS security and `hysteriaSettings.version/auth`). Salamander maps to `streamSettings.finalmask.udp`.
- TLS verification is forced on. Explicit `insecure=1`, unsupported obfuscation modes, orphan obfuscation passwords, unknown query parameters and non-root URI paths are rejected. Hysteria Realm URIs, port hopping, ECH and certificate pinning are not supported in this first slice.
- References: [official Hysteria 2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/), [Xray Hysteria outbound](https://xtls.github.io/en/config/outbounds/hysteria.html), [Xray Hysteria transport](https://xtls.github.io/en/config/transports/hysteria.html), [Xray FinalMask](https://xtls.github.io/en/config/transports/finalmask.html).
- Regression tests cover aliases, IPv6, defaults, SNI, Salamander mapping, credential-safe repr and fail-closed handling.
