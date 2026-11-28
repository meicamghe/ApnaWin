# Xray non-SSH tunnel security review — PR #8 research branch

## Scope

Reviewed the Xray share-link parser, TUN config builder, elevated supervisor, Qt connection worker and Windows traffic probe on `re/apk-native-extract`. These files are not present on current `main`; this is a review of the PR branch, not a claim that the functionality is released or integrated into the mainline application.

## Implemented generic protocol coverage on the PR branch

- Share-link parsing: VLESS, VMess, Trojan, Shadowsocks and Hysteria2.
- Transport subset: RAW/TCP, WebSocket and gRPC, with TLS/REALITY handling where supported.
- Unknown URI parameters and unsupported transports fail closed.
- Hysteria2 Salamander obfuscation is mapped to Xray FinalMask.
- Parsed links can be composed into a dual-stack Windows TUN config.
- The config uses IPv4 and IPv6 default routes, DNS entries and WFP leak-filter settings; no direct/freedom fallback outbound is emitted.
- A worker owns the elevated helper lifecycle and does not emit connected until the traffic probe returns.

This is generic Xray protocol support. It does not identify the proprietary APNA engine or prove compatibility with APNA provider profiles, credentials or endpoints.

## Security gap: route check is not socket pinning

`WindowsTunnelTrafficProbe.verify()` currently:
1. checks adapter/routes/DNS readiness;
2. resolves the probe hostname;
3. asks Windows which interface would route to each DNS server and destination IP;
4. creates a TCP socket using `socket.create_connection`;
5. completes TLS and a short HTTP request.

The route lookup and the subsequent socket connect are separate operations. A route change between them is a TOCTOU window. The socket is not explicitly pinned to the checked interface. WFP policy may provide an additional leak barrier, but the current probe does not independently prove that the actual socket used the ApnaWin interface.

Windows Winsock supports interface selection on unicast sockets:
- IPv4: `IPPROTO_IP / IP_UNICAST_IF`; the interface index is supplied in network byte order.
- IPv6: `IPPROTO_IPV6 / IPV6_UNICAST_IF`; the interface index is supplied in host byte order.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
- https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options

Recommended fix before treating the probe as a leak-proof acceptance gate:
- Create the socket explicitly for the resolved address family.
- Set the matching unicast-interface socket option to the ApnaWin interface index before connect.
- Fail closed if the option is unavailable or setting it fails.
- Keep the route lookup as an additional diagnostic, not as a substitute for socket pinning.
- Add tests proving both IPv4 and IPv6 socket options are applied before connect and failures prevent any connection attempt.

The system resolver call is still separate from this TCP socket. DNS leak protection therefore continues to depend on the configured WFP/DNS policy and should be validated with Windows packet capture or an equivalent independent network trace.

## Other reliability findings

- The traffic probe performs a single `recv(4096)`; HTTP status parsing can false-negative if the status line arrives fragmented. A bounded read-until-CRLF parser would be more reliable.
- Resolver injection has no explicit timeout at the call site; cancellation may be delayed while DNS resolution blocks.
- The worker's stop event is checked before and after the probe, but the probe itself is not cooperatively cancellable.
- Unit tests use mocked sockets/routes and do not constitute live Windows TUN acceptance.

## Release gate

Do not claim leak-free full-tunnel operation until the socket is pinned to the intended interface and a real Windows test records IPv4, IPv6, DNS, TCP, UDP, disconnect and failure behavior. No Windows build or CI was run for this review. SSH remains excluded.
