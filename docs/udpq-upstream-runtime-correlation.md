# UDPQ upstream/runtime correlation (pinned StarUDP source)

## Scope and evidence boundary

This note correlates the Windows sidecar currently built by ApnaWin with the pinned public StarUDP source at commit `23fa29bb4fad600330b30e2b703b8029ef091446`.

It is a source-level compatibility audit. It does **not** claim that APNA's protected runtime supplies these exact values, nor that a live APNA provider accepts the client.

Primary source files:
- [app/cmd/main.go](https://github.com/starrising321/starudp/blob/23fa29bb4fad600330b30e2b703b8029ef091446/app/cmd/main.go)
- [app/cmd/client.go](https://github.com/starrising321/starudp/blob/23fa29bb4fad600330b30e2b703b8029ef091446/app/cmd/client.go)
- [app/cmd/config.go](https://github.com/starrising321/starudp/blob/23fa29bb4fad600330b30e2b703b8029ef091446/app/cmd/config.go)
- [core/cs/client.go](https://github.com/starrising321/starudp/blob/23fa29bb4fad600330b30e2b703b8029ef091446/core/cs/client.go)
- [core/cs/protocol.go](https://github.com/starrising321/starudp/blob/23fa29bb4fad600330b30e2b703b8029ef091446/core/cs/protocol.go)

## Runtime facts confirmed from source

1. **CLI invocation:** `--no-check` is a persistent Cobra flag whose description is “disable update check”. It suppresses the asynchronous update-check routine; it does not disable config validation, TLS verification, or protocol authentication. The sidecar supervisor's `--no-check client --config <file>` invocation is therefore consistent with the pinned CLI.
2. **TLS:** the client sets TLS minimum version to TLS 1.3, passes the configured ALPN as `NextProtos`, sets `ServerName`, and only skips certificate verification when `insecure=true`. ApnaWin serializes `insecure=false`; certificate verification remains enabled.
3. **ALPN default:** upstream `DefaultALPN` is `hysteria`, applied by `clientConfig.Fill()` only when the config's ALPN is empty. APNA's inspected `libudpqtwo.so` did not contain the literal `hysteria`. Therefore this upstream default must **not** be treated as APNA's confirmed runtime ALPN.
4. **Authentication selection:** the upstream client uses `auth` as a byte slice when non-empty; otherwise it uses the UTF-8 bytes of `auth_str`. The sidecar currently writes `auth_str`. The APNA auth value and whether APNA supplies `auth` or `auth_str` remain unknown.
5. **QUIC:** upstream enables QUIC DATAGRAM, sets TLS 1.3, configures stream/connection receive windows and idle/handshake timeouts, and applies the configured packet-connection factory. Control-stream protocol version is 3.
6. **Client mode validation:** the CLI reads the JSON config, parses it, runs `clientConfig.Check()`, then calls `client()`; `client()` logs the config, fills defaults, and starts the connection. The config must specify a server, a speed at least the upstream minimum, and at least one local mode (SOCKS5, HTTP, TUN, relay, TProxy or redirect).
7. **Packet modes:** the pinned source maps empty/udp, wechat, wechat-video and faketcp. The Windows build supports udp, wechat and wechat-video; faketcp is explicitly unsupported by the non-Linux implementation.

## ApnaWin sidecar mapping

The current `UdpqClientConfig.to_json_bytes()` writes these upstream-compatible fields:

| ApnaWin field | JSON field | Source behavior |
|---|---|---|
| server host/port and optional port list | `server` | Parsed as the remote server address / UDP port hopping input |
| `protocol` | `protocol` | Selects UDP / WeChat packet connection factory |
| `auth_str` | `auth_str` | Used as auth bytes if `auth` byte slice is absent |
| `alpn` | `alpn` | TLS NextProtos; empty value invokes upstream default |
| `server_name` | `server_name` | TLS SNI and certificate hostname verification |
| `up_mbps`, `down_mbps` | same | Converted by source to bytes/sec for clientHello rate fields |
| `obfs`, `hop_interval` | same | Packet-connection obfuscation / hopping configuration |
| `fast_open`, `lazy_start` | same | TCP response handling / deferred connection start |
| loopback SOCKS endpoint | `socks5.listen` | Starts local SOCKS5 TCP and UDP service |
| `insecure=false` | `insecure` | Keeps TLS certificate verification enabled |
| optional CA path | `ca` | Adds a custom root CA pool |

ApnaWin deliberately binds SOCKS5 to loopback only and rejects FakeTCP on Windows. The generated runtime config is temporary and removed after startup readiness; the sidecar binary is checked against the installed runtime manifest digest.

## What is still not known about APNA

The static APNA evidence establishes a strong StarUDP/Hysteria-v1 wire-structure and config-schema lineage, but does not expose the protected runtime's effective values. These remain unresolved:

- actual ALPN selected by APNA;
- server hostname/SNI and port (including any port-hopping list);
- exact auth bytes and whether the runtime uses `auth` or `auth_str`;
- upload/download rate values;
- packet mode and obfuscation password/parameters;
- whether APNA changes any upstream defaults or protocol behavior;
- the protected process launch arguments and the config handoff from LIAPP to the Go PIE executable.

The primary DEX pass found no readable `libudpqtwo.so` launch call; it did identify separate `pdnsd` and `tun2socks` child-process paths. The LIAPP-protected secondary DEX was not decrypted or bypassed. That boundary remains in force.

## Next evidence-gathering sequence

1. On a test device, launch and use APNA normally with Android diagnostics enabled. Record process start/exit, command line where the OS permits it, service lifecycle and native loader errors. Do not bypass LIAPP.
2. Capture DNS and network metadata for the app's own authorized session (destination IP/port, timing, UDP vs TCP, TLS ClientHello SNI/ALPN where visible). Do not intercept/decrypt user payloads or contact third-party endpoints without authorization.
3. Compare observed destination, SNI and ALPN with the pinned client's config in a controlled, authorized test environment.
4. If the app's normal UI/export flow exposes its server profile, record the effective values with secrets redacted. Do not infer credentials from binary strings.
5. Only after the above, create an APNA-specific profile adapter. Keep the generic StarUDP profile separate from APNA compatibility until a real authorized handshake and TCP+UDP forwarding test pass.

## Validation status

- Pinned StarUDP Windows x64 build and CLI smoke test: passed in CI.
- Loopback QUIC + SOCKS5 TCP CONNECT: passed.
- Loopback QUIC DATAGRAM + SOCKS5 UDP ASSOCIATE: passed.
- APNA provider handshake / APNA credential validation: **not yet demonstrated**.
