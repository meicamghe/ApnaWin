# Xray process runner

## Scope

`XrayProcessRunner` validates a supplied Xray JSON configuration using the executable's config-test command, starts the executable without a shell, supervises stop/cleanup, and can inspect a local SOCKS inbound.

It is a process runner and local-listener diagnostic, **not yet a production tunnel engine**. It does not:
- Generate an Xray outbound from the current profile fields.
- Know APNA TUNNEL's private protocol/configuration format.
- Verify a remote server handshake or end-to-end traffic.
- Create a Windows TUN adapter or modify routes/DNS.
- Claim that a running process or open local SOCKS port means the tunnel works.

## Inputs

The caller supplies:
- A separately installed Windows Xray executable path.
- A complete UTF-8 JSON Xray configuration file.
- A profile whose transport is `xray`.

Config files are read with a hard 16 MiB byte limit (the reader consumes at most one byte beyond that limit to detect overflow), before UTF-8 decoding or JSON parsing. Larger files are rejected before parsing to bound memory and parser work. Config parsing rejects duplicate object keys at every nesting level and non-standard non-finite JSON constants such as `NaN` and `Infinity`; these values are otherwise silently accepted by Python's default JSON decoder and can make security review ambiguous. Before config validation or process launch, the runner requires exactly one inbound in the entire `inbounds` array, and that inbound must be a SOCKS listener bound explicitly to loopback (`127.0.0.1`, `::1`, or `localhost`). Missing, additional, malformed, non-SOCKS, wildcard, and non-loopback inbounds are rejected before Xray is executed. This intentionally disallows auxiliary HTTP, mixed, dokodemo-door, or other listeners: even if the SOCKS listener is safe, an unchecked second inbound could expose a local proxy or service to the LAN. Configurations needing a different inbound topology require a separately designed policy rather than bypassing this check.

The current profile's host and port do not specify protocol, security, flow, credentials, UUID, TLS/Reality parameters, transport settings or routing. Therefore the runner intentionally does not synthesize a config from those two fields.

## Local SOCKS diagnostics

`local_socks_inbound()` accepts exactly one inbound total, which must be a SOCKS inbound with an explicit loopback listen address (`127.0.0.1`, `::1`, or `localhost`) and a valid integer port. Wildcard and non-loopback bind addresses are rejected to avoid accidentally exposing a local proxy to the network.

`is_socks_ready()` attempts a short TCP connection to that configured listener. Its timeout must be a finite positive number; zero, negative, non-finite, boolean and non-numeric values are rejected. A successful result means only that a local TCP listener accepted a connection; it does not prove authentication, proxy negotiation, remote reachability, or successful traffic forwarding.

`is_socks_protocol_ready()` performs the SOCKS5 greeting for the no-authentication method (`05 01 00`) and accepts only the matching no-auth response (`05 00`). It does not send credentials; a listener that selects username/password authentication is reported as not ready. Its timeout must be a finite positive number. This verifies SOCKS5 protocol negotiation with the local listener, but still does not issue a SOCKS CONNECT request or prove remote traffic forwarding.

`socks_connect(destination_host, destination_port)` sends a SOCKS5 CONNECT request for the explicit destination supplied by the caller. It supports domain names, IPv4 and IPv6 literals, validates the destination port, parses the proxy's reply and returns true only for SOCKS5 success. The shared reply parser validates the version, reserved byte, address type, non-empty domain length and complete bound-address fields; malformed or truncated replies fail closed. It also rejects non-finite, zero, negative or non-numeric timeout values. It does not send credentials, so authenticated-only inbounds are unsupported by this probe. Use only a destination you are authorized to test. A successful CONNECT reply confirms that the proxy reports a connection to that destination; it does not exchange application payload or prove Windows system-wide routing.

`socks_exchange(destination_host, destination_port, payload, max_response_bytes=65536)` builds on the same no-auth SOCKS5 CONNECT flow, sends caller-supplied bytes, half-closes the write side and reads the response until EOF. It uses the same strict SOCKS5 reply parser as `socks_connect`. It returns the response bytes on clean EOF, `None` for socket/proxy failures, and raises `ValueError` if the response exceeds the configured positive byte limit. Payload must be `bytes`; the caller is responsible for protocol framing, request safety and authorization of the destination. Use a short timeout and a conservative response limit. This is an application-level proxy data-exchange probe only: it does not validate a particular protocol beyond the bytes returned, prove APNA TUNNEL compatibility, or establish Windows system-wide routing. Tests use fake sockets and do not contact public endpoints.

## Safety behavior

- Uses argument arrays and `shell=False`.
- Discards validation stdout and stderr directly to the null device instead of capturing potentially unbounded or sensitive output.
- Redirects validation stdout and stderr to `subprocess.DEVNULL`; output that could contain server details or credentials is neither buffered in Python memory nor exposed.
- Reads at most 16 MiB plus one detection byte, then parses strict JSON (rejecting duplicate keys and non-finite constants), then validates the config before launch and rejects missing, additional, malformed, non-SOCKS, wildcard or non-loopback inbounds before executing Xray.
- Refuses duplicate starts.
- Validates finite positive validation and stop timeouts at construction.
- Stops the process and escalates after the configured timeout. On Windows, the forced-stop path first attempts `taskkill /T /F` for the supervised PID so Windows can include descendants. If `taskkill` is unavailable, times out, or returns a non-zero exit code, it falls back to the direct `Popen.kill()` handle. The process handle is cleared only after exit is confirmed; termination, kill or wait failures raise `XrayProcessError` and retain the handle when the child may still be alive. A successful `taskkill` exit code is followed by a wait on the supervised process, but does not independently prove that every descendant has exited.
- The Windows tree-kill fallback is best-effort and only runs when the supervised process has not exited within the graceful-stop timeout. It is not a substitute for a Windows Job Object: if Xray exits gracefully while independently spawned descendants remain, this runner does not yet guarantee their cleanup.
- Does not alter Windows routes, DNS, firewall or adapters.

## Next acceptance steps

1. Test with an authorized Xray config and a pinned Windows binary on a Windows 10/11 test machine.
2. Use `socks_exchange` with a small, bounded request against an authorized test endpoint and verify the returned application response.
3. Separately design and test TUN, DNS, route rollback and privilege boundaries.
4. Only then implement a real `TunnelEngine` adapter and enable the Connect button.

The automated tests use fake processes and sockets; they verify command construction, configuration checks and local-listener diagnostics, not a real Xray binary or network tunnel.
