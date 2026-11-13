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

The current profile's host and port do not specify protocol, security, flow, credentials, UUID, TLS/Reality parameters, transport settings or routing. Therefore the runner intentionally does not synthesize a config from those two fields.

## Local SOCKS diagnostics

`local_socks_inbound()` accepts exactly one SOCKS inbound with an explicit loopback listen address (`127.0.0.1`, `::1`, or `localhost`) and a valid integer port. Wildcard and non-loopback bind addresses are rejected to avoid accidentally exposing a local proxy to the network.

`is_socks_ready()` attempts a short TCP connection to that configured listener. A successful result means only that a local TCP listener accepted a connection; it does not prove authentication, proxy negotiation, remote reachability, or successful traffic forwarding.

`is_socks_protocol_ready()` performs the SOCKS5 greeting for the no-authentication method (`05 01 00`) and accepts only the matching no-auth response (`05 00`). It does not send credentials; a listener that selects username/password authentication is reported as not ready. This verifies SOCKS5 protocol negotiation with the local listener, but still does not issue a SOCKS CONNECT request or prove remote traffic forwarding.

## Safety behavior

- Uses argument arrays and `shell=False`.
- Does not capture or expose raw Xray output, which could contain server details.
- Validates the config before launch.
- Refuses duplicate starts.
- Stops the process and escalates to kill after the configured timeout.
- Does not alter Windows routes, DNS, firewall or adapters.

## Next acceptance steps

1. Test with an authorized Xray config and a pinned Windows binary on a Windows 10/11 test machine.
2. Add a SOCKS CONNECT test and remote traffic verification to an authorized test endpoint.
3. Separately design and test TUN, DNS, route rollback and privilege boundaries.
4. Only then implement a real `TunnelEngine` adapter and enable the Connect button.

The automated tests use fake processes and sockets; they verify command construction, configuration checks and local-listener diagnostics, not a real Xray binary or network tunnel.
