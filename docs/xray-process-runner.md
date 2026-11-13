# Xray process runner

## Scope

`XrayProcessRunner` is the first Windows engine-integration building block. It validates a supplied Xray JSON configuration using the executable's config-test command, starts the executable without a shell, and supervises stop/cleanup.

It is a process runner, **not yet a production tunnel engine**. It does not:
- Generate an Xray outbound from the current profile fields.
- Know APNA TUNNEL's private protocol/configuration format.
- Verify a remote server handshake or end-to-end traffic.
- Create a Windows TUN adapter or modify routes/DNS.
- Claim that a running process means the tunnel is connected.

## Inputs

The caller supplies:
- A separately installed Windows Xray executable path.
- A complete UTF-8 JSON Xray configuration file.
- A profile whose transport is `xray`.

The current profile's host and port do not specify protocol, security, flow, credentials, UUID, TLS/Reality parameters, transport settings or routing. Therefore the runner intentionally does not synthesize a config from those two fields.

## Safety behavior

- Uses argument arrays and `shell=False`.
- Does not capture or expose raw Xray output, which could contain server details.
- Validates the config before launch.
- Refuses duplicate starts.
- Stops the process and escalates to kill after the configured timeout.
- Does not alter Windows routes, DNS, firewall or adapters.

## Next acceptance steps

1. Test with an authorized Xray config and a pinned Windows binary on a Windows 10/11 test machine.
2. Add a localhost SOCKS readiness check against a config known to expose a local SOCKS inbound.
3. Add controlled remote traffic verification to an authorized test endpoint.
4. Separately design and test TUN, DNS, route rollback and privilege boundaries.
5. Only then implement a real `TunnelEngine` adapter and enable the Connect button.

The automated tests use fake processes; they verify command construction and lifecycle behavior, not a real Xray binary or network tunnel.
