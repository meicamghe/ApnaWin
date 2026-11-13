# Engine contract

## Purpose

The engine adapter is the boundary between application orchestration and a concrete Windows transport implementation. The UI must not launch arbitrary commands or manipulate routes directly.

## Current contract

`apnawin.engines.base.TunnelEngine` defines:
- A stable adapter name.
- A shared `ConnectionState`.
- Profile validation.
- Connect and disconnect lifecycle methods.

A production adapter must report failures, clean up child processes, and restore resources it changed. It must not claim `CONNECTED` merely because a process started; it should verify backend readiness and, where feasible, a usable tunnel.

## Mock adapter

`MockTunnelEngine` is only an in-memory development aid. It does not create sockets, routes, DNS changes, a TUN interface, or an encrypted tunnel. Its name explicitly says "no network". It must never be shipped as an actual VPN option.

## Production adapter acceptance checklist

- Windows 10 and Windows 11 support matrix documented.
- Supported CPU architectures and binary hashes recorded.
- License and redistribution terms reviewed.
- Input configuration validated before process launch.
- Arguments passed without shell interpolation.
- Secrets redacted from logs and process diagnostics.
- Child process monitored and terminated reliably.
- DNS/routes/TUN changes have rollback and disconnect cleanup.
- Connection readiness and failure states tested with an authorized test server.
