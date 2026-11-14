# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator and bounded HTTPS transport are implemented. The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).

## Latest verification

Workflow run [#146](https://github.com/meicamghe/ApnaWin/actions/runs/43569366650) passed:
- Python unit tests
- Windows portable build
- Packaged-app smoke test
- Artifact upload

This verifies the desktop package starts in CI; it does not verify VPN connectivity or system-wide traffic tunneling.

## Latest engineering change

The refresh coordinator now validates the server-declared catalog validity window against an injectable UTC clock before persisting a response. Expired and not-yet-valid responses are rejected without replacing the last-known-good cache. Regression tests cover both cases and the existing retry/concurrency behavior.
