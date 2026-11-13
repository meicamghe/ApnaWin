# Windows engine candidate assessment

## Decision status

Xray-core is the first candidate to prototype as an optional transport engine. This is a candidate selection for a controlled prototype, not a claim that APNA TUNNEL server configurations are compatible and not approval to ship a bundled binary yet.

## Verified upstream facts

- Project X publishes a Windows executable named `xray.exe`.
- Its installation documentation lists Windows x86, amd64, arm32 and arm64 support.
- The upstream project repository identifies its license as Mozilla Public License 2.0 (MPL-2.0).
- The documented client example starts a local SOCKS inbound listener and forwards traffic through a configured outbound.
- The Windows usage guide documents running Xray with a configuration file; the documented CLI form is `xray run -c <config>`.

Official references:
- https://xtls.github.io/en/document/install
- https://xtls.github.io/en/document/config
- https://github.com/XTLS/Xray-core

## Why it is a candidate

- A native Windows executable exists, so Android `.so` binaries are not needed.
- It has a documented command-line/configuration interface that can be wrapped by a Python adapter.
- Its upstream license is published and can be reviewed for compliant redistribution.

## Important limits

- Xray-core alone is not yet a complete ApnaWin system-wide VPN implementation.
- A local SOCKS inbound only proxies applications configured to use it. System-wide traffic requires a separately designed and tested Windows TUN, routing, DNS and cleanup layer, or another explicitly verified supported mode.
- The APK's reported `libxray.so` name is only a clue. It does not prove the Android app uses the same Xray version, protocols, config schema, plugins, or server-side behavior as the current upstream project.
- No private APNA TUNNEL profile, protocol format, credentials or authorized test server has been verified in this repository.

## Prototype acceptance plan

1. Obtain an authorized, non-production test configuration and document its exact protocol and transport fields without committing secrets.
2. Pin an upstream Xray release and record the Windows binary SHA-256 and source tag/commit.
3. Review MPL-2.0 obligations and notices before any binary redistribution.
4. Build a Python adapter that writes a temporary, validated config with restrictive file permissions where supported, starts Xray without shell interpolation, captures redacted diagnostics, and terminates the process reliably.
5. First verify a localhost SOCKS connection to a controlled test endpoint.
6. Separately evaluate a Windows TUN backend, DNS/routing behavior, elevation, rollback and disconnect cleanup before enabling system-wide Connect.
7. Enable the UI transport only after automated tests and manual Windows 10/11 tests pass.

## Current implementation status

No Xray binary is downloaded, bundled, launched or integrated. The Connect button remains disabled. The next implementation milestone is a localhost-only Xray process adapter and test harness; it must not alter system routes or DNS.
