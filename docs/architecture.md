# ApnaWin architecture

## Product goal

Build a native Windows 10/11 client that offers a clear desktop workflow for tunnel profiles, connection status, diagnostics, and supported transport engines. It is not an Android emulator or an Android APK wrapper.

## Design principles

- Keep the desktop UI independent from tunnel implementation details.
- Keep privileged networking operations out of the UI process.
- Make engine capabilities explicit; never show a transport as supported until its Windows implementation is integrated and tested.
- Do not embed credentials, private keys, server lists, or vendor endpoints in source control.
- Make diagnostics useful without logging secrets.
- Record exact Windows build and architecture in test reports.

## Proposed layers

1. Presentation: PySide6 desktop window and profile editor.
2. Application: profile lifecycle, validation, persistence and, later, connection orchestration.
3. Domain: transport-neutral profiles, connection states and capability declarations.
4. Engines: adapters for independently licensed Windows-compatible engines, after protocol/config compatibility is established.
5. Platform: Windows service integration, process management, firewall/DNS and TUN adapter lifecycle.
6. Diagnostics: redacted logs, environment checks and support bundles.

## Current implementation

- Native PySide6 desktop UI, profile lifecycle, diagnostics, and a fixed-path elevated Windows helper.
- Current production engine registry: `Transport.XRAY` and `Transport.APNA_SSH`. `OPENVPN` and `SOCKS` enum values are not yet backed by production engine adapters.
- Xray share-link importer supports VLESS, VMess, Trojan and Shadowsocks outbounds with validated supported stream transports. These protocol implementations are supplied by the pinned Xray-core runtime through one Xray/Wintun engine.
- APNA Lite catalog decoding/import and bounded live catalog retrieval; only four observed SSH-compatible catalog categories are mapped. Other catalog categories remain unsupported until the protected Android runtime's exact configuration mapping is verified.
- APNA SSH/Payload connector with direct, TLS-direct, HTTP-proxy and TLS-HTTP-proxy modes; payload expansion/split behavior; Paramiko authentication; known-hosts or explicit SHA-256 host-key verification; loopback-only SOCKS5 TCP forwarding.
- APNA UDPGW framing/flow tracking over an SSH direct-tcpip stream and a local SOCKS5 UDP ASSOCIATE gateway.
- APNA full-tunnel adapter routes the local SOCKS5 gateway through a strict dual-stack Xray TUN/Wintun configuration. UDP DNS and certificate-validated IPv4/IPv6 TLS egress checks are required before CONNECTED.
- SSH relay supports TCP half-close semantics: a client FIN does not discard a pending remote response.
- Credentials and Xray configurations are protected with current-user Windows DPAPI; profile metadata exports exclude secrets.
- Windows CI runs Ruff, unit/integration tests, installer/runtime security tests, VPN readiness/egress checks, x64 packaging and packaged-app smoke tests. A separate pinned BadVPN Windows x64 build is research-only and is not integrated because its upstream TUN backend targets TAP-Windows.

## Milestones

- M0: repository skeleton, coding conventions and architecture record — complete.
- M1: inspect APK metadata/resources and document observable features/protocols — partial; protected runtime and exact native split-library behavior remain unknown.
- M2: profile schema, persistence, mock engine contract and desktop profile workflow — implemented.
- M2a/M2b: Xray process runner, Windows Job Object containment and elevated helper lifecycle — implemented with Windows CI coverage.
- M2c–M2e: remote catalog evidence, strict catalog model/cache and bounded HTTPS transport — implemented; live catalog fetch is available but remains lower priority than tunnel reliability.
- M3a: Xray/Wintun engine and VLESS/VMess/Trojan/Shadowsocks share-link import — implemented; clean-host live provider acceptance remains.
- M3b: APNA SSH/Payload/UDPGW session and APNA Wintun full-tunnel adapter — implemented with mocked/unit-level coverage; real APNA provider authentication and traffic acceptance remain open.
- M4: Windows helper, TUN lifecycle, rollback and cleanup — implemented at component level; clean Windows 10/11 crash/reboot acceptance remains.
- M5: portable x64 packaging and CI artifact publication — implemented; code signing and final release acceptance remain.

## Security and compatibility boundaries

The APK's Android native libraries cannot be assumed to run on Windows. Use Windows builds of suitable engines, after verifying their license, architecture, command-line interface, configuration format and redistribution terms. Do not copy proprietary application code, assets, keys, or backend credentials. Implement independently and lawfully compatible behavior.

## Verification status

The Windows GitHub Actions workflow runs the Python test suite on Windows and builds/smoke-tests the portable application folder. Workflow run [#144](https://github.com/meicamghe/ApnaWin/actions/runs/43568756016) passed both the test and Windows build/smoke-test jobs, including artifact upload. Passing unit tests and a packaged-app smoke test do not establish VPN connectivity, server compatibility, privileged networking behavior, or successful operation on a clean machine. Connect remains disabled until the separate end-to-end networking acceptance criteria are met.

## Profile text rendering

Profile fields originate from imported or user-edited local data. The profile details label is explicitly configured for plain-text rendering, so values resembling Qt rich text are displayed literally rather than interpreted as markup. The profile name inserted into the remove-confirmation dialog is HTML-escaped before being passed to Qt's auto-detecting message text.

## Remote server configuration

The Android app may refresh its server catalog and connection parameters remotely. This behavior is not yet reproducibly verified. The discovery evidence requirements, separation of catalog/profile/account data, secure refresh pipeline and acceptance criteria are recorded in [remote configuration discovery](remote-configuration.md). The current catalog schema is an internal normalized format, not a claim about APNA's upstream API. Do not hard-code guessed backend endpoints or treat a downloaded server list as proof of engine compatibility.
