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

- Native PySide6 application shell.
- Add, edit, select and remove connection profiles.
- Profile metadata is stored as UTF-8 JSON under the current user's application-data directory.
- The profile format stores only name, transport, endpoint host and port. It does not store credentials or private keys.
- Profile loading validates the stored schema and rejects unsupported format versions.
- Connect remains disabled: no real Windows tunnel engine is integrated.

## Milestones

- M0: repository skeleton, coding conventions and architecture record — complete.
- M1: inspect APK metadata/resources and document observable features and protocols — preliminary; reproducible verification remains.
- M2: define profile schema, persistence, mock engine contract and desktop profile workflow — in progress.
- M3: integrate one Windows engine end-to-end using a test server and documented configuration.
- M4: implement elevation/service and TUN adapter lifecycle with rollback and cleanup.
- M5: package, sign where possible, test on clean Windows 10/11 VMs and publish releases.

## Security and compatibility boundaries

The APK's Android native libraries cannot be assumed to run on Windows. Use Windows builds of suitable engines, after verifying their license, architecture, command-line interface, configuration format and redistribution terms. Do not copy proprietary application code, assets, keys, or backend credentials. Implement independently and lawfully compatible behavior.

## Verification status

The Windows GitHub Actions workflow runs the Python test suite on Windows. Passing unit tests do not establish VPN connectivity, server compatibility, privileged networking behavior, or successful packaging on a clean machine.
