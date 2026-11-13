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

1. Presentation (ui/): PySide6 windows, profile selection, connect/disconnect controls, status and logs.
2. Application (application/): orchestration, validation, lifecycle and user-facing state.
3. Domain (domain/): transport-neutral profiles, connection states and capability declarations.
4. Engines (engines/): adapters for independently licensed Windows-compatible engines, after protocol/config compatibility is established.
5. Platform (platform/): Windows service integration, process management, firewall/DNS and TUN adapter lifecycle.
6. Diagnostics (diagnostics/): redacted logs, environment checks and support bundles.

## Initial milestones

- M0: repository skeleton, coding conventions and architecture record.
- M1: inspect APK metadata/resources and document observable features and protocols.
- M2: define profile schema and a mock connection engine; build UI without privileged networking.
- M3: integrate one Windows engine end-to-end using a test server and documented configuration.
- M4: implement elevation/service and TUN adapter lifecycle with rollback and cleanup.
- M5: package, sign where possible, test on clean Windows 10/11 VMs and publish releases.

## Security and compatibility boundaries

The APK's Android native libraries cannot be assumed to run on Windows. Use Windows builds of suitable engines, after verifying their license, architecture, command-line interface, configuration format and redistribution terms. Do not copy proprietary application code, assets, keys, or backend credentials. Implement independently and lawfully compatible behavior.

## Current status

This repository is at M0. No working tunnel engine or server compatibility is claimed yet. The APK findings in apk-analysis.md are preliminary observations that still require reproducible verification.
