# ApnaWin

A native Windows 10/11 desktop VPN client. The project is building independently implemented, security-conscious tunnel transports; it is not an Android emulator or an Android APK wrapper.

## Current status — 2026-11-18

**Active development:** [PR #6](https://github.com/meicamghe/ApnaWin/pull/6), branch `vpn/dual-stack-egress-readiness`. The PR remains Draft and unmerged pending real-provider acceptance.

Implemented in the active branch:

- Native PySide6 desktop UI, profile lifecycle, diagnostics, and fixed-path elevated helper for Windows TUN operation.
- **APNA SSH/Payload:** bounded APNA Lite APK catalog decoder/import, supported SSH-family profile mapping, payload expansion and split behavior, direct/TLS/HTTP payload socket setup, strict SSH host-key verification, Paramiko authentication, loopback SOCKS5 TCP forwarding, and SSH-carried BadVPN-compatible UDPGW framing.
- **APNA full tunnel:** local SOCKS5/UDPGW path connected to Xray-core + Wintun dual-stack TUN. Startup fails closed unless UDP DNS and certificate-validated IPv4 and IPv6 TLS egress checks succeed. Cleanup retains ownership when a resource cannot be confirmed stopped.
- **Xray share-link import:** VLESS, VMess, Trojan and Shadowsocks profiles using supported TCP, WebSocket, gRPC and HTTPUpgrade transports, with TLS/Reality validation where applicable. Credentials are stored in the current-user Windows DPAPI-protected config store.
- Windows x64 packaging, runtime hash/architecture checks, helper security checks, Ruff, unit/integration tests and VPN readiness/egress tests in GitHub Actions.
- A pinned BadVPN Windows x64 native build workflow. Its artifact is research-only and is **not integrated** into the product because its upstream Windows TUN backend targets TAP-Windows while ApnaWin currently uses Wintun.

## Actual support boundary

- The desktop engine registry currently activates **APNA SSH** and **Xray**. VLESS, VMess, Trojan and Shadowsocks are Xray outbound protocols, not four separate Windows engine processes.
- OpenVPN and standalone SOCKS profile enum values do not yet have a registered production engine in the desktop application. They must not be presented as working connections.
- APNA catalog categories outside the verified SSH-family mapper (including Xray/Trojan/Shadowsocks/UDP-labelled categories) remain unsupported until their protected Android runtime field mapping is verified. Category names alone are not sufficient evidence to map them to a protocol.
- CI and successful packaging do not prove that an APNA provider accepted SSH authentication or carried real traffic.

## Release gates

A release requires a clean Windows 10/11 acceptance run against an authorized APNA provider endpoint: independently verified SSH host key, successful authentication, real UDPGW datagram round-trip, routed TCP/UDP/DNS, IPv4/IPv6 egress and leak checks, plus disconnect/crash cleanup. Follow [the APNA live Windows acceptance runbook](docs/apna-live-windows-acceptance.md). Do not merge or mark the PR ready before those gates pass.

See [the current session handoff](docs/SESSION-HANDOFF.md), [architecture](docs/architecture.md), and [APNA upstream evidence](docs/apna-tunnel-lite-upstream-evidence.md) for implementation detail and evidence limits.

## Run from source

Requires Python 3.10+.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m apnawin
```

## Build artifact

On pushes to `main` and pull requests, the Windows workflow runs tests first, then builds the native desktop app with PyInstaller. On a successful run, download the `ApnaWin-Windows-x64` artifact from the workflow run's **Artifacts** section. Extract the ZIP and launch `ApnaWin.exe` from the extracted `ApnaWin` folder. The artifact is temporary CI output (14-day retention), not a signed installer. For the elevated TUN helper, extract the folder and run Install-ApnaWin.ps1 as Administrator; it installs under Program Files with standard-user read/execute ACLs. The helper is not Authenticode-signed.

Run tests:

```powershell
python -m pytest
```

## Profile storage

Profiles are saved under the current user's application-data directory in `profiles.json`. Writes use a unique temporary file in the same directory and atomic replacement; malformed JSON, duplicate keys, unsupported schema versions, unexpected fields and duplicate profile names are rejected. The current schema stores only:
- Profile name
- Transport selection (Xray, APNA SSH, OpenVPN or SOCKS; only Xray and APNA SSH currently have production engine registrations)
- Server host
- Server port

It does not store passwords, access tokens, private keys or other credentials. Do not place secrets in profile names or endpoint fields.

## Project structure

- `src/apnawin/` — application package and desktop entry point
- `src/apnawin/domain/` — transport-neutral domain models
- `src/apnawin/engines/` — tunnel-engine contract, test-only mock and Xray process runner
- `src/apnawin/storage/` — profile and encrypted Xray-config persistence
- `src/apnawin/services/` — UAC helper lifecycle and read-only Windows tunnel diagnostics
- `tests/` — automated tests, including desktop profile workflow checks
- `docs/architecture.md` — architecture, milestones and security boundaries
- `docs/SESSION-HANDOFF.md` — durable implementation status and next engineering steps
- `docs/apk-analysis.md` — preliminary APK observations and reproducible verification checklist
- `docs/apna-tunnel-lite-upstream-evidence.md` — third-party APNA Lite catalog/engine findings, evidence limits and next verification gates
- `docs/apna-upstream-framework-comparison.md` — public SSH/TUN framework comparison, payload behavior, security and licensing caveats
- `docs/remote-configuration.md` — evidence plan and security contract for Android-style server/config refresh
- `docs/engine-contract.md` — requirements for production tunnel adapters
- `docs/profile-storage.md` — schema, atomic-write behavior and credential boundary
- `docs/xray-process-runner.md` — scope and limitations of Xray process supervision
- `docs/xray-tunnel-supervisor.md` — desktop helper lifecycle contract
- `docs/windows-tunnel-diagnostics.md` — read-only adapter, route and DNS checks

## Important compatibility note

Android ARM64 native libraries are not Windows binaries. The current Windows path is an imported Xray TUN configuration plus a Windows Xray/Wintun runtime. The APNA-specific catalog decoder now works against the supplied embedded APK sample; live refresh, profile generation and end-to-end APNA connection are not yet verified. APK class and library names are clues, not proof of compatibility. See the upstream evidence document before making implementation assumptions.

## Development direction

The UI, application orchestration, transport-neutral domain model, engine adapters and Windows-specific privileged operations will remain separate. Credentials and private server configurations must not be committed.

## Session continuity

For the current project decisions, implementation boundaries, and next-session checklist, see [docs/SESSION-HANDOFF.md](docs/SESSION-HANDOFF.md).
