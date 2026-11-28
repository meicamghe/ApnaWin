# ApnaWin

A native Windows 10/11 desktop client project inspired by the workflow of APNA TUNNEL LITE. The goal is to build a Windows application, not to run the Android APK in an emulator.

## Current status

**The Windows desktop/profile foundation and generic Xray share-link import path are implemented; live tunnel connectivity and APNA-specific compatibility remain unverified.** The repository includes:
- A native PySide6 desktop application.
- Add, edit, select and remove connection profiles.
- Strict local JSON persistence for non-secret profile metadata, with unique same-directory atomic temp files, flush/fsync, duplicate-key/schema validation and duplicate-name rejection.
- Import of complete Xray TUN JSON configs for XRAY profiles, encrypted at rest with current-user Windows DPAPI; profile metadata exports exclude credentials.
- Import of VLESS, VMess, Trojan, Shadowsocks and Hysteria2 share links; bounded batch parsing, strict full-tunnel Xray config composition and encrypted config persistence.
- A dedicated fixed-path UAC helper, a desktop-side Xray tunnel supervisor wrapper, read-only Windows adapter/route/DNS diagnostics, and a Program Files installer script; the helper keeps the desktop at normal integrity and supervises Xray in a Job Object.
- Strict Xray config parsing that rejects duplicate JSON keys and non-finite constants before execution.
- A transport-neutral profile model and tunnel-engine contract.
- A test-only mock engine that does not touch the network.
- Windows Job Object process-tree containment for the Xray runner.
- Windows GitHub Actions tests and a PyInstaller build job that publishes a portable Windows x64 application-folder artifact (14-day retention).
- A pinned runtime packaging step for Xray-core v26.11.9 and Wintun 0.14.1, with archive hash, PE architecture, Authenticode and version checks.

The desktop now has an asynchronous Xray TUN connection lifecycle. Connect is enabled only when an XRAY profile has an encrypted TUN config and the protected Program Files helper is installed. The worker starts the elevated helper without blocking the UI, waits for the adapter/routes/DNS readiness signal, then performs a real HTTPS request only after confirming that Windows selects the ApnaWin interface for the probe destination. The UI reports Connected only after that route-bound TLS/HTTP probe succeeds; a failed probe triggers helper shutdown. Disconnect requests graceful helper cleanup, and a cleanup failure blocks reconnect and instructs the user to close the desktop so the helper's parent-process monitor can unwind. This is a generic Xray connectivity path, not proof of APNA TUNNEL compatibility. Actual Windows 10/11 end-to-end acceptance, route/DNS restoration after crashes, WFP leak tests and an authorized APNA-compatible configuration source remain outstanding. Do not treat CI unit tests as live VPN acceptance.

The Android app may refresh its server catalog and connection parameters remotely. This is a first-class requirement for the Windows product, but the actual API, schema, authentication and refresh policy have not yet been verified. See [remote configuration discovery](docs/remote-configuration.md); no guessed backend endpoint or static replacement server list will be shipped.

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

The Windows workflow runs unit tests on pushes and pull requests, then builds a portable Windows x64 validation artifact for pull requests after tests pass. Download `ApnaWin-Windows-x64` from the workflow run's **Artifacts** section. Extract the ZIP and run `Install-ApnaWin.ps1` as Administrator; it installs the protected helper and runtime under Program Files. Launch the installed `ApnaWin.exe` normally. This artifact is not a signed installer, and the helper is not Authenticode-signed. It is a generic Xray client build: use an authorized, compatible Xray share link. It does not establish APNA TUNNEL protocol compatibility. Actual Windows 10/11 traffic, route/DNS rollback, WFP leak and crash-recovery acceptance is still required.

Run tests:

```powershell
python -m pytest
```

## Profile storage

Profiles are saved under the current user's application-data directory in `profiles.json`. Writes use a unique temporary file in the same directory and atomic replacement; malformed JSON, duplicate keys, unsupported schema versions, unexpected fields and duplicate profile names are rejected. The current schema stores only:
- Profile name
- Transport selection (Xray, OpenVPN or SOCKS)
- Server host
- Server port

It does not store passwords, access tokens, private keys or other credentials. Do not place secrets in profile names or endpoint fields.

## Project structure

- `src/apnawin/` — application package and desktop entry point
- `src/apnawin/domain/` — transport-neutral domain models
- `src/apnawin/engines/` — tunnel-engine contract, test-only mock and Xray process runner
- `src/apnawin/storage/` — profile and encrypted Xray-config persistence
- `src/apnawin/services/` — UAC helper lifecycle, asynchronous connection worker, route-bound HTTPS probe, Xray config import and Windows tunnel diagnostics
- `tests/` — automated tests, including desktop profile workflow checks
- `docs/architecture.md` — architecture, milestones and security boundaries
- `docs/SESSION-HANDOFF.md` — durable implementation status and next engineering steps
- `docs/apk-analysis.md` — preliminary APK observations and reproducible verification checklist
- `docs/remote-configuration.md` — evidence plan and security contract for Android-style server/config refresh
- `docs/engine-contract.md` — requirements for production tunnel adapters
- `docs/profile-storage.md` — schema, atomic-write behavior and credential boundary
- `docs/xray-process-runner.md` — scope and limitations of Xray process supervision
- `docs/xray-tunnel-supervisor.md` — desktop helper lifecycle contract
- `docs/windows-tunnel-diagnostics.md` — read-only adapter, route and DNS checks

## Important compatibility note

Android ARM64 native libraries are not Windows binaries. The current Windows path is an imported Xray TUN configuration plus a Windows Xray/Wintun runtime. No APNA-specific server endpoint, authentication schema or remote configuration protocol has been verified; the client does not fabricate these details. APK class and library names are only clues; they do not prove backend compatibility. See the analysis document before making implementation assumptions.

## Development direction

The UI, application orchestration, transport-neutral domain model, engine adapters and Windows-specific privileged operations will remain separate. Credentials and private server configurations must not be committed.

## Session continuity

For the current project decisions, implementation boundaries, and next-session checklist, see [docs/SESSION-HANDOFF.md](docs/SESSION-HANDOFF.md).


## APNA SSH integration status

The APNA SSH transport implementation is being integrated on the separate branch
`feature/apna-ssh-backend-port`. It includes Paramiko SSH with explicit host-key
verification, payload transports, local SOCKS5 TCP forwarding, UDPGW relay and
Xray/Wintun tunnel composition. APNA catalog import and DPAPI-protected profile
settings are included in that branch.

This branch has not yet passed its own full CI run or live provider acceptance.
A successful SSH login alone is not a full-tunnel acceptance: verify routed TCP,
non-DNS UDP, DNS, IPv4/IPv6 egress, disconnect cleanup and crash recovery with an
authorized APNA account before treating the feature as production-ready.
