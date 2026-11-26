# ApnaWin

A native Windows 10/11 desktop client project inspired by the workflow of APNA TUNNEL LITE. The goal is to build a Windows application, not to run the Android APK in an emulator.

## Current status

**M2 profile workflow and M2a/M2b engine-process foundations are implemented; M2c remote-configuration discovery is documented but awaits APK/runtime evidence.** The repository includes:
- A native PySide6 desktop application.
- Add, edit, select and remove connection profiles.
- Strict local JSON persistence for non-secret profile metadata, with unique same-directory atomic temp files, flush/fsync, duplicate-key/schema validation and duplicate-name rejection.
- Import of complete Xray TUN JSON configs for XRAY profiles, encrypted at rest with current-user Windows DPAPI; profile metadata exports exclude credentials.
- A dedicated fixed-path UAC helper, a desktop-side Xray tunnel supervisor wrapper, read-only Windows adapter/route/DNS diagnostics, and a Program Files installer script; the helper keeps the desktop at normal integrity and supervises Xray in a Job Object.
- Strict Xray config parsing that rejects duplicate JSON keys and non-finite constants before execution.
- A transport-neutral profile model and tunnel-engine contract.
- A test-only mock engine that does not touch the network.
- Windows Job Object process-tree containment for the Xray runner.
- Windows GitHub Actions tests and a PyInstaller build job that publishes a portable Windows x64 application-folder artifact (14-day retention).
- A pinned runtime packaging step for Xray-core v26.11.9 and Wintun 0.14.1, with archive hash, PE architecture, Authenticode and version checks.

The desktop UI is wired to the connection controller and fixed-path UAC/Xray supervisor. Connect is enabled only for a selected XRAY profile with an imported, validated, DPAPI-protected full-tunnel config and an installed protected helper/runtime. The helper verifies Xray/Wintun hashes, waits for stable effective IPv4/IPv6 default routes and configured DNS, then requires a certificate-validated external TLS egress probe before signaling ready. While connected it monitors adapter/routes/DNS and periodically rechecks independent TLS egress; repeated health failures trigger graceful Xray shutdown. CI verifies the application build and these component-level behaviors, but it does not execute an authorized live APNA server session. Clean Windows 10/11 acceptance for provider-specific traffic, DNS/IPv4/IPv6 leak behavior, WFP under failure, disconnect and crash/reboot cleanup remains outstanding. The portable artifact is not a signed installer or a verified APNA VPN client. No APNA TUNNEL server compatibility is claimed.

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

On pushes to `main` and pull requests, the Windows workflow runs tests first, then builds the native desktop app with PyInstaller. On a successful run, download the `ApnaWin-Windows-x64` artifact from the workflow run's **Artifacts** section. Extract the ZIP and launch `ApnaWin.exe` from the extracted `ApnaWin` folder. The artifact is temporary CI output (14-day retention), not a signed installer. For the elevated TUN helper, extract the folder and run Install-ApnaWin.ps1 as Administrator; it installs under Program Files with standard-user read/execute ACLs. The helper is not Authenticode-signed.

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
- `src/apnawin/services/` — UAC helper lifecycle and read-only Windows tunnel diagnostics
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
