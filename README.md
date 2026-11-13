# ApnaWin

A native Windows 10/11 desktop client project inspired by the workflow of APNA TUNNEL LITE. The goal is to build a Windows application, not to run the Android APK in an emulator.

## Current status

**Milestone M2 is in progress.** The repository includes:
- A native PySide6 desktop application.
- Add, edit, select and remove connection profiles.
- Local JSON persistence for non-secret profile metadata.
- A transport-neutral profile model and tunnel-engine contract.
- A test-only mock engine that does not touch the network.
- Windows GitHub Actions tests and a PyInstaller build job that publishes a portable Windows x64 application-folder artifact (14-day retention).

The Connect button is intentionally disabled. An Xray process runner validates a supplied config and supervises the executable, but it is not yet a complete tunnel engine. The CI build artifact is an early portable application build, not a signed installer and not a VPN client with working tunnel connectivity. No APNA TUNNEL server compatibility is claimed.

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

On pushes to `main` and pull requests, the Windows workflow runs tests first, then builds the native desktop app with PyInstaller. On a successful run, download the `ApnaWin-Windows-x64` artifact from the workflow run's **Artifacts** section. Extract the ZIP and launch `ApnaWin.exe` from the extracted `ApnaWin` folder. The artifact is temporary CI output (14-day retention), not a signed installer.

Run tests:

```powershell
python -m pytest
```

## Profile storage

Profiles are saved under the current user's application-data directory in `profiles.json`. The current schema stores only:
- Profile name
- Transport selection (Xray, OpenVPN or SOCKS)
- Server host
- Server port

It does not store passwords, access tokens, private keys or other credentials. Do not place secrets in profile names or endpoint fields.

## Project structure

- `src/apnawin/` — application package and desktop entry point
- `src/apnawin/domain/` — transport-neutral domain models
- `src/apnawin/engines/` — tunnel-engine contract, test-only mock and Xray process runner
- `src/apnawin/storage/` — profile persistence
- `tests/` — automated tests, including desktop profile workflow checks
- `docs/architecture.md` — architecture, milestones and security boundaries
- `docs/apk-analysis.md` — preliminary APK observations and reproducible verification checklist
- `docs/engine-contract.md` — requirements for production tunnel adapters
- `docs/xray-process-runner.md` — scope and limitations of Xray process supervision

## Important compatibility note

Android ARM64 native libraries are not Windows binaries. The Windows client will need compatible Windows engine builds and a verified configuration/protocol path. APK class and library names are only clues; they do not prove backend compatibility. See the analysis document before making implementation assumptions.

## Development direction

The UI, application orchestration, transport-neutral domain model, engine adapters and Windows-specific privileged operations will remain separate. Credentials and private server configurations must not be committed.

## Session continuity

For the current project decisions, implementation boundaries, and next-session checklist, see [docs/SESSION-HANDOFF.md](docs/SESSION-HANDOFF.md).
