# ApnaWin

A native Windows 10/11 desktop client project inspired by the workflow of APNA TUNNEL LITE. The goal is to build a Windows application, not to run the Android APK in an emulator.

## Current status

**Milestone M0 is committed:** repository structure, Python packaging, a minimal PySide6 desktop shell, an initial test, and architecture/APK-analysis notes.

The Connect button is intentionally disabled. No working tunnel engine, server compatibility, or release installer is claimed yet.

## Run from source

Requires Python 3.10+.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m apnawin
```

Run tests:

```powershell
python -m pytest
```

## Project structure

- `src/apnawin/` — application package and desktop entry point
- `tests/` — automated tests
- `docs/architecture.md` — architecture, milestones and security boundaries
- `docs/apk-analysis.md` — preliminary APK observations and reproducible verification checklist

## Important compatibility note

Android ARM64 native libraries are not Windows binaries. The Windows client will need compatible Windows engine builds and a verified configuration/protocol path. APK class and library names are only clues; they do not prove backend compatibility. See the analysis document before making implementation assumptions.

## Development direction

The UI, application orchestration, transport-neutral domain model, engine adapters and Windows-specific privileged operations will remain separate. Credentials and private server configurations must not be committed.
