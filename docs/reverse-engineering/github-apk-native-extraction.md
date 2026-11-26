# GitHub APK native-library extraction

This repository now has a manual GitHub Actions workflow for extracting and inspecting a native library already committed under `APNA-APKs/`.

## Run it

1. Open the repository's **Actions** tab.
2. Select **APK native-library extraction**.
3. Choose **Run workflow** on branch `re/apk-native-extract` (or the branch containing this workflow).
4. Keep the default library name `libudpqtwo.so`, then start the run.
5. When the run completes, open its **Artifacts** section and download `ApnaWin-libudpqtwo-analysis`.

The workflow is manual-only. It does not run on pushes or pull requests, does not build the Windows application, and does not need secrets or write permissions. It searches all top-level APK files in `APNA-APKs/` and fails rather than silently selecting a library if multiple copies are found.

## Artifact contents

- `libudpqtwo.so`: extracted native library.
- `extraction.txt`: source APK/archive entry, SHA-256 and file identification.
- `apk-native-inventory.txt`: SHA-256 of each committed APK plus every embedded ABI `.so` entry and its uncompressed-content hash, across all APK splits. This is read-only and does not load or execute native code.
- `readelf-report.txt`: ELF header, LOAD segments, sections, notes and dynamic section.
- `elf-structural-report.txt`: file-backed VA mapping for the known pclntab/moduledata candidates, pclntab header words, derived functab range and initial records when readable.
- `strings.txt` and `go-build-strings.txt`: printable strings and likely Go build metadata strings.

Artifacts are retained for seven days. The extracted library is a temporary analysis artifact; it is not committed back into the repository.

## Current reverse-engineering hypothesis

The current candidate addresses and recovery hypothesis are documented in [libudpqtwo-stomped-pclntab.md](libudpqtwo-stomped-pclntab.md). The workflow is intended to produce the exact binary and fresh structural evidence needed to validate or reject that hypothesis before changing GoReSym.
