# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. The inventory is metadata-only and rejects unsafe ZIP structures before reporting. Its current implementation hashes and inspects the archive through one open file descriptor, enforces a 2 GiB compressed-file ceiling, and checks for ordinary concurrent file mutation. The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).

## Latest verification

Workflow run #158 passed:
- Python unit tests
- Windows portable build
- Packaged-app smoke test
- Artifact upload

This verifies the desktop package starts in CI; it does not verify VPN connectivity or system-wide traffic tunneling.

## Latest engineering change

The APK inventory now reads the same opened file descriptor for SHA-256 and ZIP metadata inspection, reducing path-replacement/TOCTOU exposure. It verifies the opened object is a regular file, enforces a 2 GiB compressed-input limit, and compares file identity, size and timestamps before and after inspection. Tests cover single-open behavior, non-regular paths and size limits in addition to ZIP metadata defenses.
