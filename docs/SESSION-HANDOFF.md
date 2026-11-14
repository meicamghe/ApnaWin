# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. The inventory is metadata-only and rejects unsafe ZIP structures before reporting. The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).

## Latest verification

Workflow run #155 passed:
- Python unit tests
- Windows portable build
- Packaged-app smoke test
- Artifact upload

This verifies the desktop package starts in CI; it does not verify VPN connectivity or system-wide traffic tunneling.

## Latest engineering change

The APK inventory now validates ZIP entry paths and metadata before reporting: duplicate names, traversal/absolute/Windows-style paths, symbolic links, encrypted members, excessive entry counts, oversized entries, aggregate expansion and suspicious compression ratios are rejected. No archive member is extracted or executed. Regression tests cover the defensive checks.
