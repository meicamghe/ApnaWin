# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. The inventory hashes and inspects through one open file descriptor, enforces a 2 GiB compressed-input ceiling, and checks for ordinary concurrent mutation.

Optional Android SDK-backed inspection covers manifest and DEX metadata; ZIP inventory also records bounded native-library metadata:
- Manifest decoder: selected package/version/SDK, permissions, component declarations and VPN-binding services.
- DEX decoder: DEX filenames, defined-class count, per-DEX method-reference counts and heuristic candidate VPN/network class names.
- Native inventory: allowlisted `.so` basenames, ABI labels and sizes; combined report emits token-boundary filename-only engine candidates and per-ABI counts. Android `.so` files are not assumed to be Windows DLLs.

The combined report correlates manifest VPN service names with defined DEX classes and rejects DEX-count disagreement between ZIP inventory and APK Analyzer. It does not claim runtime behavior or discover APNA endpoints.

The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).

## Latest verification

Workflow run #170 passed on commit `a213da9cf5903bd3f4720aba6b9c4ca537e81361`. This verifies the repository's configured CI checks for that revision; it does not verify VPN connectivity or system-wide traffic tunneling.

## Latest engineering change

Native engine-name matching now uses token boundaries to reduce substring false positives, and the combined report exposes native-library counts per ABI. Tests cover positive/negative filename cases, inventory immutability, report correlation, ABI aggregation and DEX-count mismatch. No real APNA APK has yet been analyzed.
