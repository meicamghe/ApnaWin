# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. The inventory hashes and inspects through one open file descriptor, enforces a 2 GiB compressed-input ceiling, and checks for ordinary concurrent mutation.

Optional Android SDK-backed inspection covers manifest and DEX metadata. Its shared subprocess runner enforces timeout and per-stream output caps while reading, terminating the child on overflow instead of checking only after unbounded capture. ZIP inventory also records bounded native-library metadata:
- Manifest decoder: selected package/version/SDK, permissions, component declarations and VPN-binding services.
- DEX decoder: DEX filenames, defined-class count, per-DEX method-reference counts and heuristic candidate VPN/network class names.
- Native inventory: allowlisted `.so` basenames, ABI labels and sizes; combined report emits token-boundary filename-only engine candidates and per-ABI counts. Android `.so` files are not assumed to be Windows DLLs.

The combined report correlates manifest VPN service names with defined DEX classes and rejects DEX-count disagreement between ZIP inventory and APK Analyzer. DEX class rows are checked for expected shape, numeric metadata, valid dotted class names and duplicate definitions before joining. It does not claim runtime behavior or discover APNA endpoints.

The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).

## Latest verification

Workflow #176 passed on commit `ee6fc420e5969555d143c6a9abd1c91ee756b791`. Workflow #178 on `1918c394101617f61615d671b00a281b62b609eb` found two test-fixture failures (332 passed): the newly added DEX tests encoded literal backslash-n text instead of newline separators. The fixture correction is committed separately and its CI result must be checked. CI verifies configured tests only, not live VPN connectivity or APNA endpoint discovery.

## Latest engineering change

Native engine-name matching now uses token boundaries to reduce substring false positives, and the combined report exposes native-library counts per ABI. Tests cover positive/negative filename cases, inventory immutability, report correlation, ABI aggregation and DEX-count mismatch. No real APNA APK has yet been analyzed.


## Manifest-to-DEX join hardening

Manifest component class names are now allowlisted as dotted Java-style identifiers (including dollar signs for nested classes); malformed names are omitted before they can enter the join. Invalid package identifiers are not used as resolution context. DEX join resolution returns an unresolved value for relative/simple names when package context is absent instead of guessing. Tests cover invalid names, missing/invalid package context, duplicate VPN service declarations and nested-class names. A positive join still means only that the class is defined in DEX, not that Android instantiates or executes it.
