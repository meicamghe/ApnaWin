# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator, bounded HTTPS transport and privacy-conscious APK inventory are implemented. Android APK inspection is static metadata analysis only; native Android `.so` files are not treated as Windows DLLs.

The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not available.

## Windows network transaction

- Wintun is the leading Layer-3 adapter candidate, pending pinned-binary architecture/hash/signature/license verification and clean-machine testing.
- The privileged helper, packet-forwarding integration and route/DNS executor do not exist yet.
- `windows_network_plan.py` validates immutable route/DNS intent without OS changes. It requires a physical-interface endpoint host route before tunnel default routes, prevents duplicate default routes per family, and binds DNS to the tunnel interface.
- A valid plan does not prove that routes were applied or that traffic traverses a VPN.

## Remote configuration

Available evidence has not established a verified APNA endpoint, authentication scheme, signature format or upstream response schema. Do not invent any of these. No credentials or endpoints are hard-coded.

## Latest verification

Workflow `43707683054` passed on commit `6c35c124179106123bf68c0f022a22e143c6d9ae`: 574 tests passed, and the Windows PyInstaller folder build, packaged-app smoke test and artifact upload all succeeded. This verifies packaging and configured tests, not live VPN connectivity.

## Latest engineering changes

- Connection lifecycle cleanup and validation semantics were hardened; cleanup failure retains the active profile for retry.
- Windows route/DNS intent now has a pure immutable validation model; no privileged mutations are performed.
- Connect remains disabled until a production Windows tunnel passes end-to-end route, DNS, leak, disconnect and crash-recovery acceptance tests.
