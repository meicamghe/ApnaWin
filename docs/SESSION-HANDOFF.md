# Session handoff

## Current repository state

The native Windows application shell, profile management, Xray process runner, Windows Job Object supervision, remote catalog schema/cache, refresh coordinator and bounded HTTPS transport are implemented. The Connect button remains intentionally disabled because a verified Windows tunnel/TUN integration and authorized end-to-end server configuration are not yet available.

## Remote configuration

The Android app is believed to refresh server information and connection behavior, but the APK/network evidence has not yet been supplied. No APNA endpoint, authentication scheme, signature format, or upstream response schema is known. Do not invent any of these. See [remote-configuration.md](remote-configuration.md).



## Latest verification

Workflow run [#144](https://github.com/meicamghe/ApnaWin/actions/runs/43568756016) passed:
- Python unit tests
- Windows portable build
- Packaged-app smoke test
- Artifact upload

This verifies the desktop package starts in CI; it does not verify VPN connectivity or system-wide traffic tunneling.

## Latest engineering change

The refresh coordinator now retains a result per in-flight generation while that generation has waiting callers. A subsequent refresh cannot overwrite the result observed by callers that joined the earlier attempt. Waiting-result entries are removed after the final waiter consumes them. The new lifecycle assertions and the full Windows workflow are pending verification on the latest commit.
