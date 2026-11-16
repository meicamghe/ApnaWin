# Connection lifecycle controller

`ConnectionController` is the transport-neutral coordinator used by the Windows desktop UI with the production `XrayTunnelEngine`.

- Serializes connect/disconnect operations with a controller lock.
- Validates the selected profile before entering `CONNECTING`; validation failure leaves lifecycle state unchanged and does not request cleanup.
- Rejects overlapping or duplicate connection attempts.
- Enters `CONNECTED` only when the engine itself reports that state after the elevated helper has signaled readiness.
- Requests engine cleanup after a failed or unconfirmed connect and preserves the original failure as the primary exception cause/message.
- Retains the cleanup exception and active profile when cleanup fails, so ownership information remains available for diagnostics and retry.
- Clears the active profile after successful cleanup, while leaving the controller in `ERROR` to make the failed attempt explicit.
- Keeps the active profile and enters `ERROR` when an ordinary disconnect fails, allowing a caller to retry cleanup.
- Makes disconnect from `DISCONNECTED` idempotent.

## Windows desktop integration

The PySide6 desktop creates the production controller only on Windows when the fixed elevated helper exists at the protected `Program Files\\ApnaWin` location. The Connect control is enabled only when a controller exists, an Xray profile is selected, and that profile has an encrypted imported TUN configuration. Connection work runs off the UI thread.

The helper reports ready only after runtime hash verification, strict Xray config validation, TUN adapter readiness, effective IPv4 and IPv6 default-route checks, configured DNS checks, and a certificate-validated independent TLS egress probe. The helper then monitors routes/DNS and periodically probes egress; repeated failures cause Xray to stop. The UI's Connected status therefore means these local readiness checks passed, not that APNA-specific service traffic has been independently accepted.

## Release limitations

The controller is not itself a packet engine or a persistent system firewall. Windows TUN/WFP leak filters are requested through Xray's native `autoSystemWfpBlockLeak: ["allexceptlan", "dns"]` configuration and the strict config validator rejects a missing or weakened setting. This is not equivalent to an independent persistent kill switch surviving Xray/helper termination. Clean-machine Windows acceptance is still required for actual DNS/IPv4/IPv6 leak behavior, WFP filter lifecycle, abrupt process termination, route/DNS restoration, sleep/resume and reboot recovery. An authorized APNA configuration and successful provider-specific traffic test are also still required.

Do not interpret a successful package build or unit-test run as proof of APNA connectivity or leak-free operation.
