# Connection lifecycle controller

`ConnectionController` is a transport-neutral synchronous coordinator around the `TunnelEngine` contract.

- Serializes connect/disconnect operations with a controller lock.
- Validates a profile exactly once before entering `CONNECTING`; validation failure leaves state unchanged and does not call cleanup.
- Rejects overlapping or duplicate connection attempts.
- Enters `CONNECTED` only when the engine itself reports that state.
- Requests engine cleanup after a failed or unconfirmed connect and preserves the original failure as the primary exception cause/message.
- Retains both the cleanup exception and active profile when cleanup fails, so ownership information remains available for diagnostics and retry.
- Clears the active profile after successful cleanup, while leaving the controller in `ERROR` to make the failed attempt explicit.
- Keeps the active profile and enters `ERROR` when an ordinary disconnect fails, allowing a caller to retry cleanup.
- Makes disconnect from `DISCONNECTED` idempotent.

Engine adapters are called only after controller preflight validation and should not repeat that validation in `connect()`. Each production adapter must independently verify its required readiness before reporting `CONNECTED`.

This is lifecycle orchestration only; the mock engine is not a VPN. On Windows, the desktop is wired to the production Xray TUN engine and enables Connect only when the protected Program Files helper, an XRAY profile, and its encrypted imported TUN configuration are available. A successful Connect means the helper passed its local readiness gates (adapter, effective dual-stack routes, configured DNS, and certificate-validated TLS egress). It does not establish APNA-provider compatibility, IPv6 application egress, DNS/IPv4/IPv6 leak resistance under failure, or crash/reboot recovery. Those remain release-acceptance requirements and must not be represented as proven by CI.
