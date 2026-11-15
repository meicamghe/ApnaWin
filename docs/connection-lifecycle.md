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

This is lifecycle orchestration only. It does not make the mock engine a VPN, does not create a tunnel, and does not verify TUN, DNS, routes, remote reachability, or rollback. The desktop Connect button remains disabled until a production Windows engine passes the end-to-end acceptance checklist.
