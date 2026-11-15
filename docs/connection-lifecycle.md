# Connection lifecycle controller

`ConnectionController` is a transport-neutral synchronous coordinator around the `TunnelEngine` contract.

- Validates a profile before entering `CONNECTING`.
- Rejects overlapping or duplicate connection attempts.
- Enters `CONNECTED` only when the engine itself reports that state.
- Requests engine cleanup after a failed or unconfirmed connect and retains any cleanup exception on `ConnectionLifecycleError`.
- Keeps the active profile and enters `ERROR` when disconnect fails, allowing a caller to retry cleanup.
- Makes disconnect from `DISCONNECTED` idempotent.

This is lifecycle orchestration only. It does not make the mock engine a VPN, does not create a tunnel, and does not verify TUN, DNS, routes, remote reachability, or rollback. The desktop Connect button remains disabled until a production Windows engine passes the end-to-end acceptance checklist.
