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

This is lifecycle orchestration only; the mock engine is not a VPN. On Windows, the desktop creates the live connection controller only when the protected Program Files helper is valid. APNA SSH and Xray engines are registered in that controller; UDPQ is conditionally registered only when its Windows sidecar and pinned runtime-manifest provenance/hashes validate. OpenVPN and standalone SOCKS remain unregistered. Connect is enabled only for a selected profile with a matching registered engine and valid engine-specific configuration. A successful Xray/APNA SSH/UDPQ Connect means the relevant engine and helper passed their local readiness gates (adapter, effective dual-stack routes, configured DNS, and certificate-validated IPv4 plus IPv6 TLS egress). It does not establish APNA-provider compatibility, DNS/IPv4/IPv6 leak resistance under failure, or crash/reboot recovery. Those remain release-acceptance requirements and must not be represented as proven by CI. If the elevated helper exits abnormally, its process ownership is retained and a replacement tunnel is blocked until network cleanup can be verified; the UI must not convert an uncertain cleanup into a successful disconnect.
