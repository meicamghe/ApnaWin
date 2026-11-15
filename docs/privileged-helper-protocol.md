# Privileged helper request envelope

The platform-neutral `apnawin.services.privileged_protocol` module validates the outer request envelope before any future named-pipe service dispatches it.

- Payload must be non-empty UTF-8 and no larger than 64 KiB.
- JSON duplicate keys and non-standard numeric constants are rejected.
- The envelope must contain exactly `version`, `request_id`, `transaction_id`, `operation` and `arguments`.
- Version 1 uses lowercase canonical UUID strings and a fixed operation allowlist.
- JSON nesting, total values, object members, array items, key length and string length are bounded.
- Unknown operations and unknown envelope fields fail closed.

This is only envelope parsing. It does not create an IPC endpoint, authenticate a peer, authorize a session, deduplicate requests, validate operation-specific argument schemas, acquire the service mutex or perform Windows operations. The service must validate each operation's exact argument schema before any OS call; a structurally valid envelope is not authorization.
