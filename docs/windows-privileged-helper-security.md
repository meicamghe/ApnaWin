# Windows privileged networking helper: security and API contract

## Status

Design only. No Windows service, named-pipe server, route mutation, DNS mutation or Wintun adapter creation is implemented. The desktop process remains unprivileged and the Connect button remains disabled.

## Process boundary

- Keep the PySide6 desktop process unprivileged. It owns presentation, profile selection and user consent only.
- Put privileged networking operations behind a narrowly scoped Windows service/helper installed with explicit administrator consent.
- The helper owns Wintun handles, route/DNS mutations and the durable transaction journal. It does not accept arbitrary process launches, executable paths, DLL paths, scripts, command lines or shell fragments from the desktop.
- The helper must not expose a general-purpose administrator RPC interface. Its API is a fixed allowlist of typed networking operations.

## Local IPC requirements

The initial transport candidate is a local named pipe with all of these controls:

1. Create the pipe with `PIPE_REJECT_REMOTE_CLIENTS`; do not rely on the pipe name alone to make it local-only.
2. Supply an explicit security descriptor. Do not pass a null security descriptor: the documented default grants read access to Everyone and anonymous users in addition to full control for SYSTEM, administrators and creator owner.
3. Grant only the required read/write rights to SYSTEM, the service identity and the intended interactive user/session. Deny network/remote access.
4. Authenticate the connected peer using its actual pipe token and session identity. Do not trust a PID, username string or client-supplied identity field.
5. If client impersonation is used for authorization, always call `RevertToSelf` in a `finally` path. Do not accidentally perform privileged mutations while impersonating an unprivileged client.
6. Use bounded message framing: strict UTF-8 JSON, maximum 64 KiB per request, duplicate-key rejection, exact schema/version checks, bounded arrays and a finite request timeout.
7. Return structured error codes and a correlation ID. Never return secrets, raw token data, arbitrary exception text or unbounded OS output.

The named-pipe security descriptor and remote-client flag are independent controls; both are required. The service must reject requests from other sessions unless a documented multi-session product requirement is added.

## Versioned request surface

Every request contains only:
- protocol version;
- request UUID;
- transaction UUID;
- one allowlisted operation name;
- a typed argument object for that operation.

Initial operation names may include `snapshot_network`, `create_owned_adapter`, `configure_owned_adapter`, `add_owned_route`, `set_interface_dns`, `restore_interface_dns`, `remove_owned_route`, `remove_owned_adapter`, and `query_transaction`.

The allowlist is not permission to implement all operations at once. Each operation needs a separately reviewed schema, precondition, postcondition, idempotency rule, ownership rule, compensation and Windows integration tests. The helper must reject unknown operations and unknown fields.

## Windows API mapping

### Routes

- Enumerate IPv4 and IPv6 route tables with `GetIpForwardTable2(AF_UNSPEC)`; release the returned table with `FreeMibTable`.
- Build route rows with exact destination prefix, next hop and interface LUID. `CreateIpForwardEntry2` requires a valid destination prefix, same-family next hop and interface LUID or index.
- Delete only the exact route entry owned by the current transaction. `DeleteIpForwardEntry2` matches destination prefix, next hop and interface identity; do not delete a route based only on its destination prefix.
- Capture interface metrics as well as route metrics. Windows' effective route metric combines the route metric offset with the interface metric.
- Query the best route after mutation and compare the selected interface with the expected interface before reporting success.

### DNS

- `GetInterfaceDnsSettings` and `SetInterfaceDnsSettings` operate on an interface GUID, not an interface LUID. The helper must resolve and verify the LUID/GUID mapping before use.
- Initialize the requested settings structure with the correct version and empty flags for reads; free the returned settings with `FreeInterfaceDnsSettings`.
- Snapshot the complete supported DNS settings structure, not just the nameserver string, before mutation. Restore the captured settings, not guessed defaults.
- These DNS APIs document Windows 10 build 19041 as the minimum supported client for Get/Set. If an older supported Windows build is encountered, fail closed until a separately tested compatibility implementation exists.
- Verify DNS behavior after applying settings; a successful API return alone is not a DNS leak or resolver-behavior test.

## Transaction and ownership rules

- Persist the pre-change snapshot and transaction identity before the first mutation.
- Record each successful mutation immediately after its postcondition is verified.
- A resource is removable only if the current transaction created it and its exact identity still matches the journal.
- Before rollback, compare current state with the transaction's recorded after-state. If another program or user has changed it, do not overwrite that newer state; mark recovery required and preserve diagnostics.
- Roll back in reverse order. Preserve the journal on any partial failure.
- On service start, reconcile incomplete transactions before accepting new connection requests.
- Serialize `recover`, `execute` and `rollback` with one service-owned named Windows mutex. Create/open it with an explicit DACL granting access only to SYSTEM and the service SID; do not rely on a default DACL or a client-created object.
- Hold the mutex across the complete journal read/check, adapter mutation, verification and journal persistence sequence. A per-process Python lock is not a substitute.
- Treat `WAIT_ABANDONED` as evidence that the previous owner terminated unexpectedly. Keep ownership of the mutex, run conservative journal recovery, and accept no new transaction until recovery succeeds.
- Use a bounded wait. A timeout or mutex acquisition failure must fail closed without mutating routes or DNS.
- Release ownership in a `finally` path and close the mutex handle. Never release a mutex from a thread other than the owning thread.
- Journal only bounded network metadata and opaque resource IDs; never store credentials, private keys or complete Xray configuration.

The mutex is a second serialization layer in addition to the journal's atomic persistence. It protects the check-then-act interval across multiple service processes; it does not replace compare-before-restore checks or journal recovery.

## Minimum security and failure tests

- Remote named-pipe connection rejected even if the pipe name is known.
- Anonymous, unrelated-user and unrelated-session clients rejected.
- Malformed, oversized, duplicate-key, unknown-version and unknown-operation requests rejected before any OS call.
- Client disconnect, service crash and desktop crash at every transaction boundary.
- Route add collision and route deletion mismatch do not remove pre-existing routes.
- DNS snapshot failure prevents DNS mutation; DNS restore failure retains the journal.
- Interface LUID/GUID changes between snapshot and mutation cause a safe abort.
- Repeated request UUIDs do not duplicate a completed mutation.
- Helper restart reconciles only resources owned by its incomplete transaction.

## References

- Microsoft `CreateNamedPipeW`: remote-client rejection and default pipe ACL behavior: https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- Microsoft named-pipe client impersonation: https://learn.microsoft.com/windows/win32/ipc/impersonating-a-named-pipe-client
- Microsoft named-pipe security overview: https://learn.microsoft.com/windows/win32/ipc/named-pipes
- Microsoft `GetIpForwardTable2`: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/getipforwardtable2
- Microsoft `CreateIpForwardEntry2`: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/createipforwardentry2
- Microsoft `DeleteIpForwardEntry2`: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2
- Microsoft `GetInterfaceDnsSettings`: https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings
- Microsoft `SetInterfaceDnsSettings`: https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
