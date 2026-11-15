# Windows TUN and network-state transaction design

## Decision status

Wintun is the leading TUN adapter candidate for the Windows 10/11 client, subject to a pinned-binary review, architecture checks, redistribution-license review, clean-machine installation tests and an authorized end-to-end Xray configuration. This document records the implementation boundary; it does not claim that an adapter, route or DNS integration exists today.

The upstream Wintun project describes a Layer-3 TUN driver for Windows 7 through 11. Its documented API creates or opens an adapter, obtains its interface LUID, starts a packet-ring session, and transfers IPv4/IPv6 packets. The upstream site currently lists Wintun 0.14.1 and a SHA-256 for its downloadable archive. The project source is GPL-2.0, while the prebuilt signed DLL archive has a separate, more permissive license included with that archive. ApnaWin must review and retain the exact binary archive license and hash before redistribution; it must not build or redistribute the GPL driver source as if it were covered by the binary license.

## Proposed ownership boundaries

1. **Unprivileged desktop process**: profile selection, status presentation, diagnostics and user consent. It must not directly mutate system routes or DNS.
2. **Privileged networking helper/service**: narrowly scoped operations for adapter creation/configuration, interface addresses, routes and DNS. It accepts a versioned, strictly validated request and returns structured results. It must not accept arbitrary shell commands or arbitrary executable paths from the UI.
3. **Tunnel engine process**: owns the Xray process tree using the existing Windows Job Object launcher. It must be ready before traffic is redirected into the TUN interface.
4. **Transaction journal**: records the exact pre-change state and each successfully applied operation, with bounded, redacted metadata. Secrets and full profile credentials must not be written to the journal.

## Connect transaction (fail closed)

1. Validate profile and a fully generated Xray configuration; run Xray's config test.
2. Verify required privilege/helper availability and the pinned Wintun DLL architecture/hash before changing networking.
3. Snapshot relevant interface addresses, metrics, routes and DNS settings. Record only the exact state required to restore what this transaction changes.
4. Create/open the uniquely named Wintun adapter; obtain its LUID; configure addresses and MTU; start the packet session.
5. Start the Xray process under the existing Job Object and verify its local SOCKS protocol readiness. Local SOCKS readiness alone is not tunnel readiness.
6. Start the packet-forwarding/data-plane integration and verify bounded, authorized end-to-end traffic through the intended tunnel.
7. Only after the data plane is confirmed, apply the planned route and DNS changes. Preserve an explicit route to the VPN server through the original physical interface to avoid recursive tunneling.
8. Verify route selection and DNS behavior using controlled probes. Publish CONNECTED only after all required checks succeed.

Every operation must be idempotent or have a compensating action. If any step fails, unwind in reverse order using the transaction journal. A failed rollback is a hard ERROR with retained ownership/diagnostics; it must never be reported as DISCONNECTED or CONNECTED until state is reconciled.

## Disconnect and crash recovery

1. Stop admitting new packet work and stop forwarding.
2. Restore DNS and routes from the transaction's captured pre-change values, not guessed defaults.
3. Confirm route and DNS restoration before removing the adapter.
4. End the Wintun session, close the adapter handle and remove only the adapter created/owned by this transaction.
5. Stop the Xray process tree and confirm Job Object active-process count is zero.
6. Mark DISCONNECTED only after all owned resources are confirmed released. On partial failure, retain the journal and helper/service ownership so cleanup can be retried.

A service restart or desktop crash must not erase an active transaction record. Startup recovery must reconcile recorded adapter, route and DNS state before allowing another connection attempt. Never delete unrelated user routes or pre-existing adapters.

## Wintun API lifecycle requirements

- Resolve the documented DLL exports dynamically and reject missing/unknown exports before system changes.
- Verify the DLL's PE machine type matches the packaged process architecture and verify its pinned SHA-256.
- Use a unique, stable vendor pool/name policy; do not use generic names that collide with other VPN clients.
- Keep adapter/session handles owned by one lifecycle object; close them in reverse acquisition order.
- For received packets, always release each packet buffer after processing, including exceptions.
- Treat ring exhaustion as backpressure/drop telemetry, not as a reason to allocate unbounded memory.
- Wait on the Wintun read event when no packet is available; use cancellable waits so shutdown is bounded.
- Do not call the API from UI callbacks or block the GUI thread on packet I/O.

## Windows route and DNS requirements

- Prefer documented Windows IP Helper APIs for route/interface inspection and mutation over parsing localized command output.
- Capture route keys and metrics precisely enough to restore only entries changed by ApnaWin.
- Keep the VPN server endpoint reachable through the physical interface; prevent default-route recursion.
- Treat IPv4 and IPv6 separately. Do not claim IPv6 leak protection unless IPv6 routes and DNS are covered and tested.
- DNS changes must be interface-scoped, reversible and verified with both positive and negative resolution tests. If the chosen supported Windows API cannot preserve the prior state exactly, do not apply the change.
- Use explicit privilege boundaries and least privilege. The helper must validate all addresses, prefixes, interface identifiers, route metrics and operation counts.

## Test gates before enabling Connect

- Unit tests for every transaction transition, compensation action and failure point.
- Windows integration tests on clean Windows 10 and Windows 11 x64 VMs.
- Tests for pre-existing routes/DNS, multiple adapters, IPv4-only, dual-stack, sleep/resume, interface changes, helper crash and desktop crash.
- Confirm no route/DNS residue after normal disconnect, failed connect, forced process termination and reboot recovery.
- Verify traffic to the authorized test server, DNS behavior, endpoint route pinning and absence of unintended cleartext fallback.
- Confirm exact Wintun binary version, hash, signature and included redistribution license in the release manifest.

## Current limitations

The repository does not yet contain the Wintun DLL, privileged helper/service, packet-forwarding integration, route/DNS transaction manager or an authorized APNA-compatible Xray configuration. The existing Xray runner and SOCKS probes are building blocks only. Connect remains disabled.

## References

- Wintun official project and usage/API documentation: https://www.wintun.net/
- Wintun upstream API reference mirror: https://github.com/WireGuard/wintun
- Microsoft Windows IP Helper API overview: https://learn.microsoft.com/windows/win32/iphlp/ip-helper-start-page
