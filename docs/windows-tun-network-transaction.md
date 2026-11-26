# Windows TUN and network-state architecture

## Decision

ApnaWin uses Xray-core's native Windows `tun` inbound with the pinned Wintun DLL. It does **not** implement a second Python Wintun packet engine or a separate route/DNS mutation stack. Xray owns packet I/O, adapter configuration, IPv4/IPv6 routes, DNS assignment, physical-interface binding for its own remote-proxy sockets, and WFP leak filters.

The older `wintun_session.py`, `windows_network_plan.py`, `windows_network_journal.py` and `windows_network_transaction.py` modules are experimental building blocks; they are not in the production connection path. Do not add a second packet forwarder or duplicate route manager unless clean-machine testing proves a specific Xray behavior cannot meet a requirement.

## Packaged runtime and privilege boundary

- Xray-core v26.11.9 and Wintun 0.14.1 are downloaded from pinned release archives.
- The build verifies archive SHA-256, PE AMD64 architecture, Xray version and Wintun Authenticode signer, and retains both license notices.
- A generated runtime manifest records archive and binary hashes. The elevated helper verifies the installed `xray.exe` and `wintun.dll` hashes before launch.
- The desktop remains medium-integrity. A fixed helper installed under Program Files is launched through UAC `runas`, decrypts only the selected current-user DPAPI config, and supervises Xray in a kill-on-close Job Object.
- The installer requires the runtime manifest and applies protected Program Files ACLs.

## Strict full-tunnel configuration

The import path accepts one Xray TUN inbound with:
- usable IPv4 and IPv6 gateway prefixes and both default routes;
- one to eight unique DNS server addresses;
- `autoOutboundsInterface: "auto"`;
- exactly the required `allexceptlan` and `dns` WFP leak filters;
- a primary remote-proxy outbound supported by Xray;
- no direct `freedom`, `loopback`, unsupported or unverified DNS outbound path.

The first outbound is Xray's primary outbound. Rejecting direct outbounds prevents a config from presenting a full-tunnel UI while sending traffic straight to the physical network. Xray's own `run -test -c` is executed again by the elevated helper before startup.

## Startup readiness gate

1. Verify the helper's protected install path and runtime hashes.
2. Decrypt and validate the selected Xray config; run Xray's config test.
3. Refuse to reuse a pre-existing adapter with the requested TUN alias.
4. Start Xray and wait for the named adapter to become Up.
5. Verify the best effective IPv4 and IPv6 default routes (combined route and interface metrics) select only the TUN interface; a tie with another interface fails closed.
6. Verify every DNS server declared by the TUN config is assigned to the TUN interface, and require those conditions to remain stable.
7. Require a certificate-validated TLS handshake to at least one independent public endpoint by fixed IP, initiated by the helper so the connection exercises the system TUN route and WFP policy.
8. Only then signal helper readiness. While active, recheck adapter, effective routes and DNS every two seconds; three consecutive unhealthy samples trigger graceful Xray shutdown.

The TLS probe is a basic IPv4 data-plane smoke test. It does not prove APNA-specific traffic, IPv6 egress, or every possible leak path.

## Disconnect and recovery

A normal disconnect signals the helper, which asks Xray to stop gracefully so Xray's own TUN cleanup can restore interface, route, DNS and WFP state. If the helper misses its readiness deadline, the parent requests the same graceful stop and uses forced termination only as a bounded fallback. The Job Object kills Xray if the helper process exits.

Forced termination bypasses Xray's Go cleanup path. Route/address/DNS and adapter state after helper crash, forced process termination, desktop crash or reboot are not assumed to be clean; they require native Windows acceptance tests. Do not claim successful recovery until the before/after network snapshots prove it.

## Remaining release gates

- The desktop Connect/Disconnect UI is already wired to `XrayTunnelSupervisor`; Connect is enabled only when the protected helper and an encrypted imported XRAY TUN profile are available. This is a local-readiness gate, not APNA-provider or leak-safety acceptance.
- Test on clean Windows 10 and Windows 11 x64 systems with the actual packaged Wintun runtime.
- Verify DNS query behavior and DNS leak paths, IPv4/IPv6 leak behavior, WFP policy under route changes, and provider-specific application traffic.
- Verify graceful disconnect, helper crash, desktop crash, forced Xray termination, sleep/resume and reboot recovery; no stale routes, DNS settings or ApnaWin-owned adapters may remain.
- Obtain and validate an authorized APNA configuration/catalog/authentication source. No APNA endpoint, credentials or API schema is inferred by this project.

**Connection readiness is implemented, but release acceptance is incomplete.** The Windows UI can start the helper when its installation and encrypted XRAY TUN profile prerequisites are met. A successful readiness event verifies local adapter/routes/DNS plus an IPv4 TLS egress smoke test; it does not prove APNA-specific traffic, IPv6 egress, DNS/IPv4/IPv6 leak resistance, or forced-termination/reboot recovery. Do not label the build leak-free or APNA-compatible until those native Windows acceptance tests pass.
