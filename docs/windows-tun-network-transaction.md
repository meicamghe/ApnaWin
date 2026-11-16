# Windows TUN and network-state architecture

## Decision

ApnaWin uses Xray-core's native Windows `tun` inbound with the pinned Wintun DLL. It does **not** implement a second Python Wintun packet engine or a separate route/DNS mutation stack. Xray owns packet I/O, adapter configuration, IPv4/IPv6 routes, DNS assignment, physical-interface binding for its own remote-proxy sockets, and the native Windows Filtering Platform (WFP) leak filters.

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
- exactly the required `autoSystemWfpBlockLeak: ["allexceptlan", "dns"]` WFP leak filters;
- a primary remote-proxy outbound supported by Xray;
- no direct `freedom`, `loopback`, unsupported or unverified DNS outbound path.

The `allexceptlan` filter blocks non-LAN traffic from escaping outside TUN while preserving LAN access. The additional `dns` filter is required because the LAN exception alone can leave router DNS reachable on the physical interface. The Python validator enforces both values and Xray's own `run -test -c` is executed again by the elevated helper. If WFP setup fails, startup must not be reported ready.

## Startup readiness and runtime supervision

1. Verify the helper's protected install path and runtime hashes.
2. Decrypt and validate the selected Xray config; run Xray's config test.
3. Refuse to reuse a pre-existing adapter with the requested TUN alias.
4. Start Xray and wait for the named adapter to become Up.
5. Verify the best effective IPv4 and IPv6 default routes (combined route and interface metrics) select only the TUN interface; a tie with another interface fails closed.
6. Verify every DNS server declared by the TUN config is assigned to the TUN interface, and require those conditions to remain stable.
7. Require a certificate-validated TLS handshake to at least one independent public endpoint by fixed IP, initiated by the helper so the connection exercises the system TUN route and Xray's WFP policy.
8. Only then signal helper readiness. While active, recheck adapter, effective routes and DNS every two seconds; three consecutive unhealthy samples trigger graceful Xray shutdown. Independent TLS egress is checked every 15 seconds; three consecutive failures also trigger graceful shutdown.

The TLS probe is a basic IPv4 data-plane smoke test. It does not prove APNA-specific traffic, IPv6 egress, every possible leak path, or WFP behavior under all Windows network transitions.

## Desktop integration status

The Windows desktop Connect/Disconnect controls are wired to `ConnectionController`, `XrayTunnelEngine` and `XrayTunnelSupervisor`. Connect is enabled only on Windows when the protected installed helper exists, an Xray profile is selected, and that profile has an encrypted imported TUN configuration. The UI reports Connected only after the elevated helper signals successful local readiness. This is not a claim that an authorized APNA server configuration has connected successfully.

## Disconnect, crash and recovery

A normal disconnect signals the helper, which asks Xray to stop gracefully so Xray's own TUN cleanup can restore interface, route, DNS and WFP state. If the helper misses its readiness deadline, the parent requests the same graceful stop and uses forced termination only as a bounded fallback. The Job Object kills Xray if the helper process exits.

Forced termination bypasses Xray's Go cleanup path. Xray's WFP filters are process-owned and are removed when Xray exits; that is not a persistent independent kill switch. Route/address/DNS and adapter state after helper crash, forced process termination, desktop crash or reboot must be verified on real Windows systems rather than assumed clean. The experimental Python route/DNS journal is not wired into the production Xray path and does not recover Xray-owned WFP filters.

## Remaining release gates

- Test on clean Windows 10 and Windows 11 x64 systems with the actual packaged Wintun runtime.
- Verify DNS query behavior and DNS leak paths, IPv4/IPv6 leak behavior, WFP policy under route changes, and provider-specific application traffic.
- Verify graceful disconnect, helper crash, desktop crash, forced Xray termination, sleep/resume and reboot recovery; no stale routes, DNS settings or ApnaWin-owned adapters may remain.
- Validate that loss of Xray does not create an unacceptable traffic-leak window; if a persistent kill switch is required, design and test it as a separate, transactionally managed component rather than assuming Xray's process-owned WFP filters persist.
- Obtain and validate an authorized APNA configuration/catalog/authentication source. No APNA endpoint, credentials or API schema is inferred by this project.

A successful package build or local readiness probe is not proof of APNA connectivity or leak-free operation.
