# Xray tunnel supervisor

XrayTunnelSupervisor is the desktop-side lifecycle wrapper around ElevatedXrayProcess. It accepts XRAY profiles only, requires an encrypted config record for the selected profile, starts the fixed Program Files helper, prevents a second simultaneous session, polls helper exit status, and signals the stop event during disconnect.

The helper performs the privileged work: decrypting the selected DPAPI config, validating it with Xray's run -test command, starting the fixed engine binary inside a Windows Job Object, and monitoring the desktop process and stop event. Xray runs in a dedicated hidden console process group so the helper can request graceful CTRL_BREAK shutdown before falling back to Job Object termination.

The supervisor reports helper lifecycle to the production XrayTunnelEngine and ConnectionController, which are now wired into the main window on Windows when the protected helper and imported XRAY config are present. Connect remains disabled on non-Windows systems and whenever the required installation/config is missing. A successful helper readiness event is required before the UI shows Connected: the helper verifies runtime hashes, stable adapter state, effective IPv4/IPv6 default routes, configured DNS and an independent certificate-validated TLS egress probe. These are local tunnel-readiness checks, not proof of compatibility with a particular APNA provider.

The elevated helper now rejects non-TUN configurations and withholds its ready event until the named adapter is Up, both IPv4 and IPv6 default routes are attached to it, and every DNS address declared by the TUN configuration is present on that adapter. These conditions must remain stable for at least one second. The bounded wait also observes the desktop parent and stop event, so cancellation unwinds Xray instead of waiting for the full readiness timeout. This gate is not a substitute for external end-to-end traffic and WFP filter acceptance tests.

Before Xray starts, the helper checks that no pre-existing Windows adapter already owns the configured TUN name. It refuses to reuse an adapter left by another VPN or a prior failed session. While connected, the helper rechecks adapter, IPv4/IPv6 default routes and configured DNS every two seconds; three consecutive unhealthy samples trigger graceful Xray shutdown. This is a local routing-health monitor, not an external egress acceptance test.

The helper verifies the protected runtime manifest and SHA-256 hashes of `xray.exe` and `wintun.dll` before starting. It refuses to reuse an existing adapter with the configured TUN name, and monitors the adapter, effective dual-stack default routes and configured DNS while the tunnel is active. Three consecutive unhealthy samples trigger graceful Xray shutdown.

Before the helper signals ready, it also requires a certificate-validated TLS handshake to at least one of two independent public HTTPS endpoints by fixed IP address. This probe is initiated by the helper (not Xray), so it exercises the system TUN route and is subject to Xray's WFP leak filters. Failure to reach either endpoint fails startup closed. It is an egress smoke test, not a substitute for provider-specific application traffic acceptance.


## Ongoing egress supervision

After the initial independent TLS readiness probe, the elevated helper now repeats the same fixed-IP, certificate-validated TLS probe every 15 seconds. Three consecutive failed probes trigger graceful Xray shutdown and a distinct helper exit code. Route/DNS health remains sampled every two seconds. These checks reduce the chance of leaving a dead tunnel marked connected; they do not replace real provider-specific traffic and leak acceptance.
