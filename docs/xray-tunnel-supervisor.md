# Xray tunnel supervisor

XrayTunnelSupervisor is the desktop-side lifecycle wrapper around ElevatedXrayProcess. It accepts XRAY profiles only, requires an encrypted config record for the selected profile, starts the fixed Program Files helper, prevents a second simultaneous session, polls helper exit status, and signals the stop event during disconnect.

The helper performs the privileged work: decrypting the selected DPAPI config, validating it with Xray's run -test command, starting the fixed engine binary inside a Windows Job Object, and monitoring the desktop process and stop event. Xray runs in a dedicated hidden console process group so the helper can request graceful CTRL_BREAK shutdown before falling back to Job Object termination.

The supervisor reports process lifecycle only. A running helper is not proof that the VPN is connected. The UI must not show Connected until adapter state, both default routes, DNS path, leak protection and external connectivity have passed live checks. The main window is not yet wired to this class; Connect remains disabled.

The elevated helper now rejects non-TUN configurations and withholds its ready event until the named adapter is Up, both IPv4 and IPv6 default routes are attached to it, and every DNS address declared by the TUN configuration is present on that adapter. These conditions must remain stable for at least one second. The bounded wait also observes the desktop parent and stop event, so cancellation unwinds Xray instead of waiting for the full readiness timeout. This gate is not a substitute for external end-to-end traffic and WFP filter acceptance tests.
