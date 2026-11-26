# Read-only Windows tunnel diagnostics

WindowsTunnelDiagnostics queries the named ApnaWin adapter using a fixed, encoded PowerShell script. It does not change adapter state, routes, DNS or firewall policy. The result records whether the adapter exists and is Up, whether its interface owns every best IPv4 and IPv6 default route after combining route and interface metrics (a tie with another interface fails closed), and which DNS server addresses are configured on that adapter.

The snapshot's routing_ready property is deliberately narrow: it means the adapter is Up, the best effective IPv4 and IPv6 default routes select only that interface, and at least one valid DNS server is configured. The elevated helper additionally requires every DNS server in the TUN config to be present and performs a certificate-validated external TLS handshake through the system TUN route before signaling ready. This does not prove provider-specific application traffic, IPv6 egress, or every DNS/leak path.

The helper currently combines this snapshot with:
- Xray helper/process liveness and strict TUN config validation;
- required Xray WFP leak-protection policy (Xray refuses startup if WFP filters cannot be installed);
- exact configured DNS server presence;
- an independent external TLS egress smoke test through the TUN;
- periodic route/adapter/DNS health checks and graceful shutdown after repeated failure.

Before the UI can show Connected, clean Windows 10/11 acceptance must still cover provider-specific application traffic, DNS resolution/leak behavior, IPv6 egress expectations, WFP behavior under failure, and disconnect/crash/reboot restoration to baseline.

The PowerShell command is invoked with an argument array, no shell, a timeout, bounded JSON schema validation and strict IP-address parsing. The adapter alias is constrained to a short safe character set before it is embedded in the script. No route or DNS mutation is performed.
