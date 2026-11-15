# Read-only Windows tunnel diagnostics

WindowsTunnelDiagnostics queries the named ApnaWin adapter using a fixed, encoded PowerShell script. It does not change adapter state, routes, DNS or firewall policy. The result records whether the adapter exists and is Up, whether IPv4 and IPv6 default routes use its interface index, and which DNS server addresses are configured on that adapter.

The snapshot's routing_ready property is deliberately narrow: it means the adapter is Up, both default routes are present on that interface, and at least one valid DNS server is configured. It does not prove that DNS queries are actually using the tunnel, that packets reach the remote Xray server, that WFP leak filters were installed successfully, or that public internet traffic exits through the expected VPN server.

Before the UI can show Connected, combine this snapshot with:
- Xray helper/process liveness;
- verified Xray TUN WFP leak-filter state;
- a controlled DNS-resolution test;
- an external connectivity and egress-path test;
- disconnect and crash tests proving routes, DNS and adapter state return to baseline.

The PowerShell command is invoked with an argument array, no shell, a timeout, bounded JSON schema validation and strict IP-address parsing. The adapter alias is constrained to a short safe character set before it is embedded in the script. No route or DNS mutation is performed.
