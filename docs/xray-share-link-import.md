# Xray share-link import and guarded connection path

## Scope

ApnaWin contains a generic Xray share-link import path for VLESS, VMess, Trojan and Shadowsocks, plus Hysteria2 parsing. Parsed profiles are converted into Xray outbound configuration and persisted through the current-user DPAPI-protected Xray config store.

This is a generic Xray compatibility feature. It is **not** evidence that the proprietary APNA Android application uses any of these protocols.

## Supported share-link inputs

- `vless://`: TCP/RAW, WebSocket or gRPC; TLS or REALITY; UUID, encryption and flow fields.
- `vmess://`: Base64 JSON links with TCP/RAW, WebSocket or gRPC and supported TLS options.
- `trojan://`: TLS or REALITY with TCP/RAW, WebSocket or gRPC.
- `ss://`: supported SIP002 user-info and legacy Base64 forms with the implemented Xray cipher allowlist.
- `hysteria2://`: supported Hysteria2 URI subset, including the explicitly supported Salamander obfuscation form.

The parser rejects duplicate/unknown query parameters, unsupported transports, malformed Base64, invalid ports, oversized input, unsupported ciphers/plugins, and unsupported VMess legacy options. It does not silently discard URI extensions it does not understand. Hysteria2 configuration forces TLS verification; the parser does not accept an insecure TLS bypass.

The implemented transport subset is intentionally not every Xray transport. XHTTP, mKCP, HTTPUpgrade and unsupported plugin/vendor extensions remain rejected until implemented with dedicated schema and security tests.

## Application integration present in source

The application source includes these code paths:

1. Import a bounded text file containing share links.
2. Parse and validate the supported links.
3. Persist the resulting Xray TUN configurations using the DPAPI-backed config store; profile metadata is saved separately.
4. Select an Xray profile and check for the installed protected Program Files helper and its encrypted config.
5. Start `XrayConnectionWorker`, with Connect/Cancel/Disconnect and worker lifecycle callbacks.
6. Emit the connected state only after the configured traffic probe reports success; cleanup failures disable reconnect and retain a recovery path.

This describes source-level integration only. It does **not** establish that the Windows UI is currently enabled in every installation, that a particular server accepts the profile, or that a live tunnel is leak-free. The Connect control remains subject to application readiness gates and the project's Windows acceptance criteria.

## Security and operational boundaries

- Parsed objects hide credential-bearing fields from their repr. Never log raw links or outbound dictionaries.
- `to_outbound()` returns secrets in memory because Xray needs them. Persist the resulting config only through the existing DPAPI-protected store.
- The importer does not fetch subscription URLs, follow redirects, resolve hostnames, contact servers, or verify credentials.
- The UI worker/helper lifecycle is present in source, but mocked/unit tests are not proof of a functioning live VPN.
- The traffic probe's route-inspection-then-socket sequence has a possible TOCTOU gap. A route check does not prove that the probe socket was bound to the tunnel interface.
- The probe's system DNS use and single-read HTTP handling require bounded timeout and incremental response handling. A Windows network-trace acceptance test must verify no direct-WAN fallback during startup, steady state, route changes and shutdown.

## Validation still required

- Run the relevant parser/import/worker tests in a controlled local environment.
- Validate representative links against the exact packaged Xray-core version.
- Add bounded DNS, connect and read timeouts; parse the HTTP status line incrementally.
- Add Windows end-to-end tests and packet/network traces proving tunnel routing and no direct-WAN leak.
- Verify cleanup and route/DNS rollback after cancellation, process failure and route changes.

Until those gates pass, describe this as an integrated import and guarded connection implementation, not a verified production VPN client.

## Protocol-identification boundary

SSH remains paused. No SSH implementation or weakened SSH/TLS security behavior is introduced here. APNA's proprietary native protocol remains unidentified until APK/native configuration and runtime handshake evidence is recovered.
