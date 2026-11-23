# APNA live Windows acceptance runbook

This runbook is for an authorized APNA Lite SSH profile on a clean Windows 10/11 host. It is deliberately separate from CI unit tests: mocked transports and a successful package build do not prove provider compatibility.

## Preconditions

- Use an APNA server and credentials that you are authorized to use.
- Obtain the SSH host-key SHA-256 fingerprint from an independent provider-controlled source. A fingerprint returned by the app's Probe SSH host key button is only an observation of the endpoint and is not trusted evidence by itself. Prefer a provider-issued TLS CA bundle; the per-profile self-signed TLS compatibility switch is an explicit fallback, not a trust substitute.
- Confirm the profile's SSH endpoint, payload mode, UDPGW endpoint/port and account credentials from the provider's own configuration. Do not guess missing fields.
- Record the Windows build, network adapter, and baseline route/DNS state before testing. Do not put passwords, payload secrets, or full profile exports in logs or issue reports.

## Acceptance sequence

1. Install the current verified x64 package and launch ApnaWin as a standard user. Approve the signed/elevated helper only when Windows requests it.
2. Import the APNA Lite APK or fetch the live catalog. Select only a supported SSH-family server/payload pair. Unsupported categories must remain disabled rather than being guessed.
3. Enter the independently verified SSH host-key fingerprint (or configure a trusted known_hosts entry). The probe button can display the observed key but does not authenticate its trustworthiness. Keep TLS certificate verification enabled by default. If the provider endpoint is known to use a self-signed/untrusted TLS certificate and no provider CA bundle is available, the user may explicitly enable compatibility mode for that profile only; this disables TLS certificate-chain and hostname checks, retains TLS encryption and SNI, and exposes the connection to man-in-the-middle interception. It does not bypass SSH host-key verification or SSH authentication.
4. Save the profile and connect. Startup must complete SSH authentication, the configured UDPGW preflight, local SOCKS5 startup, Xray/Wintun startup, UDP DNS checks and certificate-validated IPv4 + IPv6 TLS egress checks before showing Connected.
5. With the tunnel active, verify separately:
   - HTTPS over IPv4 (for example, curl.exe -4 https://www.cloudflare.com/cdn-cgi/trace).
   - HTTPS over IPv6 (for example, curl.exe -6 https://www.cloudflare.com/cdn-cgi/trace).
   - DNS resolution and the resolver actually used; check for DNS leakage from the physical interface.
   - A known UDP application flow other than DNS, using a test endpoint you control. DNS success alone is not a UDPGW acceptance test.
   - The observed public egress addresses and that they belong to the authorized provider path.
6. Disconnect normally. Confirm the Xray helper exits, APNA SSH/SOCKS resources close, and the original physical routes and DNS settings are restored.
7. Repeat with an interrupted SSH transport and an unexpected helper exit. The app must enter ERROR, retain ownership of resources whose cleanup is unconfirmed, and must not report a false successful disconnect.

## Evidence to retain

- Redacted profile identifiers and selected transport category (never credentials or payload secrets).
- SSH host-key fingerprint plus the independent provider source used to verify it.
- Timestamp, Windows build, adapter names and before/after route/DNS snapshots.
- Pass/fail and exit status for IPv4, IPv6, DNS, non-DNS UDP, disconnect and crash-cleanup checks.
- Redacted application/helper diagnostics.

## Release gate

A release candidate requires all acceptance steps to pass on at least one clean Windows 10 and one clean Windows 11 host using an authorized APNA endpoint. A passing CI suite, live catalog fetch, native BadVPN build, or TLS readiness probe alone is not sufficient evidence of an authenticated APNA tunnel carrying real user traffic.

## Per-profile failure triage

Treat each imported server/payload combination as an independent profile. Do not copy a diagnosis from one profile to another and do not automatically rewrite a failed profile using another profile's host, port, payload, SNI or UDPGW endpoint. Record the profile name and endpoint shown in the error dialog.

| Failure stage / message | What it proves | Safe next check |
|---|---|---|
| DNS resolution failed | The configured endpoint name did not resolve from this network. | Check that profile's exact endpoint and DNS availability. |
| TCP connection failed / refused / timeout | No usable TCP socket was established. | Verify that profile's host, port, network reachability and provider status. |
| TLS self-signed / untrusted issuer | TLS certificate validation failed before SSH. | Prefer the provider-published CA chain from a trusted source. If unavailable and the user deliberately accepts MITM risk, enable the explicit per-profile compatibility mode; record that decision and still require independently verified SSH host-key pinning. Never enable it globally or treat it as proof of endpoint identity. |
| TLS hostname/SNI mismatch | The certificate identity does not match the requested TLS name. | Compare the profile's endpoint and SNI with provider instructions. An IP-literal SNI paired with a DNS endpoint is a warning, not permission to guess a replacement. |
| HTTP 101 / WebSocket Upgrade | The endpoint switched protocols. The client validates the complete RFC 6455 handshake (GET HTTP/1.1, Upgrade, Connection, version 13, key and accept value), then unwraps masked client and unmasked server binary frames into the SSH byte stream. | Confirm the provider's exact WebSocket payload and endpoint. Missing or invalid handshake headers, bad accept values, text frames, masked server frames and malformed control frames fail closed. Never pass raw WebSocket frames directly to SSH. |
| HTTP 301/302 | The payload endpoint redirected instead of establishing the expected SSH stream. | Check the selected payload host, path, Host header and port with the provider. Redirects are intentionally not followed. |
| HTTP 400 | The proxy rejected the request syntax or target. | Review only that profile's payload template, HTTP version, Host, target and CRLF placement. |
| HTTP 403 | The proxy or edge policy denied the request. If headers identify `Server: CloudFront`, a CloudFront `Via` hop, or `X-Cache: Error from cloudfront`, the request reached the CloudFront edge but no SSH stream was established. | For that exact profile, verify the catalog payload method/path, HTTP `Host`, viewer port, SNI, and the provider's CloudFront behavior/origin policy. Do not infer that the origin accepted the request, swap in another profile's values, or treat 403 as SSH success. |
| SSH no acceptable ciphers | The endpoint sent SSH negotiation data, but its offered encryption ciphers do not overlap with the client's enabled cipher policy. This occurs before host-key verification and authentication. The updated probe reports both directional peer cipher lists and the client-enabled list. | Send the complete redacted cipher diagnostic for review. Prefer a provider endpoint with modern mutually supported ciphers. Do not enable CBC/3DES or other legacy algorithms globally or silently. Any compatibility exception must be explicit, narrowly scoped to the selected profile, and security-reviewed. |
| SSH host-key pin / known_hosts missing | The SSH identity is not yet trusted locally. | Compare the observed SHA-256 fingerprint with a provider-published fingerprint from an independent trusted channel, then pin it explicitly. |
| SSH authentication failed | SSH key exchange progressed far enough to reach authentication, but credentials or auth policy failed. | Verify the account and authentication method for this profile; do not expose credentials in reports. |
| UDPGW preflight failed | SSH may be available, but the configured UDP gateway could not be reached through the SSH path. | Verify this profile's published UDPGW host and port. TCP-only success is not full-tunnel success. |
| TUN/DNS/IPv4/IPv6 egress readiness failed | The application did not prove a complete routed tunnel. | Keep the state disconnected/error, inspect the failing readiness check and confirm rollback restored routes and DNS. |

A probe that retrieves an SSH host-key fingerprint does not authenticate that fingerprint. Never enable SSH trust-on-first-use, silently disable TLS verification, follow HTTP redirects for SSH payloads, or substitute catalog endpoints as a recovery strategy. TLS compatibility is allowed only as an explicit per-profile user choice for a known certificate-trust problem; it weakens protection against MITM and does not relax SSH host-key verification.

## Parallel live-test record

Run the following independently for each profile the user chooses to test; failures from separate profiles must remain separately attributable:

- [ ] TLS endpoint, SNI and certificate chain
- [ ] HTTP payload response (if applicable)
- [ ] SSH key exchange and independently verified host-key fingerprint
- [ ] SSH authentication
- [ ] UDPGW preflight and a real non-DNS UDP round-trip
- [ ] TUN startup and leak protection
- [ ] IPv4, IPv6 and DNS egress
- [ ] Disconnect and route/DNS restoration
