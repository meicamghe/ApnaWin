# APNA payload transport diagnostics

This document records the transport stages used by the APNA profile mapper and
the Windows client's host-key probe. It is an implementation map, not proof
that a particular provider payload is accepted or that a tunnel carries traffic.

## Stage boundaries

1. **Name resolution and TCP** — the connector opens
   `connect_host:connect_port`. A `socket.gaierror` occurs before a TCP
   connection exists. For HTTP proxy profiles, this is the selected payload
   proxy/front endpoint; `target_host` is normally carried in the HTTP
   request and is not resolved locally by the client at this stage.
2. **TLS (when selected)** — `TLS_DIRECT` and `TLS_HTTP_PROXY` wrap the
   connected socket with certificate verification enabled by default.
   `server_hostname` is the configured SNI, or the mode-specific default.
   A provider CA can be added without disabling verification. The explicit
   insecure compatibility option remains opt-in and must not be enabled as
   an automatic recovery.
3. **HTTP payload (proxy modes only)** — the rendered payload is written to
   the established socket. The response parser accepts only the configured
   status set. HTTP 200 is the normal CONNECT success. HTTP 101 is accepted
   only for a structurally valid WebSocket request and its
   `Sec-WebSocket-Accept` value is verified before WebSocket framing is used.
   Redirects are not followed.
4. **SSH protocol negotiation** — only after the connector returns a usable
   byte stream does Paramiko start SSH banner/key exchange and later host-key
   verification/authentication.

## Mode mapping

| Mode | TCP destination | TLS | HTTP payload | SSH begins |
|---|---|---|---|---|
| `DIRECT` | selected SSH endpoint | no | no | on raw TCP stream |
| `HTTP_PROXY` | selected payload host/port | no | yes | after accepted proxy response |
| `TLS_DIRECT` | selected TLS endpoint | yes | no | inside verified TLS stream |
| `TLS_HTTP_PROXY` | selected payload host/port | yes | yes | after TLS and accepted proxy response |

The mapper currently treats catalog method `direct` as DIRECT, `ssl` as
TLS_DIRECT, and `http` as HTTP_PROXY or TLS_HTTP_PROXY according to the
catalog's `sslws` flag. The selected payload host/port and SNI are retained
in the mapped configuration; explicit catalog SNI data takes precedence over
the mode default.

## Failure classification

- `socket.gaierror`: DNS resolution failed before TCP. No HTTP request, TLS
  handshake, SSH banner or SSH key exchange has happened.
- `ConnectionRefusedError`, timeout, or other socket errors: TCP/network
  stage failure. They are not SSH key-exchange failures.
- `ssl.SSLCertVerificationError`: certificate-chain or hostname validation
  failure during TLS. Do not relabel it as SSH and do not silently disable
  certificate verification.
- Other `ssl.SSLError`: TLS handshake failure, before HTTP/SSH.
- HTTP 3xx: proxy redirect. It is reported but not followed because changing
  the request target can change provider routing.
- HTTP 401/407: proxy authentication challenge/rejection.
- HTTP 403: the HTTP endpoint understood enough of the request to deny it.
  If safe response metadata identifies CloudFront or Cloudflare, the
  diagnostic names that edge. A CloudFront 403 proves that the request reached
  the edge; it does **not** prove that the configured origin route, payload,
  Host header, SNI, or SSH stream is valid.
- Paramiko banner/key-exchange/cipher/host-key/authentication errors: SSH
  stage failures, after a byte stream was returned by the payload connector.

The host-key probe now raises `ApnaPayloadTransportProbeError` for
`PayloadTransportError` failures and retains `ApnaHostKeyProbeError` for
SSH negotiation failures. The typed `stage` field is `payload_transport`
or `ssh_key_exchange`. Redacted payload diagnostics are preserved up to a
bounded length so CloudFront response metadata and request routing context are
not cut off at the former short SSH exception limit.

## Current user-provided observations (2026-11-28)

- Three `tumsongcloud.xyz:1194` endpoints advertised the unrecognized cipher
  name `strawberry`. These reached SSH negotiation and are a separate SSH
  compatibility issue.
- TLS Direct to `sm81.tumsongcloud.xyz:443`, SNI
  `mda.digicelgroup.com`, failed local DNS resolution. A later
  `tls_direct` sample on another host reached TLS but failed certificate
  verification; this is a TLS trust/SNI issue, not DNS or SSH.
- HTTP Proxy attempts using `referrals.hrblock.com:80`,
  `estacio.br:80`, and `redmas.com.co:80` failed DNS before TCP.
  These observations do not establish a CloudFront edge response.
- Other CloudFront payload attempts returned HTTP 403. Those requests reached
  CloudFront, but no SSH stream was established. The safe request summary
  records method, redacted path, Host, endpoint, target and SNI where
  applicable; safe response metadata is limited to selected headers.

## Evidence limits and next acceptance checks

- The current mapper and transport are implemented, but a static mapper test
  cannot establish that the selected payload/Host/SNI combination matches a
  live provider's edge behavior.
- The latest error reports do not contain a full authorized catalog record
  and raw request bytes; do not invent or substitute payload paths, Host,
  SNI, credentials, or endpoint values.
- Validate with a provider-authorized profile and the exact imported catalog
  payload. Record the selected method, connect endpoint, target endpoint,
  SNI, HTTP status and allowlisted response headers without logging secrets.
- After HTTP/TLS transport succeeds, separately verify SSH banner, host-key
  fingerprint from an independent provider source, authentication, routed
  TCP/UDP/DNS, disconnect and crash recovery. A successful HTTP 200/101 alone
  is not a working VPN tunnel.
