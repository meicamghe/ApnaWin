# Remote server and connection configuration discovery

## Status

This is an investigation and architecture contract, not an implementation of an APNA backend client. The Android application's reported ability to refresh server information and connection settings is a working hypothesis from product observation. The original APK archive and a reproducible runtime network trace are not currently present in this repository, so no endpoint, response schema, update cadence, signing method, or protocol is verified.

Do not invent API URLs, scrape guessed endpoints, or ship a hard-coded server list. Do not reuse private credentials, tokens, certificates, or user-specific server data from an APK or device capture.

## What must be established

Separate the following data classes; they may come from different sources and refresh on different schedules:

1. **Catalog metadata** — server display name, region, availability, ordering, maintenance status.
2. **Connection profile** — address, port, transport, protocol, TLS/Reality parameters and other fields needed to build a client configuration.
3. **Engine/runtime metadata** — engine family, supported version, platform-specific binary requirements and feature flags.
4. **Account/authorization data** — subscription state, entitlements, short-lived access tokens or user-specific server assignment.
5. **Update policy** — refresh trigger, polling interval, cache lifetime, fallback behavior and minimum supported client version.

A server list alone is not a usable connection profile. A profile alone does not prove that the selected Windows engine supports its protocol or that the endpoint is authorized for this client.

## Evidence collection plan

### Static APK inspection

For each supplied APK split, record SHA-256, package/version, ABI and signing-certificate fingerprint. Inspect manifest, DEX strings/classes, resources, assets and native library metadata. Search for networking clients, URL construction, remote-config SDKs, JSON/protobuf models, subscription parsers, update workers and certificate pinning. Record findings with file/class/method evidence and distinguish literal strings from runtime-computed values.

### Controlled runtime observation

On an authorized test device and account, capture a clean baseline and then observe:
- cold launch and initial server-list load;
- manual refresh;
- background/foreground transitions;
- expiry or stale-cache behavior;
- server selection and connection initiation;
- app/version update checks.

Record destination hostnames, request method/path, response content type/schema, status codes, cache headers and timing. Redact authorization headers, cookies, query tokens, identifiers, private keys, server credentials and personal data. Do not bypass TLS pinning or access controls. Compare multiple runs to distinguish stable API structure from per-user or ephemeral values.

### Correlation

Correlate network requests with UI changes and local persistence. Establish whether the app downloads a catalog, receives a complete generated configuration, requests a per-server credential, or negotiates connection parameters at connect time. Determine whether protocol settings are bundled, remotely delivered, or derived from account/server metadata.

## Windows client design requirements

Implement a provider-neutral pipeline only after the source contract is verified:

- **RemoteConfigProvider**: fetches a versioned document from a configured, trusted origin.
- **ConfigVerifier**: validates transport security and, if the service supports it, verifies a detached signature or signed envelope against a pinned public verification key.
- **ConfigParser**: strict schema/version validation, duplicate-key rejection, bounded document size, typed fields and rejection of unknown critical fields.
- **ConfigStore**: atomic cache of non-secret catalog/config metadata, with explicit freshness and source version.
- **RefreshCoordinator**: refreshes on launch, user request and bounded policy intervals; prevents concurrent refreshes and applies backoff.
- **ConnectionConfigBuilder**: converts a verified remote profile into an engine-specific temporary configuration without logging or persisting secrets.

### Security and resilience

- HTTPS certificate validation must remain enabled. Never disable TLS verification to make a backend request succeed.
- A valid TLS connection authenticates the server, but does not by itself prove that downloaded configuration is authorized or untampered end-to-end; use signed configuration when the service provides a verifiable signature mechanism.
- Never execute downloaded scripts, binaries or arbitrary commands as configuration.
- Enforce size, nesting-depth, field-length, endpoint and timeout limits.
- Reject downgrade/replay where versioning or signed timestamps permit detection.
- Use atomic writes; preserve the last known-good config when refresh fails.
- Define cache expiry and offline behavior explicitly. Do not silently treat stale server availability as current.
- Keep user credentials and short-lived tokens in an OS-protected credential store, not the profile JSON or logs.
- Do not commit real server addresses, customer configurations, tokens or captured private responses.
- Remote config must not be able to enable an unimplemented transport or bypass local engine capability checks.

## Acceptance criteria before integration

1. Reproducible static and runtime evidence identifies the actual update mechanism.
2. Endpoint ownership, authorization, privacy implications and terms of use are understood.
3. A redacted sample response and documented schema/version are available.
4. Refresh, cache, expiry, offline and malformed-response behavior have automated tests.
5. Signature verification is implemented if the service provides signed documents; otherwise the residual trust model is documented.
6. Engine compatibility is independently verified for every advertised connection type.
7. Secrets are protected and never included in source control, diagnostics or crash reports.

## Current decision

Keep this work in discovery/design. Do not build a speculative backend client or enable Connect until the APK evidence and an authorized test account/configuration establish the real contract.

## Internal normalized catalog contract (implemented foundation)

`src/apnawin/domain/remote_catalog.py` defines a deliberately small,
provider-neutral **internal** catalog representation. It is not an APNA API
schema and must not be sent to or expected from any upstream service without
an explicit adapter based on verified evidence.

The normalized document contains a format version, opaque revision, timezone-
aware generation/expiry timestamps, and a bounded list of display-only server
entries (identifier, name, region and availability). It excludes endpoints,
credentials, keys, transport parameters, executable metadata and arbitrary
feature flags. Therefore a catalog entry is display/selection metadata only;
it cannot be passed to an engine or treated as a connection profile.

The parser rejects duplicate JSON keys at every depth, non-standard JSON
constants, unknown fields, invalid UTF-8, oversized documents, excess entries,
duplicate identifiers, control characters, non-boolean availability and
timestamps without timezones. The immutable parsed catalog exposes an explicit
freshness check. Stale catalogs may be retained for offline display, but callers
must check freshness before presenting availability as current.

This foundation intentionally has no HTTP client, endpoint, scheduler,
authentication, signature format or cache writer. Those belong in a future
provider adapter after the real Android/backend contract and authorization
model are evidenced. The normalized internal schema can then remain stable
while adapters translate verified upstream formats into it.
