

### Refresh coordinator (implemented, provider-neutral)

src/apnawin/services/remote_refresh.py defines an injectable
RemoteConfigProvider contract and a thread-safe
RemoteCatalogRefreshCoordinator. It serializes concurrent refresh calls
(single-flight), validates and persists provider output through
RemoteCatalogStore, and returns the last known-good cache when a fetch or
validation fails. Error results expose only the exception class, never the
exception message, to reduce accidental leakage of tokens or response data.

Automatic retries use bounded exponential backoff (default 5 seconds, capped
at 5 minutes). A forced refresh bypasses backoff but not single-flight
protection. Successful refresh resets the failure counter. Backoff uses an
injected monotonic clock and does not alter the catalog's server-declared
freshness window. Callers must still check catalog.is_fresh().

This is orchestration only: no HTTP implementation, APNA endpoint, timer,
background thread, authentication or signature verifier is guessed or enabled.
A future provider must implement strict TLS/authorization, bounded request
timeouts and translation from verified upstream responses to the internal
normalized schema. The coordinator must be invoked by application lifecycle
code only after that provider exists.
