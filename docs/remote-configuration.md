### Refresh coordinator (implemented, provider-neutral)

src/apnawin/services/remote_refresh.py defines an injectable
RemoteConfigProvider contract and a thread-safe
RemoteCatalogRefreshCoordinator. It serializes concurrent refresh calls
(single-flight), validates and persists provider output through
RemoteCatalogStore, and returns the last known-good cache when a fetch or
validation fails. Error results expose only the exception class, never the
exception message, to reduce accidental leakage of tokens or response data.

A fetched catalog is parsed and its server-declared validity window is checked
against an injectable UTC wall clock before the cache is touched. Expired
catalogs and catalogs whose generated_at timestamp is still in the future are
rejected, so they cannot replace the last-known-good cache. This freshness
check applies to new responses; callers reading an existing cache must still
check catalog.is_fresh() before using it.

Automatic retries use bounded exponential backoff (default 5 seconds, capped
at 5 minutes). A forced refresh bypasses backoff but not single-flight
protection. Successful refresh resets the failure counter. Backoff uses an
injected monotonic clock and does not alter the catalog's server-declared
freshness window.

This is orchestration only: no APNA endpoint, authentication, signature
verifier, background scheduler or upstream schema is guessed or enabled. The
HTTPS adapter accepts only an explicitly configured URL and applies normal
platform certificate validation, redirect rejection, finite timeouts and
bounded response reads. A future provider must translate verified upstream
responses into the internal normalized schema. The coordinator is invoked by
application lifecycle code only after that provider exists.
