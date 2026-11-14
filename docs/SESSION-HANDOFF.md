

## Remote refresh coordinator milestone

A provider-neutral RemoteCatalogRefreshCoordinator now provides
single-flight refresh execution, injectable provider and monotonic clock,
bounded exponential retry backoff, explicit forced refresh, cache fallback and
failure-message redaction. Tests cover concurrency, retry timing, recovery,
malformed provider documents and invalid policy values. No HTTP client,
speculative endpoint, background scheduler or APNA protocol implementation is
included; the provider contract remains blocked on APK/runtime evidence.
