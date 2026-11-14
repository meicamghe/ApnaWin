

## Remote refresh coordinator milestone

A provider-neutral `RemoteCatalogRefreshCoordinator` now provides single-flight refresh execution, an injectable provider and monotonic clock, bounded exponential retry backoff, explicit forced refresh, last-known-good cache fallback and failure-message redaction. The strict catalog parser and atomic cache reject malformed, oversized or invalid-UTF-8 data without replacing the previous valid cache. Tests cover concurrency, retry timing, recovery, malformed provider documents and invalid policy values.

The Windows Actions run [#142](https://github.com/meicamghe/ApnaWin/actions/runs/43568039087) passed the full test job and the Windows PyInstaller build plus packaged-application smoke test. The coordinator is intentionally not connected to a network provider or UI timer: the Android APK/runtime evidence needed to establish APNA's real endpoint, response schema, authentication and refresh policy is not yet available. Do not add a speculative endpoint or enable Connect based on catalog availability.
