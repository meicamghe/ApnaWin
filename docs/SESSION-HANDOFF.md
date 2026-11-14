

## Remote catalog local-cache milestone

A bounded `RemoteCatalogStore` now persists the internal normalized catalog
document using validate-before-write and atomic replacement. It preserves the
last known-good cache on invalid input or replace failure, rejects oversized
and invalid-UTF-8 cache files, and revalidates on load. Missing cache is
distinct from corrupt cache. Stale valid data may be retained for offline
display but is never silently promoted to fresh; callers must check its
declared expiry. This cache is metadata-only and does not imply cryptographic
authenticity or implement the unknown APNA backend protocol.
