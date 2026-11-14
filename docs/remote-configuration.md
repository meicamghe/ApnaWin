

### Local last-known-good cache (implemented foundation)

`src/apnawin/storage/remote_catalog_store.py` adds an atomic local cache for
the normalized, non-secret catalog document. A candidate document is fully
parsed and validated before any filesystem mutation; successful writes use a
unique same-directory temporary file, flush/fsync and atomic replacement.
Malformed, oversized or invalid-UTF-8 updates therefore cannot overwrite the
previous cache. Existing cache files are size-bounded and revalidated on load.

A missing cache returns `None`; a corrupt or oversized cache raises a
validation error rather than being silently treated as an empty catalog.
Stale-but-valid catalogs remain loadable for offline display, but the store
does not mark them fresh or extend their expiry. Callers must explicitly check
`RemoteCatalog.is_fresh()` before presenting availability as current.

The cache stores only the normalized catalog metadata already defined above.
It is not a verified upstream response, does not hold credentials, and does
not add a network provider, refresh scheduler, signature scheme or connection
profile. Last-known-good means structurally valid under the internal schema;
cryptographic authenticity still depends on a future evidence-based provider
and verifier.
