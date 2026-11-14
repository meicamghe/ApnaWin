

## HTTPS catalog transport milestone

A reusable `HttpsCatalogProvider` now fetches an explicitly configured catalog URL using Python's default HTTPS certificate validation. It rejects non-HTTPS URLs, embedded URL credentials, fragments, malformed hosts and redirects; response reads are capped at the normalized catalog size limit, and the request has a finite timeout. HTTP error bodies are not surfaced by the provider. This is a generic transport adapter only: no APNA endpoint, authentication mechanism, or upstream response schema has been inferred.
