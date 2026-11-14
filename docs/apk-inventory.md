# Reproducible APK inventory

Use the repository's metadata-only inventory before drawing conclusions from an APK:

```powershell
py -3 tools/inspect_apk.py .\\path\\to\\application.apk
```

The command prints JSON containing the APK byte size and SHA-256, whether the
root Android manifest exists, the number of DEX files, native-library ABI
directory names, signature-file count, and ZIP entry count. It does not print
archive paths, string tables, endpoints, permissions, credentials, or file
contents. It never extracts or executes archive members.

The inventory treats ZIP metadata as untrusted. It rejects duplicate names,
unsafe absolute/traversal/Windows-style paths, symbolic links, encrypted
entries, excessive entry counts, oversized individual or aggregate expanded
content, and suspicious compression ratios. The limits are defensive metadata
checks; no member is decompressed to inspect its contents.

The inventory is intentionally not a manifest decoder. Android manifests are
usually binary XML; a positive `manifest_present` result proves only that the
ZIP member exists. It does not establish package identity, version, requested
permissions, exported components, VPN service declarations, network behavior,
or backend compatibility. Use a trusted Android SDK inspection tool separately
for those questions and preserve its version and exact command in the evidence
record. Treat APKs as untrusted input.

Example output is intentionally limited to stable metadata:

- `format`: report schema identifier
- `file_size_bytes`, `sha256`: identify the exact input artifact
- `manifest_present`, `dex_file_count`: structural indicators only
- `native_abis`: ABI directory names under `lib/`
- `signature_file_count`: count of conventional META-INF signature files;
  this is not cryptographic signature verification
- `zip_entry_count`: archive member count
- `content_extracted` and `executed`: always false

Do not commit APKs, private configs, tokens, or raw network captures to the
repository. Redact secrets before sharing any supplementary analysis.
