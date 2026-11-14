# Profile storage

## Schema

The application stores a UTF-8 JSON document named `profiles.json` in the current
user's application-data directory. Schema version 1 contains exactly:

- `format_version`: integer `1` (booleans and numeric strings are not accepted).
- `profiles`: array of records containing exactly `name`, `transport`,
  `endpoint_host`, and `endpoint_port`.

Each record is validated by the domain model. Ports must be integers from 1
through 65535; names and hosts must be non-empty and within their configured
length/character limits. Profile names must be unique case-insensitively.

The complete serialized document is limited to 1 MiB. Reads are capped at
1 MiB plus one byte so an oversized file is rejected before JSON parsing.
Writes serialize and measure the UTF-8 payload before creating a temporary file;
an oversized save leaves the previous destination unchanged. This is a resource
bound, not a profile-count limit independent of record size.

## Write behavior

1. Validate and serialize all profile objects before touching the destination.
2. Reject the serialized UTF-8 document if it exceeds the 1 MiB limit.
3. Create a unique temporary file in the destination directory.
4. Write UTF-8 JSON, flush the Python stream, and call `os.fsync`.
5. Atomically replace the destination with the completed temporary file.
6. Remove the temporary file on every failure path.

Using the same directory keeps the replacement on the same filesystem and
avoids collisions between simultaneous writers using a shared fixed `.tmp`
filename. A failed serialization or replacement must not truncate or partially
overwrite the previous profile file.

## Read behavior

The loader reads at most 1 MiB plus one byte and rejects oversized files before
decoding or parsing. It requires valid UTF-8 and rejects malformed JSON,
duplicate object keys, non-standard JSON constants, unexpected top-level or
record fields, unsupported or incorrectly typed format versions, invalid
profile values, and duplicate names. It does not silently migrate unknown
schema versions.

If the profile file is missing on first launch, the application treats this as
an empty profile collection and allows a new file to be created. If an existing
file cannot be read or validated, the application enters a protected
read-only state: Add, Edit and Remove are disabled, and save attempts are
refused. This prevents a later profile action from silently replacing the
unreadable/corrupt original with an empty or partial collection. The user must
recover or intentionally move the file outside the application before normal
editing can resume.

## Security boundary

This file is metadata storage, not a credential vault. It stores only profile
name, transport, endpoint host and port. Passwords, tokens, UUIDs, private keys,
subscription URLs and other secrets must not be added to this schema. A future
credential feature must use an appropriate Windows-protected secret store and
must not serialize secrets into this JSON document or diagnostic logs.

The endpoint host and port alone do not define an Xray/OpenVPN configuration
and do not prove that a server is compatible. The UI's Connect action remains
disabled until a real engine, secure credential handling where required,
TUN/routes/DNS lifecycle, rollback and authorized end-to-end tests are complete.


## Import and export

The profile list can be exported to a user-selected JSON file and imported from
a previously exported file. Import validates the complete file with the same
size, UTF-8, schema, duplicate-key and profile-model checks used by normal
storage. Imported profiles are appended as one batch; if any imported name
collides case-insensitively with an existing profile, the entire import is
rejected without changing the current file. Empty imports are a no-op.

Exports contain only the four metadata fields in schema version 1. They never
include credentials, tokens, private keys or subscription secrets. Treat an
exported file as configuration metadata, not as a secret backup. The export
destination is chosen by the user; protect the file according to the sensitivity
of its server addresses and profile names.
