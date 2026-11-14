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

## Write behavior

1. Validate and serialize all profile objects before touching the destination.
2. Create a unique temporary file in the destination directory.
3. Write UTF-8 JSON, flush the Python stream, and call `os.fsync`.
4. Atomically replace the destination with the completed temporary file.
5. Remove the temporary file on every failure path.

Using the same directory keeps the replacement on the same filesystem and
avoids collisions between simultaneous writers using a shared fixed `.tmp`
filename. A failed serialization or replacement must not truncate or partially
overwrite the previous profile file.

## Read behavior

The loader rejects malformed JSON, duplicate object keys, non-standard JSON
constants, unexpected top-level or record fields, unsupported or incorrectly
typed format versions, invalid profile values, and duplicate names. It does
not silently migrate unknown schema versions.

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
