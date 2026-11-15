# Windows network transaction journal

`apnawin.services.windows_network_journal` provides a bounded, versioned journal model and atomic single-file persistence. It is deliberately separate from Windows route/DNS mutation and from privilege elevation.

## Record format and safety properties

- Every record has a canonical transaction UUID, positive revision, explicit lifecycle phase and 1–256 unique resource mutations.
- Each mutation identifies only a route or DNS resource, carries a bounded resource key, before/after JSON object snapshots, and an explicit applied flag.
- Duplicate JSON keys, non-finite numbers, unknown document fields, unsupported schema versions, invalid identities and files over 1 MiB are rejected.
- Snapshot JSON is normalized before storage and limited to 32 KiB per state.
- Writes use a same-directory temporary file, flush and fsync the file, then atomically replace the previous snapshot. POSIX additionally fsyncs the containing directory and creates the temporary file with mode 0600.
- The store is a single-writer primitive. A future helper must serialize writers and enforce monotonic revisions itself.

## Required integration rules

1. Create and durably persist a `PREPARED` record containing exact pre-change snapshots and intended after-states before the first OS mutation.
2. Persist `APPLYING` and each mutation's applied progress before proceeding to the next resource. Never infer success from a requested API call; query live state.
3. Persist `COMMITTED` only after routes, DNS, endpoint bypass and end-to-end traffic checks are independently verified.
4. On disconnect or recovery, reconcile live state against both snapshots and transaction ownership. Restore only resources proven to be owned by this transaction; preserve concurrent or pre-existing changes.
5. Persist `ROLLING_BACK`, then `ROLLED_BACK` only after reverse compensation is verified. Keep `ROLLBACK_FAILED` and the journal when any resource cannot be safely restored.
6. Do not delete a journal merely because the application exits. Startup recovery must be explicit and conservative.

## Important limitations

- This module does not apply or inspect Windows routes/DNS, prevent concurrent writers, implement crash recovery, establish ACLs, or create a privileged service.
- The containing directory must receive a restrictive Windows ACL before any privileged integration. The Python file mode is not a Windows ACL.
- A corrupt, missing, oversized or unsupported journal must cause the future privileged helper to fail closed; it must not guess or blindly clear networking.
- The journal is not proof that a mutation reached the operating system. Recovery must compare with fresh OS snapshots.

Connect remains disabled until the complete Windows tunnel and recovery path passes acceptance tests.
