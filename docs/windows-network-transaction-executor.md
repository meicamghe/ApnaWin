# Windows network transaction executor

`windows_network_transaction.py` is a serialized, fail-closed orchestration layer over an injected narrow resource adapter. It does not call Windows APIs, elevate privileges, or configure routes/DNS itself.

## Execution contract

1. The complete `PREPARED` journal must be durably saved before the adapter is called.
2. Immediately before each mutation, the executor reads the exact live resource and requires it to equal the captured before-snapshot. A stale snapshot aborts rather than overwriting a concurrent change.
3. The resource is marked as possibly applied and the next `APPLYING` revision is saved before its external mutation. This closes the crash window between an OS change and a later progress write.
4. After each adapter call, the executor reads the exact resource and compares its canonical JSON state with the requested after-snapshot.
5. `COMMITTED` is persisted only after every resource has been independently observed in its after-state.
6. Compensation walks resources in reverse order. It restores only when live state still exactly matches the transaction's after-snapshot. An already-restored before-state is a no-op; any third-party state is a conflict and is never overwritten.
7. Rollback errors or persistence errors retain a non-success journal phase. The caller must keep the journal for operator-assisted recovery.

The journal's `applied` flag means **possibly applied / eligible for live-state reconciliation**, not proof that the OS mutation succeeded. A crash may occur after this flag is persisted but before the adapter is called. Recovery therefore always compares the live resource with both snapshots.

## Startup recovery

`recover()` loads the persisted journal and reconciles it against fresh adapter reads:
- `PREPARED`: no mutation was authorized to run; it is safely closed without OS writes.
- `APPLYING`, `ROLLING_BACK`, `ROLLBACK_FAILED`: reverse compensation is retried conservatively.
- `COMMITTED`: treated as an interrupted active connection and restored to its before-snapshots.
- `ROLLED_BACK`: returned idempotently.
- Missing, corrupt, oversized or unsupported journals fail closed; they are never silently replaced.

A third-party state that matches neither before nor after snapshots causes recovery to retain `ROLLBACK_FAILED` and refuse to overwrite it.

## Adapter requirements

A production Windows adapter must:
- accept only exact `ResourceKind.ROUTE` and `ResourceKind.DNS` plus validated resource keys;
- return a complete, normalized object snapshot, with `{}` representing absence;
- apply only one exact allowlisted resource and never execute arbitrary commands;
- provide read-after-write semantics and report API failures;
- preserve concurrent external changes and avoid broad route-table or DNS resets.

The executor lock serializes calls through one instance only. The production helper must additionally enforce a process-wide single transaction owner. Before privileged use, the journal directory needs a restrictive Windows ACL and a service-owned location. The current store does not defend against a hostile local administrator or reparse-point manipulation.

## Limitations

This is a testable orchestration layer, not a production Windows network adapter or a complete crash-recovery service. It does not prove end-to-end connectivity or packet forwarding. Connect remains disabled until the Windows TUN, privileged helper, route/DNS adapter, leak protection, disconnect and crash-recovery acceptance tests pass.
