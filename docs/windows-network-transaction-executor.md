# Windows network transaction executor

`windows_network_transaction.py` is a pure orchestration layer over an injected, narrow resource adapter. It does not call Windows APIs, elevate privileges, or configure routes/DNS itself.

## Execution contract

1. The complete `PREPARED` journal must be durably saved before the adapter is called.
2. Each resource is marked as possibly applied and the next `APPLYING` revision is saved before its external mutation. This intentionally closes the crash window between an OS change and a later progress write.
3. After each adapter call, the executor reads the exact resource and compares its canonical JSON state with the requested after-snapshot.
4. `COMMITTED` is persisted only after every resource has been independently observed in its after-state.
5. Compensation walks resources in reverse order. It restores only when live state still exactly matches the transaction's after-snapshot. An already-restored before-state is a no-op; any third-party state is a conflict and is never overwritten.
6. A partial adapter failure is handled by inspecting live state, so a resource changed immediately before an exception can still be compensated.
7. Rollback errors or persistence errors retain a non-success journal phase. The caller must keep the journal for operator-assisted recovery.

The journal's `applied` flag means **possibly applied / eligible for live-state reconciliation**, not proof that the OS mutation succeeded. A crash may occur after this flag is persisted but before the adapter is called. Recovery therefore always compares the live resource with both snapshots.

## Adapter requirements

A production Windows adapter must:
- accept only the exact `ResourceKind.ROUTE` and `ResourceKind.DNS` plus validated resource keys;
- return a complete, normalized object snapshot, with `{}` representing absence;
- apply only one exact allowlisted resource and never execute arbitrary commands;
- provide read-after-write semantics and report API failures;
- preserve concurrent external changes and avoid broad route-table or DNS resets.

The adapter and store must be serialized by a single transaction owner. Before privileged use, the journal directory needs a restrictive Windows ACL and a service-owned location. The current store is explicitly single-writer and does not defend against a hostile local administrator or reparse-point manipulation.

## Limitations

This layer is not crash recovery by itself. Startup recovery still needs a trusted helper to load the journal, take fresh OS snapshots, reconcile ownership, and run conservative compensation. It does not prove end-to-end connectivity or packet forwarding.

Connect remains disabled until the Windows TUN, privileged helper, route/DNS adapter, leak protection, disconnect and crash-recovery acceptance tests pass.
