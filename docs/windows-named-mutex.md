# Windows named mutex

`windows_named_mutex.py` provides a Windows-only named mutex wrapper while
remaining importable on non-Windows development hosts. The native backend uses
`ConvertStringSecurityDescriptorToSecurityDescriptorW`, `CreateMutexW`,
`WaitForSingleObject`, `ReleaseMutex`, and `CloseHandle`.

## Safety contract

- A non-empty SDDL is mandatory; a null/default security descriptor is never used.
- Production SDDL must grant only SYSTEM and the installed service SID. The
  desktop client and IPC request must never choose the mutex name or its ACL.
- Use a service-owned `Global\\` name when cross-session coordination is
  required. Provision/create the object from the service before accepting clients.
- Waits are finite and bounded. Timeout and wait errors fail closed.
- `WAIT_ABANDONED` means the caller owns the mutex but the previous owner died.
  The caller must run journal recovery while holding ownership; no work is
  admitted if the callback is missing or recovery fails.
- Release occurs in a finally path on the acquiring thread, then the handle closes.

## Current integration boundary

`WindowsNetworkTransaction` can now accept this mutex and acquires it around
`execute()`, `recover()` and `rollback()`, holding ownership across journal
reads, adapter mutation, verification and persistence. When acquisition reports
`WAIT_ABANDONED`, the transaction recovery callback runs while the mutex is
owned and before the requested operation proceeds. The mutex remains optional
for platform-neutral tests; production helper construction must supply a
service-owned instance and finite timeout.

The helper/service still must establish and verify the service-owned DACL;
`CreateMutexW` does not replace the ACL on an already existing named object.
The native Windows CI tests validate cross-process exclusion and abandoned
owner behavior, but not service SID provisioning or the complete service
lifecycle.

The unit tests use an injected backend to validate ownership, timeout,
abandoned-owner recovery ordering, failure cleanup and input validation. They
do not substitute for native Windows multi-process tests.


## Native Windows CI coverage

Windows CI additionally runs two-process tests using a unique local mutex:
one process holds ownership while the second must time out, and a child process
terminates while owning the mutex so the next process observes abandoned
ownership and runs recovery before entering its critical section. These tests
exercise actual Win32 mutex semantics; they still do not validate the production
service SID/DACL provisioning or service lifecycle.
