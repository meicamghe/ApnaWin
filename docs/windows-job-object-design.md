# Windows Xray process containment: Job Object design

## Decision

The Windows Xray runner should use a Windows Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to own the Xray process tree. This is
the intended production containment mechanism for Windows 10/11. The existing
`taskkill /T /F` path remains a best-effort fallback only until the Job Object
implementation is complete and verified.

Do **not** implement Job Object assignment by starting Xray with ordinary
`subprocess.Popen` and assigning it afterward. That creates a race: Xray can
spawn descendants before assignment, leaving those descendants outside the
job. Do not reach into private `Popen` internals such as `_handle` to try to
paper over this race.

## Creation-time assignment

Use the documented extended process creation API:

1. Create an unnamed Job Object with `CreateJobObjectW`.
2. Configure `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` using
   `SetInformationJobObject`, setting only
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Do not enable either
   `JOB_OBJECT_LIMIT_BREAKAWAY_OK` or
   `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`.
3. Build a `STARTUPINFOEXW` attribute list with
   `InitializeProcThreadAttributeList` and
   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_JOB_LIST)`, containing
   the job handle.
4. Call `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`, explicit
   application path and a correctly quoted mutable command line. Do not use a
   shell. The OS assigns the new process to the job before its initial thread
   is allowed to execute, avoiding the post-spawn assignment race.
5. Close the thread handle after successful creation. Retain the process
   handle and Job Object handle in an owned process-controller abstraction.
6. On every failure path, preserve the original Win32 error, terminate and
   wait for any process that was created, and close every handle/attribute
   allocation exactly once. Never silently fall back to an uncontained
   `Popen` launch on Windows.

`PROC_THREAD_ATTRIBUTE_JOB_LIST` is supported on Windows 10 and later, which
matches this application's Windows 10/11 target. The implementation must
still handle creation failure (including incompatible host/outer-job
constraints) as a clear startup error; it must not weaken containment to make
launch succeed.

## Lifecycle contract

- The controller owns both process and job handles for the full child lifetime.
- Graceful stop may first request termination of the root process, but the
  configured timeout must ultimately escalate to `TerminateJobObject`.
- Confirm root-process exit and query the job's active-process count until it
  reaches zero (bounded by the stop timeout policy). Do not report success
  while members remain.
- Closing the final job handle with `KILL_ON_JOB_CLOSE` is the crash-cleanup
  safety net. Explicit stop should still terminate and confirm the job before
  releasing ownership.
- If termination or confirmation fails, retain the controller and its handles
  so the caller can retry; do not claim the process tree stopped.
- Descendants normally inherit job membership. Because breakaway limits are
  not enabled, the job does not intentionally permit breakaway. Test the
  behavior of Xray and any supported child processes on Windows 10/11.

## Python integration boundary

The current runner relies on the `Popen` interface (`poll`, `wait`,
`terminate`, `kill`, `pid`) and its tests use process doubles. A small
internal controller should provide an equivalent, explicitly documented
surface without pretending to be a `subprocess.Popen` instance. Keep
platform-specific ctypes structures and API declarations isolated in a
Windows-only module; importing the GUI and running unit tests on non-Windows
must remain safe.

Do not depend on undocumented CPython `Popen` handles. Do not add a third-party
dependency unless a later review demonstrates that the standard Win32 API
wrapper is not maintainable.

## Required tests before replacing the current fallback

1. Unit-test Win32 API call ordering, flags, structure sizes, handle ownership,
   and cleanup for failures at every initialization/create/terminate step.
2. Verify that the created root process is in the job before it can execute.
3. Use a Windows integration helper that spawns a child and grandchild; verify
   both are terminated by explicit stop and by closing the final job handle.
4. Verify bounded stop behavior, active-process-count confirmation, and
   retained handles when termination/confirmation fails.
5. Exercise launch under an existing Windows job (including CI/hosted-runner
   constraints). If assignment is rejected, fail closed with a useful error.
6. Run the complete Windows tests, PyInstaller build, and packaged-app smoke
   test.

Until all of these pass, retain the existing `taskkill` best-effort behavior
and its documented limitations. Keep the GUI Connect action disabled; process
containment alone does not implement TUN, routes, DNS, rollback, or a working
VPN.

## References

- Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- Microsoft, [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- Raymond Chen, [A more direct and mistake-free way of creating a process in a job object](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812)
