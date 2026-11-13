# Windows Xray process containment: Job Object implementation

## Decision and implementation status

The Windows Xray runner now launches through a Windows Job Object configured
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The implementation lives in
`src/apnawin/engines/windows_job.py` and is imported safely on non-Windows
systems. Windows launch uses `CreateProcessW` with
`PROC_THREAD_ATTRIBUTE_JOB_LIST`, so assignment happens before the initial
thread executes. There is no uncontained `Popen` fallback on Windows.

This is an initial implementation, not yet a fully verified production
milestone. Windows CI must validate the Win32 structures and actual lifecycle;
the child/grandchild integration tests and failure-injection coverage remain
required before relying on this as complete containment.

## Creation-time assignment

1. Create an unnamed Job Object with `CreateJobObjectW`.
2. Configure `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` using
   `SetInformationJobObject`, setting only
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Neither breakaway flag is enabled.
3. Build a `STARTUPINFOEXW` attribute list with
   `InitializeProcThreadAttributeList` and
   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_JOB_LIST)`, containing
   the job handle.
4. Call `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`, explicit
   application path and a Windows-quoted mutable command line. No shell is
   used. Job membership is established before the initial thread executes.
5. Close the thread handle and retain the process and job handles in
   `WindowsJobProcess`.
6. On launch failure, terminate/wait for any created process and close owned
   handles. A failed contained launch is reported as an error; it never falls
   back to an uncontained Windows process.

`PROC_THREAD_ATTRIBUTE_JOB_LIST` targets Windows 10 and later. An incompatible
outer-job/host constraint must remain a hard launch failure.

## Lifecycle contract

- The controller owns process and job handles for the process-tree lifetime.
- Stop first terminates the root process, then waits for root exit and the
  Job Object active-process count to reach zero.
- On timeout, stop escalates to `TerminateJobObject` and waits again.
- If termination or confirmation fails, the runner retains the controller and
  handles so the caller can retry.
- After the job is confirmed empty, closing the final job handle releases
  ownership; `KILL_ON_JOB_CLOSE` remains the crash-cleanup safety net.
- Descendants inherit job membership unless the process is explicitly allowed
  to break away; this implementation does not set breakaway limits.

## Python integration boundary

`WindowsJobProcess` provides the runner's required `poll`, `wait`,
`terminate`, `kill`, and `pid` surface without relying on private
`subprocess.Popen` internals. Win32 structures and API declarations are
isolated in the Windows-specific module. Non-Windows systems continue to use
`subprocess.Popen`.

The legacy taskkill path remains only for the pre-existing generic process
fallback/test-double path; production Windows launches use the Job Object
controller.

## Verification completed and remaining work

The Windows-only integration suite in
`tests/test_windows_job_integration.py` now launches real Python helper
processes under the Job Object. It verifies that a root process can exit while
its child and grandchild remain contained, that `poll()` continues to report
the process tree as active, that stop escalation drains the active-process
count to zero, and that closing the final job handle activates
`KILL_ON_JOB_CLOSE`. These integration tests passed in Windows CI run #75.

Additional failure-path and creation-time tests have now been added:

- A termination-failure test verifies that a failed root termination is
  surfaced while both owned handles remain.
- An active-process-query failure test verifies that query errors are surfaced
  without losing handle ownership.
- A job-handle-close failure test verifies that the failed handle is retained
  and a later close can retry successfully.
- The initial thread handle is now retained by the controller if its first
  CloseHandle call fails; close() retries it before releasing the Job Object.
  A focused test covers this ownership and retry path.
- The Windows child/grandchild integration test now calls IsProcessInJob at
  the root process's first Python user-code entry and asserts membership. This
  checks creation-time containment before the root starts spawning descendants.

All of the above tests passed in Windows CI run #89 (116 tests total).
Remaining work before calling M2b complete:

1. Verify all newly added failure-injection and first-entry membership tests
   pass on the hosted Windows runner.
2. Extend failure injection to launch cleanup after partial process creation
   and any remaining Win32 cleanup edge cases; keep failed ownership
   operations fail-closed.
3. Keep exercising launch under the hosted Windows runner; incompatible outer
   job constraints must remain fail-closed.
4. Confirm the latest complete Windows PyInstaller build, packaged-app smoke
   test, and artifact upload; inspect their CI results.

Connect remains disabled. Process containment alone does not implement TUN,
routes, DNS, rollback, privilege management, or a working VPN.

## References

- Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- Microsoft, [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- Raymond Chen, [A more direct and mistake-free way of creating a process in a job object](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812)
