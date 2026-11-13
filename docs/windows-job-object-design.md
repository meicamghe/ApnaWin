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

## Remaining verification before calling M2b complete

1. Unit-test Win32 API call ordering, flags, structure sizes, handle ownership,
   and cleanup for failures at every initialization/create/terminate step.
2. Verify the created root process is in the job before it can execute.
3. Use a Windows integration helper that spawns a child and grandchild; verify
   both are terminated by explicit stop and by closing the final job handle.
4. Verify bounded stop behavior, active-process-count confirmation, and
   retained handles when termination/confirmation fails.
5. Exercise launch under an existing Windows job, including hosted-runner
   constraints. If assignment is rejected, fail closed with a useful error.
6. Run the complete Windows tests, PyInstaller build, and packaged-app smoke
   test, then inspect the resulting CI artifacts and logs.

Connect remains disabled. Process containment alone does not implement TUN,
routes, DNS, rollback, privilege management, or a working VPN.

## References

- Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- Microsoft, [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- Raymond Chen, [A more direct and mistake-free way of creating a process in a job object](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812)
