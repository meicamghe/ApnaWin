# Windows Xray process containment: Job Object implementation

## Decision and implementation status

The Windows Xray runner launches through a Windows Job Object configured
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The implementation lives in
`src/apnawin/engines/windows_job.py` and is imported safely on non-Windows
systems. Windows launch uses `CreateProcessW` with
`PROC_THREAD_ATTRIBUTE_JOB_LIST`, so assignment happens before the initial
thread executes. There is no uncontained `Popen` fallback on Windows.

The implementation and its current Windows CI verification are complete for
the M2b process-containment scope. This does not make Xray a complete VPN
engine and does not satisfy the later TUN, route, DNS, privilege, rollback,
or authorized-server acceptance requirements.

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
5. Retain process and job handles in `WindowsJobProcess`. If closing the
   initial thread handle fails, retain it so a later `close()` can retry.
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

## Verification completed

The Windows-only integration suite in
`tests/test_windows_job_integration.py` launches real Python helper
processes under the Job Object. It verifies that:

- The root process is already a member of the Job Object at its first Python
  user-code entry, before it spawns descendants.
- A root process can exit while its child and grandchild remain contained.
- `poll()` continues to report the process tree as active while descendants
  remain, and stop escalation drains the active-process count to zero.
- Closing the final job handle activates `KILL_ON_JOB_CLOSE` and terminates
  the descendant tree.

Failure-injection tests cover launch initialization failures, root termination
failure, active-process query failure, process/thread/job handle-close
ownership, and retry after a failed handle close. Failed operations surface as
errors without silently dropping the controller's retained handle references.

**Latest verified CI:** Windows workflow run
[#91](https://github.com/meicamghe/ApnaWin/actions/runs/43511327269)
completed successfully on `main` at commit
`c648f2bcbcbf427a3a60b1cdc90caac5a8a2096e`. Both the full Windows test job
and the Windows build job succeeded. The build job completed PyInstaller
packaging, ran `ApnaWin.exe --smoke-test`, and uploaded the
`ApnaWin-Windows-x64` portable-folder artifact (about 50.6 MB). This verifies
the packaged GUI startup path, not VPN connectivity or system-wide routing.

## Remaining boundaries

- Exercise the launcher on clean Windows 10/11 machines and under supported
  endpoint-security/host Job Object policies; incompatible outer-job
  constraints must remain fail-closed.
- Add further failure injection if new Win32 cleanup paths are introduced.
- M3 still requires an authorized test-server configuration and a separately
  verified end-to-end engine path.
- TUN, routes, DNS, elevation/service integration, rollback, and disconnect
  cleanup remain out of scope for this process-containment milestone.

Connect remains disabled. Process containment alone does not implement a VPN.

## References

- Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- Microsoft, [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- Raymond Chen, [A more direct and mistake-free way of creating a process in a job object](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812)
