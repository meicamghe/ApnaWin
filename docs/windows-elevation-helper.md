# Windows UAC Xray helper

## Intended privilege boundary

The desktop remains a normal-integrity process. A dedicated ApnaWinElevator.exe is built with a requireAdministrator manifest and is launched only when a TUN session is requested. The helper accepts a profile name and the encrypted config-store path; it does not accept an executable path or arbitrary command line from the desktop.

The helper:
1. Verifies that it is running from %ProgramFiles%\ApnaWin\ApnaWinElevator.exe.
2. Verifies the encrypted config store is under the current user's AppData\ApnaWin folder.
3. Opens the current-user DPAPI store and decrypts only the selected profile's Xray JSON.
4. Writes a uniquely named temporary config under %LOCALAPPDATA%\ApnaWin\runtime, then validates and starts the fixed engine\xray.exe.
5. Holds the Xray process in the existing Windows Job Object supervisor.
6. Waits on both the desktop parent-process handle and a stop event. A normal disconnect signals the stop event; a desktop crash is detected through the parent handle.
7. Deletes the temporary plaintext config when the helper exits. Startup cleanup removes stale helper config files older than 24 hours.

If the helper itself crashes, the Xray Job Object's kill-on-close policy terminates the child process. The parent uses a named ready event for startup handoff and a separate stop event so a medium-integrity desktop does not need to terminate a high-integrity process directly.

## Installation trust boundary

The helper is accepted only at the fixed Program Files path. Install-ApnaWin.ps1 copies the portable folder to %ProgramFiles%\ApnaWin and sets explicit ACLs: SYSTEM and Administrators full control, standard Users read/execute. Do not run the elevated helper from Downloads, Desktop, a user-writable folder, or a network share.

The UAC helper is not Authenticode-signed by ApnaWin. Windows may display an unknown-publisher UAC prompt. The helper binary is protected against replacement after installation by the Program Files ACL, but code signing is still a release requirement.

## Important limitations — Connect remains disabled

The helper currently calls the existing XrayProcessRunner.stop(), which force-terminates the Xray process through the Job Object. That does not prove Xray's graceful TUN close path runs, nor that Windows routes, DNS settings and adapter state are fully restored. Before enabling Connect, implement and verify a graceful stop path (for example, a dedicated console process group and CTRL_BREAK handling, with forced Job Object termination only as fallback), then test route/DNS rollback, WFP leak protection, parent crash, helper crash, Xray crash and reconnect on clean Windows 10/11 systems.

The parent-side ElevatedXrayProcess and helper entry point are implemented, but the main window's Connect/Disconnect state machine is not yet wired to this supervisor. No end-to-end VPN connection is claimed.

DPAPI uses the current Windows user scope. The helper expects UAC consent for that same administrator account. Over-the-shoulder elevation using credentials for a different administrator account cannot decrypt the original user's DPAPI config and will fail closed.
