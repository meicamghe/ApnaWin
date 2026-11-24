# Windows x64 UDPQ test build

This workflow creates a **test-only portable ZIP** from the current PR branch. It does not publish a GitHub Release. The uploaded Actions artifact expires after seven days.

## Build contents

- ApnaWin desktop executable and UAC elevated helper;
- pinned Xray-core v26.11.9 and Wintun 0.14.1 runtimes, with their official archive hashes checked;
- the Windows x64 UDPQ sidecar built from the MIT-licensed StarUDP source commit 23fa29bb4fad600330b30e2b703b8029ef091446;
- a runtime manifest containing the UDPQ executable SHA-256;
- the installer script and third-party license notices.

The desktop registers the UDPQ engine only when the sidecar and its manifest hash are present and valid. The UDPQ profile's authentication data is stored using current-user DPAPI. A temporary JSON config is created only for sidecar startup and removed after the SOCKS5 listener is protocol-probed.

## Install on a Windows test machine

1. Download ApnaWin-Windows-x64-UDPQ-Test.zip from the **Artifacts** section of the successful ApnaWin Windows x64 UDPQ test build GitHub Actions run.
2. Extract the ZIP to a normal local folder.
3. Open PowerShell as Administrator in that folder and run:

   powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ApnaWin.ps1

4. Launch ApnaWin.exe from %ProgramFiles%\ApnaWin.

The installer copies the complete verified folder to Program Files and applies the product ACLs. Do not run the elevated helper directly from Downloads or another user-writable folder. ApnaWin is not yet Authenticode-signed, so Windows may display an unknown-publisher UAC prompt.

## Import a test profile

Use Import… → UDPQ / StarUDP profile (experimental)…. Enter values supplied by a StarUDP-compatible server operator:

- server hostname and port;
- exact authentication string;
- server ALPN and TLS SNI;
- upload/download rate limits;
- packet mode (udp, wechat, or wechat-video);
- optional XPlus obfuscation password;
- optional trusted CA file if the server uses a private CA.

TLS certificate verification is always enabled. Do not use a random server, guessed password, or a third-party endpoint without authorization. faketcp is intentionally unavailable in this Windows build because the pinned upstream source compiles a non-Linux stub for that mode. Multi-port/range hopping is not exposed yet.

After importing, select the profile and press Connect. The app starts the UDPQ sidecar, verifies its loopback SOCKS5 listener, then starts the existing Xray/Wintun full-tunnel path. Disconnect stops Xray/Wintun before the sidecar. If the sidecar exits, the profile enters ERROR and must be disconnected/recovered; it must not be reported as connected.

## What this build does not prove

This is a generic StarUDP-compatible test path. The public binary fingerprints identify a strong StarUDP/Hysteria-v1 lineage for APNA's libudpqtwo.so, but APNA's protected runtime values (ALPN override, auth bytes, SNI, rates, packet mode, obfuscation and hopping) are not fully recovered. The manual importer is **not** an APNA catalog protocol mapping and does not claim APNA provider connectivity.

CI validates the pinned Windows sidecar build, its CLI, the loopback QUIC TCP/UDP reference relay, the Python test suite and the packaged desktop smoke test. It does not test a live APNA endpoint or a real Windows VPN session on the user's machine. Verify with an authorized compatible server and inspect the diagnostics before relying on it.
