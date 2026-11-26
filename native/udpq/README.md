# UDPQ / StarUDP-compatible Windows engine

This is an experimental Windows x64 client path for the Go networking family strongly matched to APNA's libudpqtwo.so.

- Upstream: https://github.com/starrising321/starudp
- Pinned commit: 23fa29bb4fad600330b30e2b703b8029ef091446
- License: MIT, without the upstream gpl build tag.
- Local patch: patches/redact-client-config-logs.patch, which removes client auth bytes/string, XPlus obfs password and local proxy credentials from INFO-level config logging.
- Build helper: ../../tools/build_udpq_sidecar.sh

## Native evidence and remaining APNA mapping

APNA v51 and UDP Thunder 1.5 libudpqtwo.so share Go package, wire-structure and JSON-config fingerprints with the pinned StarUDP source. Both target files are Go PIE executables packaged with a .so suffix, not JNI libraries. The public source exposes the protocol version 3 control stream, QUIC streams for TCP and QUIC DATAGRAM for UDP.

The exact APNA launch/config path remains protected by LIAPP. The readable primary DEX shows the pdnsd and tun2socks child-process launchers but no libudpqtwo.so call site. The ALPN, SNI, auth bytes, rate values, packet mode, obfs, port hopping and exact launch arguments passed by APNA are not yet recovered. The public source's default ALPN is hysteria, but that literal was not found in APNA's target binary. Do not map APNA catalog categories to this engine until those fields are independently confirmed.

## Windows packet modes

The pinned source exposes UDP, WeChat, WeChat-video and FakeTCP. Its Windows build supports:

- UDP, with optional XPlus obfuscation and bounded multi-port/range hopping;
- WeChat and WeChat-video UDP framing, with optional XPlus obfuscation.

FakeTCP is Linux-only in the pinned source and is rejected on Windows. Multi-port/range hopping is allowed only in UDP mode. The importer limits port expansion to 32 entries and rejects overlaps, malformed ports and non-ascending ranges.

## Desktop integration

The desktop composition root registers UdpqTunnelEngine only if all of these are true:

- the Windows x64 sidecar exists in Program Files/ApnaWin/engine;
- runtime-manifest.json contains the exact pinned source commit and reviewed redaction-patch hash;
- the sidecar's SHA-256 matches the runtime manifest.

The Import menu offers a generic StarUDP-compatible profile dialog. Credentials and settings are stored using current-user DPAPI. Each connection selects a free loopback SOCKS5 port, writes a short-lived config file, launches the sidecar in a Windows Job Object, verifies the SOCKS5 protocol handshake, and removes the plaintext config. Orphaned config files older than one hour are cleaned on the next start.

After the sidecar is ready, the engine writes a uniquely named Xray TUN config and starts the existing Xray/Wintun dual-stack path. Disconnect stops Xray/Wintun before the sidecar. Startup failures trigger rollback; uncertain cleanup is surfaced as ERROR rather than reported as disconnected.

This generic manual profile path is **not an APNA catalog protocol mapping** and does not claim APNA provider connectivity.

## Linux build and analysis

Ubuntu is useful for safe, offline analysis of APK/XAPK ZIPs and ELF files, plus cross-compiling the Windows sidecar:

    sudo apt install binutils golang-go
    chmod +x tools/build_udpq_sidecar.sh
    ./tools/build_udpq_sidecar.sh

The script checks out the pinned source, applies the reviewed credential-redaction patch, resets to the pinned commit on repeated runs, and cross-compiles Windows x64. It does not install or launch the client.

For comparing APNA and other libudpqtwo.so ELF samples, see docs/libudpqtwo-linux-triage.md and tools/compare_go_elf.py.

## Windows test package

The workflow .github/workflows/udpq-windows-test-build.yml builds ApnaWin.exe, ApnaWinElevator.exe, the pinned Xray/Wintun runtimes and udpq-client.exe, verifies the manifest provenance and hashes, runs the packaged desktop smoke test, and uploads a test-only ZIP artifact. It does not publish a GitHub Release.

See docs/udpq-windows-test-build.md for installation and manual profile testing.

CI's loopback reference test proves local QUIC/TLS TCP and UDP relay behavior. It does not prove a real APNA server handshake or a working VPN session on the user's Windows machine.
