# APK analysis notes

## Evidence status

This document is deliberately conservative. Earlier inspection notes reported the following package-level observations, but the original APK archive is not currently attached to this repository as a reproducible analysis artifact. Re-run and record commands and hashes before treating these as verified facts.

Reported preliminary observations:
- Android package: com.apnatunnel.lite
- Reported version code: 51
- Reported minimum Android API: 24
- Reported target Android API: 36
- Reported class/service names included TunnelVpnService, Tun2Socks, OpenVPNClient, XRayDNSService, and SocksDNSService.
- Reported native library names included libxray.so, libtun2socks.so, and libpdnsd.so.

These names suggest possible Xray, OpenVPN, tun2socks and DNS-related components, but names alone do not prove which protocols, configuration formats, server endpoints, or user-visible features are active.

## Required reproducible inspection

When APK splits are available, record:
- SHA-256 for every APK split.
- Package/version metadata from aapt dump badging or apkanalyzer.
- Manifest permissions, exported components and VPN service declarations.
- Native library ABI and ELF dependencies.
- Strings and resources relevant to profile formats and engine invocation.
- Network endpoints only when present in the APK and legally appropriate to document; redact tokens and credentials.
- Runtime behavior observed on a test device, clearly separated from static-analysis hypotheses.

## Windows implications

Android ARM64 .so libraries are not Windows DLLs and cannot be loaded directly by a native Windows application. A Windows port needs Windows-compatible engine binaries or a separately implemented equivalent. Compatibility with any proprietary service/backend remains unverified until a lawful test configuration is available.
