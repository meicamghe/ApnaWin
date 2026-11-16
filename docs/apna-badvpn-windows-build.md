# BadVPN native Windows x64 build — APNA transport research

## Reproducible source

- Upstream: https://github.com/ambrop72/badvpn
- Pinned commit: `07268f02706e78e282e19641b5d1d41e8e89bf31`
- License: upstream `COPYING`, 3-clause BSD-style license with attribution/non-endorsement conditions.
- Windows toolchain: MSYS2 MinGW-w64 x86_64, CMake and Ninja.
- Targets: `badvpn-tun2socks.exe` and `badvpn-udpgw.exe`.

The repository includes a dedicated Windows backend (`BConnection_win.c`, `BDatagram_win.c`) and the tun2socks target links `SocksUdpGwClient.c`. The upstream Windows path does compile the BadVPN UDPGW client into tun2socks; it is not excluded by the Windows preprocessor branch. A separate workflow builds the two binaries from a pinned source commit and checks their PE x64 format and CLI startup.

## Critical Windows adapter limitation

This source's TUN abstraction is `BTap`, and its Windows implementation is `tapwin32-funcs.c`. Its command line accepts a named TAP device (`--tundev`); it is **not** a Wintun adapter implementation. Therefore a successful MinGW build is only native binary-build evidence. It does not prove compatibility with ApnaWin's currently packaged Wintun adapter, and the binaries are not yet wired into the production TUN path.

Before adopting this binary, one of these must be completed and tested:

1. Provide and securely install/manage a compatible TAP-Windows adapter, then verify packet I/O and cleanup on clean Windows 10/11; or
2. Adapt the packet interface to Wintun with a maintained Windows backend and test the full data path.

Do not copy these binaries into the release package or report a working APNA tunnel merely because the compile workflow passes.

## Relationship to APNA

The APNA Lite Android DEX exposes a TUN-to-local-SOCKS bridge and separate UDPGW endpoint settings. BadVPN's UDPGW protocol and Windows socket backend are a strong architectural match for the UDP forwarding component. APNA's actual server-side UDPGW address, SSH credentials, profile mapping and authentication remain unconfirmed. The Windows native build cannot establish provider connectivity without a valid authorized profile.
