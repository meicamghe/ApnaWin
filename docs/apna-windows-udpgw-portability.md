# BadVPN UDPGW wire and Windows portability findings

Date: 2026-11-16

## Primary source examined

Repository: [shirokhorshid/shirokhorshid-android](https://github.com/shirokhorshid/shirokhorshid-android)  
Inspected source revision: `2c719306c2340938cbafcb3dc59c8e03173bcf8c`

Relevant files:
- `app/src/main/jni/badvpn/protocol/udpgw_proto.h`
- `app/src/main/jni/badvpn/flow/PacketProtoEncoder.c`
- `app/src/main/jni/badvpn/flow/PacketProtoDecoder.c`
- `app/src/main/jni/badvpn/udpgw_client/UdpGwClient.c`
- `app/src/main/jni/badvpn/tun2socks/SocksUdpGwClient.c`
- `app/src/main/jni/badvpn/tun2socks/CMakeLists.txt`
- `app/src/main/jni/badvpn/udpgw/CMakeLists.txt`
- `app/src/main/jni/badvpn/system/CMakeLists.txt`

## Wire format confirmed from source

1. PacketProto wraps every message with a 16-bit little-endian payload length (`htol16`).
2. UDPGW begins with a packed 3-byte header: flags byte followed by a 16-bit little-endian connection ID.
3. Flags are KEEPALIVE=0x01, REBIND=0x02, DNS=0x04, IPV6=0x08.
4. IPv4 destination is 4 raw network-order address bytes plus a 16-bit network-order port. IPv6 is 16 address bytes plus network-order port.
5. New flow creation sends REBIND on its first packet. DNS packets set DNS so the server can route them to its configured resolver.
6. Keepalive is a three-byte UDPGW body with KEEPALIVE set and zero connection ID.
7. The Android client does not use SOCKS5 UDP ASSOCIATE for this path. `SocksUdpGwClient` creates a SOCKS client connection to the configured remote UDPGW endpoint, then attaches `UdpGwClient` packet framing to that byte stream.

The implementation in `src/apnawin/engines/udpgw_protocol.py` now provides the PacketProto framing, IPv4/IPv6 datagram codec, DNS/REBIND/KEEPALIVE flags and incremental TCP-stream decoder. Unit tests cover endian layout, IPv4, IPv6, keepalive, fragmented/coalesced frames, invalid flow IDs, addresses, ports and frame lengths. This is protocol-codec coverage, not a live UDPGW session.

## Windows source/build assessment

The inspected CMake tree is more promising than the old blanket claim that UDPGW is absent on Windows:

- The root CMake file enables `BUILD_TUN2SOCKS` and `BUILD_UDPGW` by default on non-Emscripten targets.
- `BUILD_TUN2SOCKS` adds `udpgw_client`; the tun2socks executable links both `udpgw_client` and `SocksUdpGwClient.c`.
- On WIN32, `system/CMakeLists.txt` selects `BConnection_win.c` and `BDatagram_win.c` and links `ws2_32` and `mswsock`.
- UDPGW source excludes syslog/resolver headers and its system-resolver auto-discovery block under `BADVPN_USE_WINAPI`. This is a portability accommodation, not proof that a complete Windows build works or that DNS resolver auto-discovery works on Windows.
- The old `BUILD-WINDOWS-VisualStudio.md` instructions found in related BadVPN mirrors explicitly describe only a 32-bit tested build. They cannot be used as x64 build evidence for this revision.

**Current conclusion:** source-level Windows socket support exists for the stream and datagram abstractions used by UDPGW; a modern x64 MSVC/clang-cl build, binary execution, and UDPGW round-trip are still unverified. Do not ship a guessed prebuilt binary or mark Windows UDPGW complete.

## Next validation steps

1. Pin the exact BadVPN source revision and record its full license/notices before vendoring or building.
2. Configure x64 Windows with `BUILD_TUN2SOCKS=ON`, `BUILD_UDPGW=ON`, `BUILD_CLIENT=OFF`, `BUILD_SERVER=OFF`, and an explicit Windows reactor/backend; inspect required CMake options and compile errors.
3. Build a minimal codec/loopback integration harness on Windows before packaging the full tun2socks executable.
4. Verify the actual remote UDPGW endpoint semantics and DNS configuration from APNA's protected configuration/runtime. Do not assume a server port or DNS resolver.
5. Run real IPv4 and IPv6 UDP round-trips through the SSH/SOCKS byte stream, including DNS-flagged traffic, keepalive and reconnect.

## Licensing note

The inspected BadVPN source headers use a 3-clause BSD-style license. Before copying any source or binary into ApnaWin, preserve each source file's copyright/license notices and include the license in the runtime distribution. This note is not a substitute for a complete file-by-file provenance audit.
