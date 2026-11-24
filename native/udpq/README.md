# UDPQ / Hysteria-v1 sidecar research build

This folder tracks a Windows x64 client-side build of the public StarUDP/Hysteria-v1 code family identified by static comparison with APNA's \`libudpqtwo.so\`.

- Pinned source: [starrising321/starudp](https://github.com/starrising321/starudp)
- Pinned commit: \`23fa29bb4fad600330b30e2b703b8029ef091446\`
- Source license: MIT; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Build helper: \`../../tools/build_udpq_sidecar.sh\`

The upstream non-GPL client can expose a loopback SOCKS5 listener with TCP CONNECT and UDP ASSOCIATE. The existing ApnaWin Xray/Wintun TUN path can later route through that listener, avoiding a second TUN implementation.

## Important compatibility boundary

The binary fingerprints and Go wire-structure names are a strong match, but APNA's protected runtime configuration has not yet revealed:
- ALPN value (the public source defaults to \`hysteria\`, but that literal is absent from APNA's target binary);
- server name / TLS trust settings;
- authentication bytes;
- upload/download rate values;
- transport mode (\`udp\`, \`wechat\`, \`wechat-video\`, or \`faketcp\`);
- optional obfuscation password and port-hopping configuration;
- exact command-line arguments and JSON file passed by APNA.

Do not register this engine as APNA-compatible or report a successful connection until these values are mapped and a real authorized-server handshake is observed. TLS verification remains enabled by default; never use an insecure bypass as a workaround.

## Build on Ubuntu

The script cross-compiles the pinned Go client to Windows x64. It does not execute the Windows binary.

\`\`\`bash
chmod +x tools/build_udpq_sidecar.sh
./tools/build_udpq_sidecar.sh
\`\`\`

Optional output directory:

\`\`\`bash
APNAWIN_UDPQ_OUTPUT_DIR="$HOME/apnawin-build/udpq" ./tools/build_udpq_sidecar.sh
\`\`\`

No installer or release artifact is produced.


## Python sidecar lifecycle primitive

\`apnawin.services.udpq_sidecar\` now provides:

- strict JSON config generation with explicit ALPN/SNI/auth/rate settings;
- TLS verification forced on (\`insecure: false\`);
- UDP transport only until the other packet modes are verified;
- loopback-only SOCKS5 binding with UDP enabled;
- Windows Job Object process ownership;
- short-lived per-user config file, deleted after the SOCKS5 listener passes a protocol-level readiness probe.

This primitive is **not yet registered as a full VPN transport**. It does not start Wintun/Xray itself. The next integration layer will compose it with the existing Xray/Wintun TUN engine, after the APNA runtime ALPN and configuration mapping are known.
