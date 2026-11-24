# libudpqtwo.so Linux triage

## Current evidence

- APNA package: \`com.apnatunnel.lite\`, versionCode 51.
- The uploaded APNA \`base.apk\` was inspected locally as a ZIP archive. SHA-256:
  \`b1f650b168665b0728b1be0e25a0c722cd77ec873e1a1c7e2711a78aa1012a6d\`.
- That base APK contains no \`lib/<abi>/*.so\` members. The native libraries therefore need to be examined from the ABI split APK, not from \`base.apk\`.
- The public UDP Thunder VPN 1.1 listing identifies package \`com.udpthunder.vpn\`, versionCode 2, architecture \`arm64-v8a\`, and an XAPK download. This is a candidate sample only; presence of \`libudpqtwo.so\` in that XAPK has not yet been verified.
- The developer's UDP Thunder 1.5 inventory lists \`libudpqtwo.so\` under \`armeabi-v7a\`, but does not provide binary-level analysis. Filename similarity is not proof of shared code or protocol identity.

## Linux is useful here

Linux is well suited to offline Android package and ELF analysis. It can inspect ZIP/APK/XAPK contents, compare hashes, ELF architecture, Build IDs, dynamic dependencies, exported symbols, Go build metadata, and strings without installing or executing the app.

The APNA \`base.apk\` alone is insufficient. Obtain these two files first:

1. APNA's \`split_config.arm64_v8a.apk\` (or the split containing \`libudpqtwo.so\`).
2. UDP Thunder VPN 1.1 XAPK from a trusted source.

If Ubuntu VM has no direct internet, download the XAPK on the internet-connected Windows host and copy it into the VM using the existing shared-folder/transfer method.

## Inventory and extract the target library

From the ApnaWin repository root:

\`\`\`bash
python3 tools/apk_native_inventory.py \\
  /path/to/udp-thunder-v1.1.xapk \\
  /path/to/apna-split_config.arm64_v8a.apk \\
  --target-only \\
  --extract /tmp/apnawin-udpqtwo
\`\`\`

The helper:
- reads nested APKs inside XAPK archives without installing them;
- reports ABI, archive path, byte size, SHA-256 and ELF magic;
- extracts only \`libudpqtwo.so\` when \`--extract\` is supplied;
- never executes native code.

If no target is found, retain the JSON output: it tells us whether the XAPK had no matching library or whether the package structure needs another pass.

## Compare the extracted ELF files

\`\`\`bash
find /tmp/apnawin-udpqtwo -type f -name 'libudpqtwo.so' -print0 |
while IFS= read -r -d '' f; do
  echo "===== $f ====="
  sha256sum "$f"
  file "$f"
  readelf -h -n -d -Ws "$f"
  go version -m "$f" 2>&1 || true
  strings -a -n 6 "$f" |
    grep -Ei 'pion|quic|dtls|socks|udp|tls|http|jni|proxy|tunnel' |
    head -200
done
\`\`\`

Interpretation:
- Equal SHA-256 on same-architecture files proves byte-identical library samples.
- Different SHA-256 does not prove different code when ABIs differ; compare Build ID, Go module/build metadata, dependencies, symbols and strings.
- A missing Go build-info record does not prove the library is not Go.
- \`DT_NEEDED\` entries and exported symbols are clues, not a complete call graph or proof of service ownership.

## DEX and runtime follow-up

Use JADX on the APNA base/split APKs to search for \`System.loadLibrary\`, \`udpqtwo\`, \`JNI_OnLoad\` and native method declarations. The protected LIAPP secondary DEX must not be bypassed. If static references are unavailable, use ordinary app logs on a test device and record the service lifecycle and library load errors without defeating app protection.

Do not label this library TUIC, Hysteria, or another protocol until a handshake, configuration schema, or source-level implementation supports that mapping. Do not test against third-party endpoints without authorization.


## Verified UDP Thunder XAPK samples (static inspection)

The APKPure 1.1 and 1.5 XAPK downloads were fetched and their archive members inspected in memory. The downloaded XAPK SHA-256 values matched the SHA-256 values displayed on the corresponding APKPure download pages.

### UDP Thunder 1.1 (versionCode 2, ARM64)

- XAPK SHA-256: \`c20e48a8d535ea04d401a552925cba3895e871d60fe09a08864b40a386f6886f\`
- \`config.arm64_v8a.apk\` SHA-256: \`fdc3564d09107988d4cf127e1e438c58e28538eed41c8c58b7a6a9b71a7a5af6\`
- Six native libraries were present: \`libdatastore_shared_counter.so\`, \`libdns.so\`, \`libpdnsd.so\`, \`libtoolChecker.so\`, \`libtun2socks.so\`, and \`libudpq.so\`.
- \`libudpqtwo.so\` was not present in this version.

### UDP Thunder 1.5 (versionCode 6, ARM32)

- XAPK SHA-256: \`e26a57c6db5d6e34d0280f90bd6b302db9f5c4fc0c98ab06fb1a6a70e9d4e7b8\`
- \`config.armeabi_v7a.apk\` SHA-256: \`ec93fe922062dc05a35d8df541ad6f082c6e3ef2802b386a2d754505717d8d08\`
- Seven native libraries were present, including both \`libudpq.so\` and \`libudpqtwo.so\`.
- \`libudpqtwo.so\` size: 17,206,308 bytes; SHA-256: \`650a3b96995e3b4576157915e66e1ef50725090c0043a9c543b8c89de229d660\`.
- ELF header: ELF32, little-endian, \`ET_DYN\`, \`EM_ARM\` (ARM32).
- Dynamic dependencies observed: \`liblog.so\`, \`libdl.so\`, \`libc.so\`.
- Go build-info marker exists, but its embedded version is \`unknown\` and the module-info string is empty.
- Static strings include \`quic-go HTTP/3\`, QUIC v2 / QUIC packet handling, \`socks5\`, UDP, HTTP proxy-related errors and DNS/network code. These support the presence of a QUIC/HTTP3-capable Go networking stack; they do not identify the app's exact wire protocol or authentication scheme.

### Related \`libudpq.so\` observation

In the same UDP Thunder 1.5 ARM32 split, \`libudpq.so\` is 18,396,884 bytes. Its Go build info reports Go \`1.20.14\`. It embeds source-file paths such as \`/root/udpq/core/transport/client.go\`, \`/root/udpq/core/transport/server.go\`, \`/root/udpq/core/transport/socks5.go\`, \`/root/udpq/core/cs/protocol.go\`, and \`/root/udpq/core/pktconns/udp/obfs.go\`, plus the banner \`UDP-Q Server by Prince | v1.0\`. This is evidence about \`libudpq.so\` specifically; it must not be transferred to \`libudpqtwo.so\` without matching symbols or code.

### What this changes

We now have a real ARM32 \`libudpqtwo.so\` sample with QUIC/HTTP3 evidence, plus a separate \`libudpq.so\` binary that exposes Go source paths for a project rooted at \`/root/udpq\`. The next decisive comparison still requires APNA's ARM64 split containing its own \`libudpqtwo.so\`. Because the architectures differ, compare source/module fingerprints and normalized symbol/string evidence rather than expecting equal hashes.


## Direct APNA vs UDP Thunder \`libudpqtwo.so\` comparison

The exact APNA ARM64 split was fetched from this repository's \`APNA-APKs/split_config.arm64_v8a.apk\` path and compared in memory with the verified UDP Thunder 1.5 ARM32 split.

| Property | APNA v51 | UDP Thunder 1.5 |
|---|---:|---:|
| ABI | ARM64 / AArch64 | ARM32 / ARM |
| \`libudpqtwo.so\` size | 17,924,504 bytes | 17,206,308 bytes |
| \`libudpqtwo.so\` SHA-256 | \`a3dea2c032fe01cf335246a53e0b5d0035acc64cca3e66c67ba64fd46baa47b3\` | \`650a3b96995e3b4576157915e66e1ef50725090c0043a9c543b8c89de229d660\` |
| Go build-info version | \`unknown\` | \`unknown\` |
| Go module-info string | empty | empty |

Both binaries contain the same distinctive dependency/source fingerprints:

- \`github.com/pion/dtls/v2\`
- \`github.com/quic-go/quic-go\` and \`github.com/quic-go/quic-go/http3\`
- \`github.com/txthinking/socks5\`
- \`github.com/elazarl/goproxy\`
- \`github.com/folbricht/routedns\`
- \`github.com/LiamHaworth/go-tproxy\`
- \`github.com/caddyserver/certmagic\`
- \`github.com/spf13/viper\`
- \`github.com/mholt/acmez\`
- \`github.com/txthinking/x\`
- \`github.com/oschwald/maxminddb-golang\`

Both also contain the same \`quic-go HTTP/3\` marker, QUIC version-negotiation strings, QUIC v2 key/header-protection strings, SOCKS5 type/method strings, and \`json:"socks5"\` configuration tag.

A broad Go package/function-string fingerprint pass found 5,175 common tokens out of 5,203 APNA tokens and 5,225 UDP Thunder tokens. This is a heuristic string/symbol fingerprint, not a cryptographic or semantic proof of identical source.

### Assessment

This is strong evidence that the two \`libudpqtwo.so\` files belong to the same or a very closely related Go networking-engine code family, built for different Android ABIs and with different binary sizes. It is much stronger than matching a filename alone.

It does **not** yet establish:
- that the two binaries are byte-identical or from the same exact source revision;
- the actual wire-protocol name used by APNA;
- the exact handshake, authentication fields, server-side compatibility or encryption settings;
- which APNA protected service invokes the library or which configuration object it receives.

The most valuable next step is now a controlled comparison of Go function/type symbol fingerprints and the APNA DEX-to-JNI/service ownership path. Preserve \`libudpq.so\` separately: its \`/root/udpq/...\` source paths belong to that other library, not automatically to \`libudpqtwo.so\`.


## Next Linux pass: Go function names and APNA service ownership

After extracting both target libraries, run:

\`\`\`bash
for f in /path/to/apna/libudpqtwo.so /path/to/thunder/libudpqtwo.so; do
  echo "===== $f ====="
  sha256sum "$f"
  readelf -h -n -d "$f"
  go version -m "$f" 2>&1 || true
  go tool nm "$f" 2>&1 |
    grep -Ei 'pion|dtls|quic|socks5|goproxy|routedns|tproxy|udpq|jni|main\\.' |
    head -400
done
\`\`\`

The `go tool nm` output can expose Go function/type names even when the build-info version and module-info strings have been cleared. Compare the function-name sets after removing architecture-specific runtime helpers.

For the Java/Kotlin side, use JADX only on readable APK DEX content:

\`\`\`bash
jadx -d /tmp/apna-jadx APNA-APKs/base.apk
grep -RInE 'udpqtwo|loadLibrary|System\\.load|native ' /tmp/apna-jadx
\`\`\`

If the protected LIAPP secondary DEX prevents the loader/service mapping from appearing, stop at that boundary. Do not attempt to defeat LIAPP. Ordinary Android diagnostics may still show library-load events:

\`\`\`bash
adb logcat -c
# Launch APNA normally on the test device, then:
adb logcat -v threadtime |
  grep -iE 'udpqtwo|LIAPP|apnatunnel|VpnService|AndroidRuntime'
\`\`\`

The target of this pass is to identify the exported Go entrypoints and determine whether APNA's protected service passes the same config shape as UDP Thunder. A shared dependency fingerprint alone is not enough to wire the engine into ApnaWin.


## Protocol-source match: StarUDP / Hysteria-v1 lineage

A public Go repository, \`starrising321/starudp\`, was found after matching the binary's embedded Go types and config tags. Its README describes itself as an automatic installer for a UDP (Hysteria server), and its \`LICENSE.md\` identifies the source under MIT (with a separate GPL-tag caveat).

Sources:
- [StarUDP repository](https://github.com/starrising321/starudp)
- [Wire protocol definitions](https://github.com/starrising321/starudp/blob/main/core/cs/protocol.go)
- [Client handshake and stream handling](https://github.com/starrising321/starudp/blob/main/core/cs/client.go)
- [Server handshake and stream handling](https://github.com/starrising321/starudp/blob/main/core/cs/server.go)
- [Client config and TLS/QUIC setup](https://github.com/starrising321/starudp/blob/main/app/cmd/client.go)
- [Client/server JSON config schema](https://github.com/starrising321/starudp/blob/main/app/cmd/config.go)

The APNA and UDP Thunder 1.5 \`libudpqtwo.so\` executables both contain the exact Go type names and field/tag fingerprints used by \`starudp/core/cs/protocol.go\`:

- \`clientHello\` with \`Rate\`, \`AuthLen\`, \`Auth\`;
- \`serverHello\` with \`OK\`, \`Rate\`, \`MessageLen\`, \`Message\`;
- \`clientRequest\` with \`UDP\`, \`HostLen\`, \`Host\`, \`Port\`;
- \`serverResponse\` with \`OK\`, \`UDPSessionID\`, \`MessageLen\`, \`Message\`;
- \`udpMessage\` with \`SessionID\`, \`HostLen\`, \`Host\`, \`Port\`, \`MsgID\`, \`FragID\`, \`FragCount\`, \`DataLen\`, \`Data\`;
- the \`struc:"sizeof=Auth"\`, \`struc:"sizeof=Host"\`, \`struc:"sizeof=Message"\` and \`struc:"sizeof=Data"\` tags.

Both target executables also contain the StarUDP/Hysteria-style JSON config tags, including \`server\`, \`protocol\`, \`auth\`, \`alpn\`, \`server_name\`, \`insecure\`, \`socks5\`, \`tun\`, \`up\`, \`down\`, \`obfs\`, \`fast_open\`, \`lazy_start\`, \`recv_window_conn\`, \`relay_tcps\`, \`relay_udps\`, \`tproxy_udp\`, \`redirect_tcp\` and \`disable_mtu_discovery\`.

This is a direct wire-structure and config-schema match, not merely a dependency match. It makes a Hysteria-v1/StarUDP-derived QUIC engine the leading protocol-family identification for APNA's \`libudpqtwo.so\`.

### Reconstructed protocol from the matching public source

The matching source defines \`protocolVersion = 3\`. Its client sequence is:

1. Establish QUIC over UDP with TLS 1.3 and the configured ALPN.
2. Open a control stream and send the one-byte protocol version \`3\`.
3. Pack \`clientHello\` containing upload/download rates and the authentication byte string.
4. Unpack \`serverHello\`; a rejected authentication closes the QUIC connection with application error code 2.
5. For each TCP destination, open a QUIC stream and send \`clientRequest{UDP:false, Host, Port}\`; read \`serverResponse\` before piping bytes.
6. For UDP, open a QUIC stream and send \`clientRequest{UDP:true}\`; read the server-assigned \`UDPSessionID\`. UDP payloads then travel as QUIC DATAGRAM messages carrying \`udpMessage\`, with fragmentation fields \`MsgID\`, \`FragID\`, \`FragCount\` when needed.

The source defaults ALPN to \`hysteria\`, but the literal \`hysteria\` string was not found in either target \`libudpqtwo.so\` binary. APNA may override ALPN from its protected runtime configuration or use a modified default. Do not hardcode it until the APNA launch/config path is established.

### Important executable-format correction

Both target files are **Go PIE executables packaged with a \`.so\` suffix**, not ordinary JNI shared libraries:

- APNA: ELF64/AArch64, \`ET_DYN\`, non-zero entry point \`0x1be520\`, interpreter \`/system/bin/linker64\`.
- UDP Thunder 1.5: ELF32/ARM, \`ET_DYN\`, non-zero entry point \`0x8f8d0\`, interpreter \`/system/bin/linker\`.
- Neither target exports \`JNI_OnLoad\` or \`Java_*\` JNI entrypoints. Their dynamic symbol tables expose Go/cgo runtime symbols and \`main.main\`.

This strongly suggests Android launches the file as a child executable from the app's native-library directory rather than calling it through JNI. The protected LIAPP DEX still prevents us from proving the exact process command line and runtime JSON config.

### Engineering consequence

ApnaWin can build a Windows x64 sidecar from the matching MIT-licensed Go source lineage, then expose a loopback SOCKS5 TCP+UDP listener to the existing Wintun/Xray TUN pipeline. Before calling it APNA-compatible, the remaining checks are the APNA ALPN, exact config values/arguments, auth bytes, transport/obfuscation selection and a real authorized-server handshake. The source's protocol version and structures are now strong implementation evidence, but no live APNA server session has been demonstrated.


### Wire serialization detail

The matching source uses \`github.com/lunixbochs/struc\`. Its documented default byte order is **big-endian** unless a field explicitly overrides it. The observed \`sizeof=...\` tags therefore support the following source-derived message layout (lengths are byte counts):

- Control stream starts with one byte: protocol version \`3\`.
- \`clientHello\`: two unsigned 64-bit rate values, a 16-bit big-endian auth length, then that many auth bytes.
- \`serverHello\`: one-byte success flag, two unsigned 64-bit rate values, a 16-bit message length, then the message.
- \`clientRequest\`: one-byte UDP flag, 16-bit host length, host bytes, 16-bit port.
- \`serverResponse\`: one-byte success flag, 32-bit UDP session ID, 16-bit message length, then the message.
- \`udpMessage\`: 32-bit session ID, 16-bit host length, host bytes, 16-bit port, 16-bit message ID, one-byte fragment ID, one-byte fragment count, 16-bit data length, then payload bytes.

This layout is derived from the matching public source and the embedded struct/type fingerprints. It is not yet confirmed by a packet capture from an APNA session. Implementations must enforce length limits and reject malformed/truncated frames before allocating buffers.


## Reference sidecar validation

The pinned StarUDP client/server was built in CI for Linux and Windows x64. A loopback-only integration test passed using a locally generated certificate trusted by the client (TLS verification remained enabled):

- QUIC handshake over UDP succeeded.
- SOCKS5 TCP CONNECT relayed an HTTP request to a local HTTP server.
- SOCKS5 UDP ASSOCIATE relayed a UDP echo datagram through QUIC DATAGRAM and returned the expected payload.
- The test used only loopback addresses; no external server was contacted.
- The Windows x64 CLI build and `--help` smoke test also passed. No binary artifact was published.

This validates the reference implementation and the proposed SOCKS5-to-Xray/Wintun integration shape. It does not validate APNA's exact ALPN/auth/config values or connectivity to an APNA provider endpoint.
