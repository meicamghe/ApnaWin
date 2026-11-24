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
