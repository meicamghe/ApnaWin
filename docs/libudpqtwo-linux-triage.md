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
