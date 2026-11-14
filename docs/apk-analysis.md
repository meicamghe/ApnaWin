# Android APK manifest and DEX inspection

## Metadata-only inventory

Run the repository's inventory first to record the exact APK size and SHA-256:

```powershell
py -3 tools/inspect_apk.py .\path\to\application.apk
```

It never extracts or executes archive members. See [apk-inventory.md](apk-inventory.md)
for ZIP safety limits and the fields that inventory does and does not establish.

## Optional Android SDK manifest decoder

Install Android SDK Command-line Tools / APK Analyzer and make `apkanalyzer`
available on `PATH`. Then run:

```powershell
py -3 tools/inspect_apk_manifest.py .\path\to\application.apk
```

The command invokes `apkanalyzer manifest print APK` without a shell and with
a 30-second timeout. Only selected manifest metadata is emitted. The report
omits version-name text, labels, intent-filter data, resource values, arbitrary
strings, URLs, and raw XML.

## Optional DEX structure inspection

Run:

```powershell
py -3 tools/inspect_apk_dex.py .\path\to\application.apk
```

This uses the Android SDK's documented commands:
- `apkanalyzer dex list APK` to enumerate DEX files.
- `apkanalyzer dex packages --defined-only APK` to count defined classes and
  identify class names matching VPN/network-related indicators.
- `apkanalyzer dex references APK` to record per-DEX method-reference counts.

The output contains only DEX filenames, counts, and a bounded allowlist of
candidate class names. It does not include method names, field names, bytecode,
raw command output, URLs, credentials, or extracted files. Candidate matching
is heuristic: a class name containing "vpn", "tunnel", "xray", "socks", "dns",
"proxy", or related terms is a lead for later review, not proof of behavior.
Obfuscated or dynamically loaded classes may not be detected.

Both decoders invoke local SDK tooling with argument arrays, no shell, and a
30-second timeout. Standard output and standard error are drained concurrently
with a strict per-stream memory ceiling; the child process is terminated as soon
as either stream exceeds its limit. Missing tooling fails clearly; no executable
is downloaded.
Treat APKs and SDK tools as untrusted software and use an isolated analysis
environment for unknown samples. Neither report verifies runtime behavior or
discovers APNA server endpoints.

Official command reference: [Android APK Analyzer](https://developer.android.com/tools/apkanalyzer).

## Combined structural report

To generate one report with the APK hash and correlate manifest-declared VPN
services against class definitions in DEX, run:

```powershell
py -3 tools/inspect_apk_report.py .\path\to\application.apk
```

The report first records the safe ZIP inventory and SHA-256, then obtains
manifest and DEX metadata from Android SDK APK Analyzer. It checks that both
inventory and APK Analyzer agree on the number of DEX files. Relative service
names such as `.TunnelService` are resolved using the manifest package name
and compared with the defined class set. The result distinguishes a declared
VPN service from whether a corresponding class was found in DEX. A positive
match is static evidence only; it does not prove that the service starts,
establishes a tunnel, or carries traffic. A negative match may also occur when
the manifest name is aliased, obfuscated, or loaded through other mechanisms.

## Native library metadata and engine-name leads

The safe ZIP inventory records bounded `.so` basenames, ABI labels and
uncompressed sizes from entries matching `lib/<abi>/lib*.so`. It never reads
or extracts their contents. The combined report includes per-ABI library
counts and filename-only engine candidates.

Candidate matching uses name-token boundaries rather than arbitrary substring
searches. For example, `libssr.so` is a Shadowsocks lead, while an unrelated
basename that merely contains the letters "ssr" inside a longer token is not.
A small numeric suffix such as the "5" in `hev-socks5` is accepted for the
tun2socks marker. These remain heuristic leads: filenames can be misleading,
libraries can be statically linked or obfuscated, and a match does not
establish that code is loaded or used.

Android ABI libraries (such as `arm64-v8a`) are not Windows DLLs and are not
treated as reusable Windows binaries. No Windows binary compatibility is
inferred.


The combined interpretation also reports counts of VPN service classes matched in DEX, resolvable-but-missing classes, and unresolved service names. `vpn_service_class_resolution_complete` is false whenever a service could not be resolved because package context was unavailable; this prevents an incomplete join from being presented as a definitive negative result.


For each exact manifest-service-to-defined-class match, the DEX report also
includes the APK Analyzer numeric metadata for that class: defined-method
count, referenced-method count, and reported byte count. These values are
class-level structural metadata, not method names or bytecode. They are null
when the service class cannot be resolved or is not present among defined
classes. Referenced-only DEX rows are not treated as class definitions.


The combined report also summarizes filename-based engine candidates by
candidate name and ABI. Its interpretation may mark that a manifest-declared
VPN service class and one or more native engine-name candidates are both
present in the same APK. This is only co-presence in the package: it does not
establish a class-to-library dependency, dynamic loading, or runtime use.



## Native method declarations in VPN service classes

For each manifest-declared VPN service whose exact class name resolves and is
present among DEX-defined classes, the combined DEX inspection additionally
runs the documented `apkanalyzer dex code --class CLASS APK` command. The
smali output is processed in memory and discarded; only the count of method
declarations carrying the DEX `native` access flag is retained. Method names,
signatures, bytecode, strings, and raw tool output are not included in the
report. Classes that cannot be resolved or are absent from defined DEX classes
are not disassembled and have a null count with inspection marked incomplete.

A positive count establishes that the service class declares native methods;
it does not establish which library implements them, whether JNI resolution
succeeds, or whether those methods are invoked. A zero count does not rule out
native code elsewhere in the application. This remains static structural
evidence, not proof of native-service linkage or runtime behavior.

The command and smali output format are documented by the
[Android APK Analyzer reference](https://developer.android.com/tools/apkanalyzer).
