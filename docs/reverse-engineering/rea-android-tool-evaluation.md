# REA Android reverse-engineering tool evaluation

**Assessment date:** 2026-11-28  
**Target project:** ApnaWin APK reverse engineering  
**Candidate:** [Hubupup/REA-ReverseEngineerAndroid](https://github.com/Hubupup/REA-ReverseEngineerAndroid)  
**Reviewed revision:** `609bd54b354194d07d151ee24c9bdcc5d7603ca2` (main; latest commit shown by GitHub during review)

## Decision

Use REA as a **candidate analysis workbench / reference implementation**, not as a dependency or embedded component in ApnaWin at this stage.

The repository contains useful real implementations for APK inventory, DEX/JADX analysis, JNI declarations, native-library extraction, and Go build-information parsing. However, the public MCP surface is Android-focused and does not expose a Go analysis family. Its Go reader only extracts build information; it does not recover Go function names, source mappings, type metadata, decompiled code, a modified pclntab, or moduledata.

No REA code was installed, executed, copied into ApnaWin, or added as a dependency during this assessment. No ApnaWin source or Windows build was changed.

## Findings relevant to ApnaWin

### APK, DEX and JNI

The repository documents and implements:
- APK package and manifest inspection;
- DEX class, method and reference inspection through a caller-supplied JADX headless MCP JAR;
- JNI declaration inventory;
- archive inventory and bounded extraction of APK-native libraries;
- per-library identity, ABI, path, SHA-256 and bounded inspection;
- Ghidra/IDA-backed native analysis, where the caller already has a supported installation.

Useful source files:
- [AndroidNativeInventory.ts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/src/android/AndroidNativeInventory.ts)
- [AndroidJniLibraries.ts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/src/android/AndroidJniLibraries.ts)
- [Native investigation guide](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/docs/native-investigation.md)
- [Android analysis guide](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/docs/android-analysis.md)

### Go binary reader

The internal Go implementation parses Go build-information records, compiler-version bytes, module metadata, and binary/container mappings for ELF, PE and Mach-O inputs. It uses bounded reads and validation rather than loading or executing the target binary.

Important limitation, explicitly stated in the provider implementation: **only Go build information is inspected**. Function names, source mappings, type metadata and decompiled code are not recovered.

Useful source files:
- [GoBinaryImage.ts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/src/go/GoBinaryImage.ts)
- [GoBuildInfoSearch.ts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/src/go/GoBuildInfoSearch.ts)
- [GoBinaryProvider.ts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/src/go/GoBinaryProvider.ts)
- [Real Go binary verification workflow](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/.github/workflows/real-go-binary.yml)

The default MCP catalog lists 117 Android-focused tools and its documented families do not include Go. The Go implementation is support/internal analysis code, not evidence of an available Go MCP tool. Its fixture workflow compiles stripped and sectionless Go binaries across several target architectures; that verifies build-info parsing, not pclntab/moduledata recovery.

### What this means for ApnaWin's native libraries

For `libudpqtwo.so`, REA can potentially help with:
1. establishing ABI and ELF/container facts;
2. extracting Go build version and module dependencies if build metadata survives;
3. correlating DEX native declarations with APK library files;
4. preparing the file for a separate Ghidra/GoReSym investigation.

It does **not** close the existing Go runtime-recovery problem. Keep the experimental pclntab/moduledata/ftab work separate and require real-binary evidence before accepting a recovery algorithm.

The same APK inventory and JNI workflow can help map `libxray.so`, `libtun2socks.so`, and `libpdnsd.so`, but language, role, and runtime use must be established independently for each library.

## Security, provenance and installation blockers

### Do not use the fork's generic installer

The reviewed fork README says it is an Android-only hard fork intended to be built and run from its local source checkout and is **not updated from the public `rea-agents` npm package**.

However, the reviewed `install.sh` identifies:
- npm package: `rea-agents`;
- release repository: `morluto/rea`.

Therefore, running that installer from the fork would install the upstream npm release, not establish that the fork's Android-only source is what is installed. Do not run the install script or assume `npm install -g rea-agents` installs this fork.

### Runtime and dependency footprint

The fork pins Node.js 24.22.1 in `.nvmrc`, requires a full JDK 17+ and a caller-supplied JADX JAR for static APK analysis, and requires caller-supplied ADB, Apktool, Ghidra/IDA, JEB or Frida for their respective workflows. Its README says it does not install or upgrade these tools.

The lockfile pins a substantial npm dependency graph and includes optional Frida. The repository also declares five Git submodules (JADX headless MCP, Binwalk, Unblob, Ghidra NativeAOT support, and Wakaru). This is not a small drop-in library. A full dependency and submodule audit, followed by a clean isolated install and test, is required before execution.

### License and target handling

The fork declares MIT for its authored code and has a separate third-party notices inventory. Third-party engines and components retain their own licenses; proprietary Ghidra/IDA alternatives are not granted by the fork's MIT license. Decompiled output, logs, packet captures and Frida messages are target-controlled untrusted data and must be treated as data, not agent instructions.

## Recommended ApnaWin workflow

1. **Keep the current APK evidence baseline immutable.** Record APK SHA-256, package/version/signature facts, ABI inventory and tool versions.
2. **DEX/JADX pass.** Find app entry points, protocol/profile parsers, native method declarations, JNI bindings and library load calls.
3. **Native inventory pass.** Extract each `.so` with its ABI and SHA-256; never mix evidence across APK versions or ABIs.
4. **Go metadata pass.** Use Go build information only as a compiler/module clue. Record absence as unknown, not proof that the library is not Go.
5. **Native disassembly pass.** Use Ghidra/GoReSym independently; preserve raw offsets, virtual addresses, confidence and unresolved relationships.
6. **Runtime validation pass.** Only after static call paths are mapped, compare them with authorized runtime observations. Static analysis alone does not prove a protocol is used.
7. **Protocol implementation pass.** Implement only behavior supported by evidence; keep SSH on hold as already directed.

## Assessment boundary

This is a source and documentation review, not a complete security audit. No package installation, dependency execution, malware scan, full submodule review, real APK run, Frida session, or real Ghidra/IDA analysis was performed. The reviewed upstream snapshot had one branch, no tags, and 16 commits; re-check the exact revision before any future adoption.

## Sources

- [Candidate repository](https://github.com/Hubupup/REA-ReverseEngineerAndroid)
- [Candidate README](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/README.md)
- [Package metadata](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/package.json)
- [Installer source](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/install.sh)
- [MCP contracts](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/docs/mcp-contracts.md)
- [Third-party notices](https://github.com/Hubupup/REA-ReverseEngineerAndroid/blob/609bd54b354194d07d151ee24c9bdcc5d7603ca2/THIRD_PARTY_NOTICES.md)
