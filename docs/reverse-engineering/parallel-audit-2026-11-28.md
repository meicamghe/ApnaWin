# Parallel reverse-engineering audit — 2026-11-28

## Scope and safety

This report combines a selective source audit of `re/apk-native-extract` with offline static inspection and AArch64 disassembly of the uploaded `libxray.so`. No native binary was executed or connected to a network. No Windows build, CI workflow, SSH implementation, PR merge, or runtime network test was started for this audit.

The implementation under review is on `re/apk-native-extract`; this research branch is based on `main` and deliberately does not import that branch's broad, divergent changes.

## Track A — DEX/JNI and LIAPP discovery

### Confirmed implementation on this branch

- `apk_dex.py` now scans bounded candidate classes, prioritizing exact manifest services, LIAPP-related classes and network/proxy/service name signals.
- The selected class scan remains capped at `_MAX_LINKAGE_CLASSES=64` per APK. This is not an exhaustive DEX-wide index.
- The parser records bounded evidence for `System.loadLibrary`, `System.load`, `Runtime.exec`, `ProcessBuilder`, `DexClassLoader`, `PathClassLoader` and `InMemoryDexClassLoader`. Direct argument-register tracking is intentionally limited; invoke-range calls and computed/reflection paths remain unresolved.
- `apk_dex_set.py` and `tools/inspect_apk_dex_set.py` were selectively ported to this research branch. They aggregate manifest and linkage evidence across supplied base/split APKs and identify which APK defines a manifest VPN service class.
- Added mocked regression tests for linkage evidence and split-set aggregation. These tests have **not yet been executed**.

### Remaining gap

Class-name-driven selection can miss obfuscated classes that load a protector library. A true APK-wide index still needs a class-name-independent pass over DEX references/callsites with stable DEX/class/method/invoke-offset provenance. Current scanner output is static evidence, not proof of runtime execution or dynamic library origin.

The observed `libbxdtcxfzx.so` evidence (AArch64, `JNI_OnLoad`, `libliapp.so` dependency and process-introspection imports) is consistent with a LIAPP loader/bridge. It is not proof of the exact protection behavior or where `libliapp.so` is stored. `libtoolChecker.so` is separately identified as RootBeer root detection; do not conflate the two.

## Track B — Go pclntab recovery

### Confirmed from source and uploaded binary

- `tools/recover_go_pclntab.py` is an offline ELF64/AArch64 Go 1.18+ pclntab parser; it does not execute the binary.
- The uploaded `libxray.so` contains a Go pclntab with 39,856 functions and 2,574 file entries. Offline recovery using the corrected Go offset rules recovered all 39,856 function names.
- Real-binary validation exposed two parser requirements: functab `funcOff` is relative to the `pcln` table, and PIE images with `textStart=0` need a validated executable `.text` base. Both are now implemented on this branch.
- The parser still has not been validated against the distinct `libudpqtwo.so`; do not transfer Xray findings to that binary.

### Remaining validation

- Synthetic tests now cover relative function-record offsets and zero-`textStart` ELF `.text` resolution, in addition to the existing bounds/overlap checks. The updated pytest suite has not yet been executed.
- After running tests, validate the parser directly against `libxray.so` and then against `libudpqtwo.so` when that exact binary is available.

## Track C — Xray and non-SSH protocol path

### Confirmed from source

- `proxy_share_link.py` parses VLESS, VMess, Trojan, Shadowsocks and Hysteria2 links into Xray outbound objects.
- The parser rejects unknown query keys and unsupported transports rather than silently guessing.
- The reviewed application source contains import and Connect/Cancel/Disconnect paths for Xray profiles, gated on the installed helper and an existing config.
- `XrayConnectionWorker` does not emit connected until the traffic probe succeeds; cleanup failure disables reconnect and retains a recovery path.

### Risks / next work

- `docs/xray-share-link-import.md` contains stale statements that UI integration and connection lifecycle are pending. The source tree on the reviewed branch already has those paths. Documentation must distinguish code integration from operational validation.
- The Windows traffic probe checks the selected route and then creates a socket in a separate operation. A route change between those operations is a TOCTOU gap; route inspection alone does not prove the socket was bound to the tunnel interface.
- The probe uses the system resolver and a single `recv(4096)`; DNS may delay cancellation, and a fragmented response can produce a false negative. Improve bounded DNS/connect/read timeouts and parse the HTTP status line incrementally. Most importantly, add a Windows network-trace test that proves no direct-WAN fallback during connect, steady state, route changes, and disconnect.
- Unit/mocked tests are not evidence of a working live tunnel. Do not label the VPN as operational until the Windows end-to-end test passes.

The Xray share-link parser is a generic Xray import path. It is not evidence that the proprietary APNA native protocol uses VLESS, VMess, Trojan, Shadowsocks, or Hysteria2. SSH remains out of scope and on hold.

## Track D — Native binary evidence and retrieval

- `libxray.so` was uploaded directly for offline inspection. Its SHA-256 is `e796e24eece84ab28ab9e20710a8581fbcb1044c6720db5f9c79fecc839f68b5`; the full report is `docs/reverse-engineering/libxray-binary-analysis-2026-11-28.md`.
- `libxray.so` is an Android/ARM64 Go PIE executable despite its `.so` suffix. It contains Xray-core protocol/transport implementations and Android TUN code; no JNI exports were found in its dynamic symbol table.
- The larger `libudpqtwo.so` and `libsalamander.so` contents remain unavailable for direct binary inspection. Do not transfer Xray findings to either file.
- Preserve exact APK member path, ABI and SHA-256 for each binary. Do not substitute a prior Windows packaging artifact for an APK extraction artifact, and do not commit raw native binaries into Git.



## Independent revalidation and test-fixture correction

- Recomputed the mounted `libxray.so` SHA-256 and confirmed it matches the dedicated report: `e796e24eece84ab28ab9e20710a8581fbcb1044c6720db5f9c79fecc839f68b5`. The earlier apparent mismatch was a transcription/reading error; there is no evidence of a second distinct attachment.
- Re-ran an independent offline pclntab extraction against the mounted file: 39,856 function records, 2,574 file entries, 39,823 unique function names; the zero `textStart` fallback resolves to executable `.text` VA `0x3860a0`.
- `go version -m` independently confirms Go 1.26.2, Android/ARM64, Xray module path and `-buildmode=exe`.
- Fixed a bytearray slice-length bug in `tests/test_recover_go_pclntab.py` that otherwise shifted the synthetic ELF fixture by five bytes. The pytest suite remains unexecuted.
- Android's official APK Analyzer CLI reference confirms `dex code --class` requires a class name and `dex references` only reports method-reference counts. The exhaustive, class-independent callsite index therefore needs a DEX instruction parser/disassembler, not just the current apkanalyzer command set.



## Go PIE text-base correction

A comparison of pclntab function PCs with ELF dynamic symbols exposed a parser defect: ELF `.text` begins at `0x3860a0`, but contains the native `_start` stub before Go text. The Go text base is `0x386120`; `main.main`'s pclntab PC offset `0xb325d0` plus that base equals its ELF dynamic symbol VA `0xeb86f0`, and its 416-byte symbol size matches the pclntab range. The parser now uses a unique matching defined ELF function-symbol anchor for zero-`textStart` images and fails closed when no anchor exists. Synthetic tests were updated but remain unexecuted.

## Xray startup/config call chain

Corrected Go text-base resolution plus AArch64 disassembly establishes the direct call chain `main.executeRun` → `main.startXray` → `main.getConfigFilePath` → `main.readConfDir`. This strengthens the native CLI/config-path evidence but still does not identify the Android Java caller or prove VPNService FD handoff. Strings `xray.location.config` and `xray.location.confdir` are present; exact lookup semantics remain open.

## Status summary

| Area | Evidence status | Gate before claiming completion |
|---|---|---|
| LIAPP bridge identification | Strong static indicators | Find/load-path evidence for `libliapp.so`; inspect JNI registration/runtime behavior |
| DEX linkage discovery | Bounded callsite scan + base/split aggregation implemented; not exhaustive | Execute new tests; implement class-name-independent DEX reference index |
| Go symbol recovery | 39,856 names recovered from real `libxray.so`; parser updated | Execute updated tests; validate distinct `libudpqtwo.so` when available |
| Xray link parsing | Source + unit-test coverage on research branch | Upstream schema validation and malformed-input regressions |
| Xray live tunnel | Lifecycle code + mocked tests | Windows end-to-end traffic and no-leak trace |
| Proprietary APNA protocol | Not established | Recover actual native protocol configuration/handshake from APK and runtime evidence |

## Execution constraints retained

- No new Windows build before reverse engineering is complete.
- No new CI dispatch or GitHub Actions run for this audit.
- No PR #8 merge or wholesale branch merge.
- SSH remains paused.
- No claim of runtime success from static inspection alone.


## Additional source review — protocol parser and APK inventory

- The share-link parser's Hysteria2 path explicitly forces TLS verification (`allowInsecure: false`), accepts only the supported Salamander obfuscation form, and rejects unsupported query options. The generic parser's supported transport subset remains RAW/TCP, WebSocket and gRPC; this is intentionally not complete coverage of every Xray transport.
- VMess parsing type-checks textual JSON fields, gates the link version, rejects non-zero legacy alterId, and rejects unsupported network/header/security values. The parser audit did not establish live compatibility with a particular server or Xray binary version.
- The APK inventory implementation hashes the opened APK via SHA-256, validates ZIP entry paths and expansion bounds, detects duplicate ZIP names, and records native ABI/library path and size without extracting or executing members. This is a useful reproducible inventory layer; it does not itself inspect split APKs as a set or discover dynamically unpacked libraries.
- The source review did not find a safe basis to claim that the proprietary APNA protocol is one of the generic Xray protocols. Keep protocol identification evidence separate from share-link parser capability. The uploaded Xray binary itself contains CLI entry points `main.main`, `main.executeRun`, `main.getConfigFilePath`, `main.startXray`, `main.readConfDir` and `main/confloader.LoadConfig`; the DEX-to-process/config handoff is still unproven.


## Parallel implementation follow-up

The following source/documentation changes were added on this research branch after the audit:

- Added and hardened `tools/recover_go_pclntab.py`: unique VA-to-file mappings, bounded function-name strings, overlap rejection, executable-PC checks, metadata bounds, correct `pcln`-relative function-record offsets, and a validated `.text` fallback for PIE images with zero `textStart`.
- Synthetic tests now include the real Go offset convention and zero-`textStart` PIE fallback, in addition to the adversarial bounds/overlap cases. They have **not yet been executed**; no CI workflow was dispatched.
- Uploaded `libxray.so` was statically inspected and 39,856 function records were recovered offline. This validates the recovery approach against Xray, not against the separate `libudpqtwo.so`.
- Replaced the stale Xray milestone text with an accurate source-level description of share-link import and guarded worker lifecycle integration, while retaining the distinction between source integration and live VPN validation.
- Ported bounded DEX process/native-loader linkage scanning, split-set aggregation, a CLI and mocked regression tests from the divergent research branch as selective files only. The 64-class cap remains; the exhaustive class-name-independent DEX reference index is still unimplemented. Updated the design note to distinguish implemented bounded scanning from the remaining exhaustive index.

At the initial audit checkpoint the branch was six commits ahead; subsequent selective implementation and documentation updates have advanced it further. Check the GitHub compare view for the live ahead/behind count. No Windows build, CI run, SSH work, PR merge or native-binary execution was performed.


## Uploaded Xray binary follow-up

The dedicated report `docs/reverse-engineering/libxray-binary-analysis-2026-11-28.md` records the binary hash, Android/ARM64 executable classification, Go build metadata, protocol/transport inventory, Android TUN symbols, and the distinction between code presence and runtime activation. The branch remains research-only; no Windows build, CI run, SSH work, PR merge or native-binary execution was performed.


## Parallel implementation follow-up — DEX split-set and Xray entrypoints

- Added `src/apnawin/services/apk_dex_set.py`, `tools/inspect_apk_dex_set.py` and `tests/test_apk_dex_set.py` to aggregate linkage evidence across all supplied APK splits, preserve per-APK provenance and locate service-class definitions outside base.apk.
- Ported the matching bounded `apk_dex.py` implementation and its tests so the split-set aggregator receives the expected process/native-loader evidence schema.
- Static analysis of `libxray.so` recovered CLI functions `main.main`, `main.executeRun`, `main.getConfigFilePath`, `main.startXray`, `main.readConfDir` and `main/confloader.LoadConfig`. Help strings expose `run [-c config.json] [-confdir dir]`, `-config`, `-confdir`, `-format`, `-test`, and `-dump`. The literal `xray.tun.fd` is recorded only as a TUN-related internal string; it does not prove VPNService FD transfer.
- New DEX tests and updated Go parser tests have not been run. No CI was dispatched.


## Provenance note

The current `APNA-APKs` repository directory does not contain a standalone `libxray.so` file. The uploaded binary's SHA-256 is recorded, but its exact member path inside `base.apk` or a split has not yet been matched. The binary must remain an externally supplied artifact until that provenance check is completed.
