# Parallel reverse-engineering audit — 2026-11-28

## Scope and safety

This report records a source-level audit of the existing `re/apk-native-extract` branch. It does not claim that the APK's native binaries were executed or disassembled. No Windows build, CI workflow, SSH implementation, PR merge, or runtime network test was started for this audit.

The implementation under review is on `re/apk-native-extract`; this research branch is based on `main` and deliberately does not import that branch's broad, divergent changes.

## Track A — DEX/JNI and LIAPP discovery

### Confirmed from source

- `apk_dex.py` inspects a bounded set of candidate classes, prioritizing manifest services and class names matching LIAPP-related patterns.
- The selected scan list is truncated at `_MAX_LINKAGE_CLASSES` (64 in the reviewed source).
- The DEX code parser tracks a limited set of smali register flows for `System.loadLibrary`, `System.load`, process launch, and secondary DEX loaders.
- This is static evidence only. It does not prove that a callsite executes, and it does not establish the contents or origin of a library loaded at runtime.

### Risk / next work

A class-name-driven candidate set can miss obfuscated classes that load a protector library. The next improvement should add an APK-wide, bounded reference/callsite index for exact method references to `System.loadLibrary`, `System.load`, `Runtime.exec`, `ProcessBuilder`, `DexClassLoader`, and `PathClassLoader`. Preserve class/method provenance and register-flow confidence, but do not emit arbitrary method bodies or secrets. Add tests for obfuscated class names, aliases/moves, register reuse, reflection, and truncation reporting.

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

## Status summary

| Area | Evidence status | Gate before claiming completion |
|---|---|---|
| LIAPP bridge identification | Strong static indicators | Find/load-path evidence for `libliapp.so`; inspect JNI registration/runtime behavior |
| DEX linkage discovery | Partial, bounded heuristic | APK-wide reference index and obfuscation regression tests |
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
- The source review did not find a safe basis to claim that the proprietary APNA protocol is one of the generic Xray protocols. Keep protocol identification evidence separate from share-link parser capability.


## Parallel implementation follow-up

The following source/documentation changes were added on this research branch after the audit:

- Added and hardened `tools/recover_go_pclntab.py`: unique VA-to-file mappings, bounded function-name strings, overlap rejection, executable-PC checks, metadata bounds, correct `pcln`-relative function-record offsets, and a validated `.text` fallback for PIE images with zero `textStart`.
- Synthetic tests now include the real Go offset convention and zero-`textStart` PIE fallback, in addition to the adversarial bounds/overlap cases. They have **not yet been executed**; no CI workflow was dispatched.
- Uploaded `libxray.so` was statically inspected and 39,856 function records were recovered offline. This validates the recovery approach against Xray, not against the separate `libudpqtwo.so`.
- Replaced the stale Xray milestone text with an accurate source-level description of share-link import and guarded worker lifecycle integration, while retaining the distinction between source integration and live VPN validation.
- Added `docs/reverse-engineering/dex-apk-wide-linkage-index.md` defining the bounded APK-wide DEX callsite index, provenance requirements, resource limits and regression matrix. The index itself is not yet implemented; existing class-candidate scanning remains heuristic.

The branch is six commits ahead of `main` and has no divergence from `main` at the time of this update. No Windows build, CI run, SSH work, PR merge or native-binary execution was performed.


## Uploaded Xray binary follow-up

The dedicated report `docs/reverse-engineering/libxray-binary-analysis-2026-11-28.md` records the binary hash, Android/ARM64 executable classification, Go build metadata, protocol/transport inventory, Android TUN symbols, and the distinction between code presence and runtime activation. The branch remains research-only; no Windows build, CI run, SSH work, PR merge or native-binary execution was performed.
