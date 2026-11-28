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

### Confirmed from source

- `tools/recover_go_pclntab.py` parses ELF64 little-endian AArch64 images and a Go 1.18+ style pclntab function table without executing the binary.
- The current tests use a synthetic ELF fixture. They do not validate recovery against the actual `libudpqtwo.so`.
- The parser checks file-backed PT_LOAD bounds for metadata reads and checks non-decreasing function-table entry offsets.

### Correctness gaps to close before trusting recovered names

1. `name_off` is checked for negativity, but the resulting address is not constrained to the pclntab function-name table interval `[pclntab_va + funcname_off, pclntab_va + cu_off)`. A string elsewhere in a PT_LOAD can therefore be mistaken for a function name.
2. `read_c_string` and `read_va` return from the first matching PT_LOAD. Overlapping load segments can make VA-to-file mapping ambiguous; reject ambiguous mappings rather than selecting the first.
3. The parser does not validate that each `text_start + entry_off` maps into an executable PT_LOAD segment.
4. The terminal PC offset is checked for monotonicity but not against a validated executable code range.
5. The function-record offsets and records should be constrained to the pclntab metadata region, not merely any readable PT_LOAD bytes.

Add adversarial synthetic tests for each case, plus a real-binary validation fixture once the exact native file can be retrieved. Until then, report Go symbol recovery as unverified.

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

## Track D — Native binary evidence and retrieval blocker

The repository inventory previously exposed small native libraries that could be inspected through the GitHub connector. The larger `libudpqtwo.so` and `libsalamander.so` contents were not returned by the connector's UTF-8 file fetch, and the Git blob endpoint rejected binary content. No real disassembly or Go symbol extraction was performed on those files in this pass.

The next practical requirement is a binary-safe retrieval path for the exact APK member bytes, preserving SHA-256 and ABI/path provenance. Do not substitute a prior Windows packaging artifact for an APK extraction artifact.

## Status summary

| Area | Evidence status | Gate before claiming completion |
|---|---|---|
| LIAPP bridge identification | Strong static indicators | Find/load-path evidence for `libliapp.so`; inspect JNI registration/runtime behavior |
| DEX linkage discovery | Partial, bounded heuristic | APK-wide reference index and obfuscation regression tests |
| Go symbol recovery | Synthetic-fixture parser only | Parser hardening plus validation against actual `libudpqtwo.so` |
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
