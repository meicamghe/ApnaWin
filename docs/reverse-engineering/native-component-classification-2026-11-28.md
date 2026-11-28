# APNA v51 native component classification — 2026-11-28

## Scope and evidence boundary

This note consolidates static findings from the committed `APNA-APKs` materials and prior bounded ELF inspection. No Android native binary was executed. The large `libudpqtwo.so`, `libsalamander.so`, and `libputils.so` blobs were not retrievable as binary bytes through the current GitHub text connector, so this update does not claim fresh disassembly or symbol recovery for them.

## Component classification

| Component | Observed evidence | Current classification | Confidence / gap |
|---|---|---|---|
| `libbxdtcxfzx.so` | ELF64 AArch64 ET_DYN; entry point is zero; `DT_NEEDED` lists `liblog.so`, `libdl.so`, `libc.so` and `libm.so`; its 29-entry dynamic symbol table has one defined export (`JNI_OnLoad`) and undefined imports including `dlopen`, `dlsym`, `getuid`, `lstat`, `open`, `read`, `write`, `fopen`, `fread`, `fgets` and allocation/logging APIs | LIAPP-associated native loader/protection bridge | High confidence in association; exact checks, anti-tamper behavior and loader sequence need disassembly/runtime evidence |
| `libtoolChecker.so` | Tiny native library with RootBeer symbols including `RootBeerNative`, `checkForRoot`, and `Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot` | RootBeer root-detection JNI component | High confidence |
| `libpdnsd.so` | Strings identify pdnsd 1.2.9a-par and DNS server/cache concepts; readable DEX previously showed a `Pdnsd.run()` process-launch path | DNS helper | High confidence in helper role; not an encrypted transport engine |
| `libtun2socks.so` | BadVPN 1.999.127 / SOCKS5 / UDP Gateway fingerprints; readable DEX previously showed `Tun2Socks.run()` launching it with a SOCKS socket and transparent-DNS UDPGW arguments | TUN-to-SOCKS packet bridge | High confidence in helper role; not an independent encrypted protocol |
| `libudpqtwo.so` | Go/AArch64 PIE-like executable evidence and StarUDP/Hysteria-v1-family Go type/config fingerprints | Standalone native UDP transport-engine candidate | High confidence in family resemblance; exact launcher, argv, ALPN, credentials and live APNA compatibility remain unproven |
| `libsalamander.so` | Present in committed APK materials; no fresh binary inspection in this pass | Unknown | Do not infer it is the Hysteria2 Salamander obfuscator merely from its name |
| `libputils.so` | Present in committed APK materials; no fresh binary inspection in this pass | Unknown utility/library | No protocol attribution |
| `libdatastore_shared_counter.so` | Small JNI-related datastore library; prior DEX evidence references `System.loadLibrary("datastore_shared_counter")` | Storage/runtime support | Not a transport engine |

## LIAPP loading chain

A fresh bounded ELF-header/dynamic-table pass confirms that `libbxdtcxfzx.so` is a shared JNI bridge rather than a standalone executable: ELF type is ET_DYN, `e_entry=0`, there are three PT_LOAD segments (one RX and two RW), and `JNI_OnLoad` is the only defined dynamic export. The dynamic dependency list does **not** include `libliapp.so`; the literal `libliapp.so` was found in the binary's strings in the earlier pass, not in its `DT_NEEDED` entries. Therefore the strongest current conclusion is a LIAPP-associated dynamic-loader/protection bridge, not a direct ELF dependency on libliapp. The undefined dynamic imports directly confirm `dlopen`/`dlsym` plus UID/filesystem and file-I/O inspection; names such as `fork`, `waitpid`, `kill`, `prctl` and `dl_iterate_phdr` must not be described as imports unless independently found in the actual dynamic symbol table. The root `APNA-APKs` directory listing does not include a standalone `libliapp.so`; this does **not** prove it is absent from the APKs. It may be embedded under an ABI path, loaded from a protected payload, or resolved through another packaging mechanism. Search all ZIP entries in base and every split before assigning a location.

Do not bypass LIAPP, decrypt protected DEX, dump protected credentials, or claim that the protected DEX has been recovered. If static evidence cannot identify the owner of `libudpqtwo.so`, keep the process owner unresolved.

## DEX-to-native linkage status

The current `main` branch's `apk_dex.py` performs bounded APK Analyzer inspection, counts defined classes, joins manifest service names to defined classes, counts native declarations for exact manifest classes, and returns per-DEX reference counts. It does **not** yet include the broader method-level `System.load`, `System.loadLibrary`, `Runtime.exec`, `ProcessBuilder`, or dynamic DEX-loader evidence scanner that exists on the divergent PR #8 research branch.

That PR-branch scanner is heuristic and static:
- It correlates selected class-name candidates and bounded smali method snippets.
- It does not perform general data-flow analysis, reflection resolution, JNI `RegisterNatives` resolution, or runtime process attribution.
- A missing hit is not proof that a library is never loaded or executed.
- ProcessBuilder constructor evidence and `ProcessBuilder.start()` counts are not necessarily correlated to the same builder instance.

A clean, isolated port to a main-based branch is preferable to merging the divergent PR wholesale.

## Next evidence to collect

1. Inventory ZIP member paths for `libliapp.so` across `base.apk` and every split; report path, ABI, size and SHA-256 only.
2. Re-run ELF inspection on `libbxdtcxfzx.so` to capture `DT_NEEDED`, dynamic symbol counts, `.init_array`, PT_LOAD flags and executable entrypoint; then disassemble `JNI_OnLoad` and its reachable local functions without executing the library.
3. Obtain actual bytes for `libudpqtwo.so` in a local analysis environment and validate the hardened pclntab parser against the exact SHA-256 before reporting any recovered names.
4. Inspect `libsalamander.so` and `libputils.so` from local binary bytes; do not classify from filenames or strings alone.
5. Keep the StarUDP/Hysteria-v1 candidate distinct from generic Xray Hysteria2 support.

## Safety and release gates

- No protected-DEX bypass or credential extraction.
- No native APK binary execution in CI.
- No provider endpoint contact without authorization.
- No Windows build or new CI run as part of this research note.
- SSH remains on hold.
