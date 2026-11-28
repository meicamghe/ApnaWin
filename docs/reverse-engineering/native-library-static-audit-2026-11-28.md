# Native library static audit — 2026-11-28

## Scope and method

This note records a second, independent static pass over native files stored in `APNA-APKs/` on the public `main` branch. GitHub returned the complete base64 content for five small/medium ELF files; the files were decoded in memory and inspected for ELF headers, section names, and printable strings. No native library was executed, loaded into Android, or connected to a network.

The Git object identifiers below are Git blob SHA-1 values, **not SHA-256 checksums**. File sizes are repository metadata. This pass does not establish runtime loading, call order, or network behavior.

## Confirmed observations

| File | Size | Git blob SHA-1 | Static finding |
|---|---:|---|---|
| `libbxdtcxfzx.so` | 688,364 | `d28f5a6fa03bfee41b392573d2091473d9a39fe1` | ELF64 AArch64 shared object; exports only `JNI_OnLoad` in the inspected dynamic symbol table; `DT_NEEDED` lists `liblog.so`, `libdl.so`, `libc.so` and `libm.so`. The string `libliapp.so` is embedded in the file but is **not** a `DT_NEEDED` dependency. Dynamic imports include `dlopen` and `dlsym`; `prctl` and `waitpid` occur as printable strings but are not dynamic imports in this file's `.dynsym`. This is consistent with a JNI loader/bridge that may resolve additional symbols or libraries dynamically, but the exact behavior and origin of `libliapp.so` are not established. |
| `libpdnsd.so` | 215,632 | `c97bc8bd2c8fa6627e0d990a28dd44e304c41972` | ELF64 AArch64 executable-style ELF with pdnsd strings/source paths. Contains DNS cache, root-server discovery, EDNS, TCP/UDP fallback, UDP server/thread and daemonization paths. Confirms a pdnsd-derived DNS component is compiled into this file. |
| `libtun2socks.so` | 160,232 | `3dcf20c86b381081b33c4609bd44b683eaf811d8` | ELF64 AArch64 executable-style ELF. Explicit banner: `BadVPN tun2socks 1.999.127`. CLI strings require a SOCKS server and expose DNS gateway, remote UDP gateway, UDP connection/buffer limits and transparent DNS options. This confirms the BadVPN tun2socks code family and supported command-line surface, not that the app launches it. |
| `libtoolChecker.so` | 5,512 | `5d8fb7036073d4f3fbe84df1af65d38a2a3d682f` | JNI exports include `Java_com_scottyab_rootbeer_RootBeerNative_setLogDebugMessages` and `Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot`; strings identify RootBeer. This is a root-detection component, separate from the LIAPP evidence above. |
| `libdatastore_shared_counter.so` | 7,112 | `64056389fa2c9c69ded3353596a444afb29d6148` | JNI exports map to AndroidX DataStore `NativeSharedCounter`: create, truncate, get and increment shared counter. No VPN/proxy role is indicated by the inspected symbols. |

All five files report ELF machine value 183 (AArch64). The first file has no ELF entry point; the latter two with command-line banners expose entry points. These observations are based on ELF metadata and embedded strings, not full control-flow disassembly.

## Parallel tracks and current blockers

### Track 1 — Android DEX and split linkage

The research branch has a bounded DEX scanner and base/split aggregator. It scans up to 64 candidate classes per APK, prioritizing manifest VPN services and class-name signals. It can collect limited evidence for `System.loadLibrary`, `System.load`, `Runtime.exec`, `ProcessBuilder` and dynamic DEX loaders.

**Gap:** it is not an exhaustive class-name-independent DEX callsite index. Invoke-range, reflection/computed arguments and obfuscated class paths remain possible blind spots. The actual APK bytes (`base.apk` and `split_config.arm64_v8a.apk`) were not returned by the GitHub file connector, so no new DEX run is claimed in this pass.

### Track 2 — Go native engines

The previously supplied `libxray.so` analysis remains a separate evidence set. Do not transfer Xray findings to `libudpqtwo.so` or `libsalamander.so`.

**Blocker:** GitHub exposed metadata/blob IDs for `libudpqtwo.so` and `libsalamander.so`, but did not return their binary bytes through the current connector path. Their Go pclntab, imports, functions and call graph have therefore not been newly validated here.

### Track 3 — Network stack composition

The repository contains separate DNS (`libpdnsd.so`) and packet-to-SOCKS bridge (`libtun2socks.so`) components. The Xray engine is another independent path. The APK-to-process handoff, service lifecycle, configuration origin and division of traffic between these components remain to be proven from DEX/JNI callsites or runtime traces.

### Track 4 — LIAPP / anti-tamper

`libbxdtcxfzx.so` and `libtoolChecker.so` must remain separate findings. The former has LIAPP-loader indicators; the latter exposes RootBeer JNI names. Neither establishes the exact runtime policy, detection triggers, or response action.

## Next evidence required

1. Obtain the exact bytes of `base.apk` and all relevant splits to run the split-set DEX inspector and build class/method/invoke-offset provenance.
2. Obtain exact bytes of `libudpqtwo.so` and `libsalamander.so`; record SHA-256 locally before parsing Go metadata or disassembling.
3. Link every discovered native library to its APK ZIP member path and hash; do not infer provenance from a standalone filename.
4. Recover Java/Kotlin service-to-process/config handoff, then distinguish `System.loadLibrary` from executable launch and extracted-file execution.
5. Only after static provenance is established, plan controlled runtime observation. Do not infer server protocol or authentication from strings alone.

## فارسی — جمع‌بندی

این دور پنج کتابخانه را از روی بایت‌های واقعی موجود در مخزن بررسی کرد:

- `libtun2socks.so`: خانوادهٔ BadVPN tun2socks نسخهٔ 1.999.127؛ شامل مسیر SOCKS، درگاه UDP و تنظیم DNS.
- `libpdnsd.so`: موتور DNS مبتنی بر pdnsd با cache، EDNS و مسیرهای TCP/UDP.
- `libtoolChecker.so`: رابط JNI مربوط به RootBeer برای بررسی Root.
- `libdatastore_shared_counter.so`: شمارندهٔ مشترک AndroidX DataStore؛ ارتباطی با موتور تونل از شواهد فعلی دیده نشد.
- `libbxdtcxfzx.so`: دارای نشانه‌های JNI/loader و ارجاع به `libliapp.so`؛ ارتباط با LIAPP محتمل و مستند است، اما رفتار دقیق هنوز اثبات نشده است.

**محدودیت مهم:** محتوای باینری APKها، `libudpqtwo.so` و `libsalamander.so` از مسیر فعلی GitHub دریافت نشد. بنابراین DEX جدید و تحلیل عمیق این دو کتابخانه انجام‌شده محسوب نمی‌شود. هیچ فایل باینری اجرا نشده، CI یا Build ویندوز اجرا نشده، و هیچ تغییری در SSH انجام نشده است.


## ELF dynamic-symbol cross-check

The dynamic symbol tables were parsed separately from printable strings:

- `libbxdtcxfzx.so`: the only inspected defined dynamic export is `JNI_OnLoad`; `DT_NEEDED` is `liblog.so`, `libdl.so`, `libc.so`, `libm.so`. Imported symbols include `dlopen`, `dlsym`, `getuid` and `lstat`. Although the strings `prctl` and `waitpid` are present, neither is a dynamic import in the parsed `.dynsym`. The embedded `libliapp.so` name is not listed in `DT_NEEDED`; dynamic loading is plausible but not proven by that string alone.
- `libpdnsd.so`: dynamic symbols expose `main`, `udp_server_thread` and `tcp_server_thread`, among other symbols; imports include socket, bind, send/receive, pthread, fork/exec and process lifecycle functions. This supports the DNS daemon architecture inferred from its embedded messages.
- `libtun2socks.so`: dynamic symbols expose `main` and globals for SOCKS server address, UDP gateway, DNS gateway and device/network state. Imports include socket/connect/bind/accept, epoll and ioctl. This supports its standalone command-line packet-bridge architecture.
- `libtoolChecker.so`: exported JNI functions explicitly include `RootBeerNative_checkForRoot` and `setLogDebugMessages`.
- `libdatastore_shared_counter.so`: exported JNI functions explicitly implement AndroidX `NativeSharedCounter` operations.

This symbol pass refines earlier string-only interpretations. A printable token is not an imported symbol, and an embedded library filename is not proof of an ELF dependency or successful runtime load.


## ELF execution model distinction

The ELF headers/program headers add an important distinction between the files with a `.so` suffix:

- `libpdnsd.so` and `libtun2socks.so` are both ELF64 AArch64 `ET_DYN` images with a nonzero entry point, a `PT_INTERP` segment naming `/system/bin/linker64`, and a defined dynamic symbol named `main`. These are executable-style Android PIE images, despite their `.so` filenames. This makes subprocess execution a stronger hypothesis than ordinary `System.loadLibrary` loading; DEX callsites are still needed to prove how the app launches them.
- `libbxdtcxfzx.so` has no ELF entry point in the inspected header and exports `JNI_OnLoad`, which is consistent with a conventional JNI shared-library role.

This distinction is especially useful for the next DEX pass: search separately for executable file extraction/chmod plus `ProcessBuilder`/`Runtime.exec` launches of pdnsd/tun2socks, and JNI/native-loader references for the LIAPP bridge. Do not treat the `.so` suffix as evidence that all three are loaded the same way.
