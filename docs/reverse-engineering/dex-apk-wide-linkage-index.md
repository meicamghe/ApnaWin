# APK split-set DEX linkage scan — implementation status and remaining index gap

## Purpose

The current implementation has two layers:

1. `apk_dex.py` scans a bounded set of class candidates, prioritizing manifest services and names matching networking/protector keywords. It tracks selected smali register flows for `System.loadLibrary`, `System.load`, `Runtime.exec`, `ProcessBuilder`, and secondary DEX loaders.
2. `apk_dex_set.py` aggregates manifest and linkage evidence across every supplied base/split APK, joins manifest service classes to the APK in which each class is actually defined, and retains per-APK provenance.

This is a useful split-set audit, but it is **not yet an exhaustive APK-wide callsite index**: class-name selection can miss obfuscated classes, and each APK's code scan remains capped at 64 selected classes.



## Tooling constraint confirmed from Android's APK Analyzer documentation

The official CLI reference documents that `dex code --class` requires a class name, while `dex packages` emits a package/class/method/field tree and `dex references` reports per-DEX method-reference counts. These outputs do not provide invoke offsets or a class-independent callsite listing. Therefore the current class-name heuristic cannot be made exhaustive merely by changing `dex references`; a real exhaustive index needs a DEX-level parser/disassembler (e.g. dexlib2/baksmali or an equivalent parser) that walks every method's instructions and records exact invoke references and offsets. The index must preserve DEX filename, class descriptor, method descriptor, instruction offset, API target and register-flow confidence. See the official [APK Analyzer CLI reference](https://developer.android.com/tools/apkanalyzer).

## Required indexed references

- `Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V`
- `Ljava/lang/System;->load(Ljava/lang/String;)V`
- `Ljava/lang/Runtime;->exec(...)`
- `Ljava/lang/ProcessBuilder;-><init>(...)` and `start()`
- `Ldalvik/system/DexClassLoader;-><init>(...)`
- `Ldalvik/system/PathClassLoader;-><init>(...)`
- `Ldalvik/system/InMemoryDexClassLoader;-><init>(...)`
- JNI registration entry points and `RegisterNatives` references where exposed by the DEX/tool output.

## Output contract

The current split-set output preserves:
- APK/split filename and class name;
- per-method ordinal within the exact class output;
- invocation kind and call counts;
- bounded library basenames and `System.loadLibrary` names when the argument register can be traced;
- process command basenames where direct string or string-array arguments can be traced;
- dynamic DEX loader type and allowlisted archive extension;
- explicit notes where `ProcessBuilder.start()` is not correlated to a specific constructor instance.

The future exhaustive index should additionally preserve DEX filename, stable method signature/descriptor and invoke offset, exact API reference, register-flow confidence, and parser/tool version.

Do not emit complete method bodies, arbitrary string pools, credentials, filesystem paths or unrelated application data. Library names may be emitted only when they match a strict basename allowlist pattern.

## Resource and correctness limits

- Stream one DEX at a time; cap DEX count, bytes per DEX, total decoded references, methods scanned, evidence rows and wall-clock time.
- Treat tool output as untrusted: validate descriptor syntax, method signatures, argument counts and output size.
- Preserve truncation/timeout flags. A partial scan must never be reported as a complete APK-wide index.
- Deduplicate by APK member + DEX + class + method + invoke offset, not merely by library name.
- Avoid assuming that a referenced method executes. Static callsites are clues, not runtime proof.

## Regression cases

Add fixtures for obfuscated class names, class names with no signal keywords, multiple DEX files, move-object aliases, register reuse, array-based process arguments, reflection/computed strings, duplicate callsites, malformed tool output, output truncation and timeout. Include a test proving that the report marks partial scans as incomplete.

## Current status

Implemented on `research/parallel-re-audit-20261128`:
- bounded linkage scanning in `src/apnawin/services/apk_dex.py`;
- cross-split aggregation in `src/apnawin/services/apk_dex_set.py`;
- CLI in `tools/inspect_apk_dex_set.py`;
- mocked regression tests in `tests/test_apk_dex.py` and `tests/test_apk_dex_set.py`.

The implementation is static and bounded. The newly ported tests have **not yet been executed**. The exhaustive, class-name-independent APK-wide callsite index described above remains unimplemented. No result from this scanner should be presented as proof that a callsite executes at runtime.
