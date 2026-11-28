# DEX/JNI linkage scanner port review

Branch: `research/apk-dex-linkage-main` (based on current `main`)

This isolated branch ports the bounded DEX linkage scanner from the divergent PR #8 research branch while retaining every existing `main` test in `tests/test_apk_dex.py` (all 23 existing test names are present in the 52-test branch version).

## Added evidence

- Exact-register linkage for `System.loadLibrary` and `System.load` string arguments.
- Bounded process-launch evidence for `Runtime.exec`, `ProcessBuilder` constructors and `ProcessBuilder.start()`.
- Dynamic DEX loader indicators for `DexClassLoader`, `PathClassLoader` and `InMemoryDexClassLoader`.
- Manifest service to class joins across base and split APKs.
- Split-level evidence aggregation, with no raw smali method bodies returned.

## Important limitations

This is a bounded heuristic scanner, not a DEX interpreter:
- It scans selected class-name candidates, so an obfuscated class with no recognized name signal can be missed.
- It does not generally solve reflection, computed strings, register aliasing beyond its explicit patterns, or dynamic `RegisterNatives` tables.
- A `ProcessBuilder.start()` count is not proven to refer to a specific constructor instance.
- A string literal or loader call is static evidence only; it does not prove the library is loaded or a process is launched at runtime.
- Protected LIAPP DEX remains out of scope; no bypass or decryption is attempted.

## Validation status

The branch carries the expanded unit-test files from PR #8, including all 23 test names from current `main`. The tests have **not** been run in this environment. No APK was inspected by this code in this turn, no native code was executed, and no build or CI was started.
