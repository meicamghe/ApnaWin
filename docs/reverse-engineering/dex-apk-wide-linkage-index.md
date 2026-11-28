# APK-wide DEX linkage index — implementation specification

## Purpose

The current DEX inspector prioritizes a bounded set of candidate classes (including manifest services and classes whose names match networking/protector keywords). That is useful triage, but class-name selection can miss obfuscated classes whose methods call JNI or load secondary DEX files.

The next DEX pass should index exact linkage callsites across every DEX file in the APK/split set, independent of class names.

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

Each evidence row should preserve:
- APK/split filename and DEX filename;
- class descriptor and method signature;
- exact referenced API and invocation kind;
- bounded literal arguments, where statically recoverable;
- register-flow classification (`direct-literal`, `move-alias`, `array-literal`, `computed-or-unknown`);
- evidence source and parser/tool version.

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

This file specifies the next implementation slice. It does not claim that the APK-wide index has been implemented or run. Existing candidate-class linkage scanning remains heuristic and bounded.
