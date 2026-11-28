# Go pclntab parser hardening

Branch: `research/pclntab-parser-hardening-main`

This isolated change adds the standalone offline parser from the reverse-engineering work to the current `main` baseline and tightens validation before any recovered symbol is trusted.

## Changes

- Preserve ELF `PT_LOAD` flags and memory extents.
- Reject ambiguous overlapping virtual-address mappings instead of silently using the first segment.
- Require `textStart`, every function entry, and the terminal PC to resolve to executable `PT_LOAD` memory.
- Require function records to begin after the serialized functab.
- Bound signed `_func.nameOff` values and NUL-terminated names to the Go `funcnametab` interval ending at `cuOff`.
- Reject invalid UTF-8 function names rather than replacement-decoding them.

## Validation status

Regression tests cover the synthetic Go 1.18+ ELF fixture, stomped-magic opt-in, invalid header fields, out-of-range functab, non-monotonic entries, out-of-range function names, non-executable entries, and ambiguous PT_LOAD mappings.

The fixture is synthetic. No output from `libudpqtwo.so` is claimed, and no APK native binary is executed. The test suite has not been run in this environment; run the focused test before relying on the parser. This branch is intentionally based on current `main`, not the divergent PR #8 branch.
