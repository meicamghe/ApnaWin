# Reverse engineering notes: `libudpqtwo.so` Go pclntab

**Status:** investigation notes; proposed recovery fallback is not yet implemented or validated.

## Scope

This document records the analysis of the proprietary Go/cgo engine extracted from the ApnaWin APK. The binary under investigation is:

`/tmp/apnawin-udpqtwo/libudpqtwo.so`

The work is focused on recovering Go symbols and function metadata. It does not change the ApnaWin application source or authorize a new Windows build.

## Binary identification

- ELF64, little-endian, AArch64 Android shared library.
- Stripped Go + cgo binary.
- Go build information does not reveal a usable compiler version.
- GoReSym v3.4.1 currently fails with `no valid pclntab found`.

## Suspected pclntab

A likely pclntab header was identified at:

- VA: `0xc1a200`
- File offset: `0xc0a200`

Its first four bytes are non-standard/stomped. The following bytes are compatible with a Go pclntab header on ARM64.

Interpreted as little-endian:

| Header field | Value |
|---|---:|
| nfunc | `0x4edb` |
| nfiles | `0xccd` |
| textStart | `0x1be5a0` |
| funcnameOffset | `0x60` |
| cuOffset | `0x104de0` |
| filetabOffset | `0x1118e0` |
| pctabOffset | `0x124360` |
| pclnOffset | `0x2da9a0` |

The header-derived functab address is:

`0xc1a200 + 0x2da9a0 = 0xef4ba0`

The data there begins with 8-byte records that parse as two little-endian uint32 fields:

- entryoff `0`, funcoff `0x276e0`
- entryoff `0x60`, funcoff `0x27738`
- entryoff `0x540`, funcoff `0x27790`

This record width is consistent with the Go 1.18+ functab representation.

## Suspected moduledata

A likely moduledata candidate is at:

- VA: `0x10ee3a0`
- File offset: `0x10de3a0`

Its first pointer is `0xc1a200`, matching the suspected pclntab header.

Interpreting the structure with the Go 1.20 layout gives:

- pclntable data: `0x11cf540`, length `0x1ce210`
- ftab data: `0x11cf540`, length `0x4edc`
- Minpc: `0x1be5a0`
- Text: `0x1be5a0`

The ftab data pointer `0x11cf540` lies outside the ELF LOAD memory ranges. It is not a readable mapped address in this file. Do not treat it as ordinary BSS: it is beyond the LOAD segment memory extent.

A candidate at `0x1bd848` is a false positive: it lies inside `.rela.dyn`, and the apparent slice-like values are relocation records. The candidate at `0x10ee3a0` is much more strongly supported.

## GoReSym code-path findings

Relevant GoReSym v3.4.1 implementation areas inspected:

- `objfile/objfile.go`: `File.ModuleDataTable`, `Entry.ModuleDataTable`, `PclntabCandidate`, and stomped-candidate metadata.
- `objfile/layouts.go`: generic moduledata parsing and validation.
- `objfile/elf.go`: stomped magic candidate generation and moduledata scanning.
- `debug/gosym/pclntab.go`: Go 1.18+ pclntab parsing and functab field sizing.

For Go 1.18+:

- functab entries use 4-byte fields.
- Each function record occupies 8 bytes.
- The pclntab parser obtains the functab start from header offset word 7.
- The table size is `(nfunctab*2 + 1) * 4` bytes.

The generic moduledata validator reads the first functab record using `md.Ftab.Data` and validates the first entry using:

`textAddr(entryOffset, md.Text, textsectmap) == md.Minpc`

The current failure occurs earlier: the moduledata ftab pointer is unreadable, so the validator cannot read the first record.

## Stomped-candidate metadata

GoReSym's `PclntabCandidate` carries `StompMagicCandidateMeta`, which includes:

- `PclntabVa`
- `SuspectedModuleDataVa`
- `LittleEndian`

The current `ModuleDataTable` call path does not pass this metadata through to the moduledata parser/validator. The main call site supplies the pclntab VA and version/layout information only.

## Proposed guarded recovery path — not implemented

A possible fix is to derive the functab location from the pclntab header only for a matching stomped-magic candidate:

1. Pass the candidate's stomp metadata through the `File.ModuleDataTable` wrapper and into `Entry.ModuleDataTable`.
2. Preserve existing callers, for example with an optional variadic metadata argument.
3. Enable the fallback only if the metadata's pclntab VA matches the current candidate, its suspected moduledata VA matches the moduledata candidate found, and the endianness matches.
4. Restrict the initial implementation to the confirmed 64-bit little-endian Go 1.18+ layout.
5. If `md.Ftab.Data` cannot be read, read pclntab header offset word 7 and calculate `pclntabVA + offset7`, checking integer overflow.
6. Read `nfunctab` from header offset word 0; calculate `(2*nfunctab + 1)*4` with overflow checks and verify the full range is readable from the ELF LOAD file-backed region.
7. Validate the first entry using the existing `textAddr` / `Minpc` check. Do not bypass the existing validation.
8. Keep ordinary, non-stomped candidates on the existing path.
9. Do not globally expand ELF reads to accept arbitrary addresses outside LOAD segments.

The header-derived address and initial records support this hypothesis, but the fallback has not yet been implemented or regression-tested.

## Next steps

- [ ] Inspect the complete `File.ModuleDataTable` wrapper and its call context.
- [ ] Review existing moduledata tests.
- [ ] Implement guarded stomp-metadata propagation and functab fallback.
- [ ] Add regression tests for valid fallback, metadata mismatch, invalid bounds, and normal candidates.
- [ ] Run `go test ./...` and build GoReSym.
- [ ] Re-run GoReSym against `libudpqtwo.so`.
- [ ] Verify recovered symbols and function metadata before treating the recovery as successful.
