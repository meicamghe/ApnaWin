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


## Upstream GoReSym v3.4.1 source confirmation

The parser path was checked against the upstream `v3.4.1` tag
(commit `722897e`, released 2026-09-14), matching the version used for the
local analysis.

### Pclntab header and functab offsets

For Go 1.18+ the header begins with a 4-byte magic followed by four one-byte
fields (`pad1`, `pad2`, PC quantum, pointer size). The eight uint64 fields
begin at byte offset 8:

| Header field | uint64 word | Byte offset |
|---|---:|---:|
| nfunctab | 0 | 8 |
| nfiletab | 1 | 16 |
| textStart | 2 | 24 |
| funcnametab offset | 3 | 32 |
| cutab offset | 4 | 40 |
| filetab offset | 5 | 48 |
| pctab offset | 6 | 56 |
| pcln/functab offset | 7 | 64 |

GoReSym's Go 1.18+ parser reads word 0 for `nfunctab`, word 7 for the
functab offset, and sizes the serialized table as
`(2*nfunctab + 1) * 4`. Therefore the candidate table address is
`pclntabVA + word[7]`. The extraction workflow was corrected to decode this
header layout rather than treating the first eight bytes as word 0.

### Why the existing moduledata path cannot recover this candidate

In v3.4.1, `main.go` calls `File.ModuleDataTable` with the pclntab VA,
version/layout, pointer width and endianness. It does not pass
`PclntabCandidate.StompMagicCandidateMeta`. The main loop checks
`SuspectedModuleDataVa == tmpModData.VA` only after `ModuleDataTable`
has returned successfully. That is too late to guide the current validator
when the moduledata ftab pointer itself is unreadable.

The Go 1.18+ `validateAndConvertModuleData` first reads
`md.Ftab.Data` through the existing `read_memory` method and returns
immediately on failure. The existing `textAddr(entryOffset, md.Text,
textsectmap) == md.Minpc` validation occurs afterward. This confirms the
narrow failure point: a guarded fallback must provide the first functab record
without bypassing the existing Minpc validation.

### Guard conditions for a future fallback

The fallback remains proposed and unimplemented. It should run only when the
normal ftab read fails and all of the following hold:

- Stomp metadata is present and its pclntab VA equals the candidate VA.
- Its suspected moduledata VA equals the moduledata candidate currently being validated.
- Metadata endianness matches the parser's endianness.
- The input is 64-bit little-endian and the parsed layout is Go 1.18+.
- Header byte fields have valid PC quantum and pointer-size values.
- Header-derived nfunctab is bounded and consistent with the moduledata ftab length.
- The derived functab address and full serialized table size pass overflow and
  file-backed `PT_LOAD` checks using the existing `read_memory` path.
- The existing first-entry / Minpc / textsectmap validation still succeeds.

Ordinary candidates must continue using the existing path. Do not broaden
`read_memory` to arbitrary addresses or accept the invalid moduledata ftab
pointer as BSS.

## Independent moduledata scanner issue

The v3.4.1 ELF `moduledata_scan` implementation uses one `bytes.Index`
result per section. If that first pointer match is in the ignore list, it
continues to the next section instead of searching for another occurrence
later in the same section. This is a real scanner limitation, independent of
the proposed ftab fallback. It may hide a valid later moduledata candidate
when multiple references occur in one section, but that has not yet been
demonstrated for this APK.

A separate regression-tested fix should iterate subsequent matches within the
same section after an ignored candidate. Keep the existing section-boundary
check and preserve the concatenated-section behavior. Do not combine this
scanner fix with the guarded ftab fallback until each has isolated tests.


## Upstream scanner status rechecked — 2026-11-28

The independent moduledata scanner limitation was rechecked against both the
GoReSym v3.4.1 tag (commit 722897e) and the current upstream master commit
fa3f0577e6f5d5692cf98348ac512dec52bbc04b. Both versions still implement
the same first-match behavior in elfFile.moduledata_scan:

1. bytes.Index(data, pclntabVA_bytes) returns only the first pointer match
   in the current section's concatenated data.
2. If that match is present in ignorelist, continue scan jumps to the
   outer section loop, abandoning the rest of the current section.
3. Any later valid moduledata pointer occurrence in that same section is
   therefore never considered during that scan attempt.

This confirms that the limitation is still present upstream; it is not an
ApnaWin-specific patch regression. It remains independent of the stomped
pclntab/ftab fallback. A narrow fix should iterate successive matches with a
moving byte offset inside the current section, preserve the existing
moduledata_idx < int(sec.Size) section-boundary guard, and move to the next
section only after exhausting the current one.

Required regression cases for the GoReSym-side patch:

- First occurrence is ignored and a second occurrence in the same section is
  returned.
- First occurrence is valid and remains the selected candidate.
- Multiple ignored occurrences are skipped without abandoning the section.
- No candidate in any section returns the existing not-found error.

No GoReSym source has been modified in the ApnaWin repository, and no recovered
symbol output is claimed from this source review.


## Prepared GoReSym v3.4.1 scanner patch

A narrowly scoped patch is now stored at
`tools/patches/GoReSym-v3.4.1-moduledata-scan.patch`. It changes only the
moduledata candidate search:

- Searches successive pointer occurrences within the same section.
- Skips ignored candidate VAs without abandoning the section.
- Requires the full pointer signature to fit inside the current section, not merely its first byte.
- Returns the first non-ignored candidate, preserving first-valid-match
  behavior.
- Adds five regression cases: ignored first match, first valid match,
  multiple ignored matches, no match, and a signature crossing the section boundary.

To apply it in a clean GoReSym v3.4.1 checkout, copy the patch file into that
checkout and run:

```sh
git apply --check GoReSym-v3.4.1-moduledata-scan.patch
git apply GoReSym-v3.4.1-moduledata-scan.patch
gofmt -w objfile/elf.go objfile/elf_moduledata_scan_test.go
go test ./objfile
```

The patch is prepared but has **not** been applied to upstream GoReSym or
validated against the APNA binary. It addresses the independently confirmed
scanner bug only; it does not yet solve the separate unreadable ftab pointer
in the suspected APNA moduledata candidate.


## Bounded Go function-table recovery tool — 2026-11-28

A standalone offline parser is now available at `tools/recover_go_pclntab.py`. It is deliberately separate from GoReSym and does not relax GoReSym's general ELF/moduledata validation.

For a fresh extracted binary, the invocation for the current candidate is:

```sh
python tools/recover_go_pclntab.py /path/to/libudpqtwo.so \
  --pclntab-va 0xc1a200 --allow-stomped-magic > go-functions.json
```

The parser requires ELF64 little-endian AArch64 ET_DYN/ET_EXEC, checks every requested address against file-backed PT_LOAD ranges, validates the remaining Go 1.18+ header byte fields and bounded counts, derives the functab from header word 7, checks the complete serialized table and terminal PC offset, then resolves each `_func.nameOff` against the function-name table. It emits function index, entry offset, function-record offset and decoded name. The stomped magic word is accepted only with the explicit command-line opt-in; all other structural checks remain mandatory.

Synthetic regression tests cover a stomped-header recovery, missing opt-in, invalid header bytes, a non-file-backed table, and non-monotonic entries. These tests validate the parser against a constructed ELF fixture only. **No recovered function list from the APNA binary is claimed yet**: the committed APK-native extraction workflow has not produced a fresh artifact available to this analysis session. The current candidate VA and previously observed first records remain hypotheses pending execution against the exact fresh ARM64 binary.

The parser currently targets Go 1.18+ 64-bit little-endian functab layout. It does not recover inline trees, pcdata streams, line tables, type metadata or DWARF, and it does not replace validation of moduledata or prove that a recovered function is reachable at runtime.
