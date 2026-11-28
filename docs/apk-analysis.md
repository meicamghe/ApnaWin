# Android APK manifest and DEX inspection

## Metadata-only inventory

Run the repository's inventory first to record the exact APK size and SHA-256:

```powershell
py -3 tools/inspect_apk.py .\path\to\application.apk
```

It never extracts or executes archive members. See [apk-inventory.md](apk-inventory.md)
for ZIP safety limits and the fields that inventory does and does not establish.

## Optional Android SDK manifest decoder

Install Android SDK Command-line Tools / APK Analyzer and make `apkanalyzer`
available on `PATH`. Then run:

```powershell
py -3 tools/inspect_apk_manifest.py .\path\to\application.apk
```

The command invokes `apkanalyzer manifest print APK` without a shell and with
a 30-second timeout. Only selected manifest metadata is emitted. The report
omits version-name text, labels, intent-filter data, resource values, arbitrary
strings, URLs, and raw XML.

## Optional DEX structure inspection

Run:

```powershell
py -3 tools/inspect_apk_dex.py .\path\to\application.apk
```

This uses the Android SDK's documented commands:
- `apkanalyzer dex list APK` to enumerate DEX files.
- `apkanalyzer dex packages --defined-only APK` to count defined classes and
  identify class names matching VPN/network-related indicators.
- `apkanalyzer dex references APK` to record per-DEX method-reference counts.

The output contains only DEX filenames, counts, and a bounded allowlist of
candidate class names. It does not include method names, field names, bytecode,
raw command output, URLs, credentials, or extracted files. Candidate matching
is heuristic: a class name containing "vpn", "tunnel", "xray", "socks", "dns",
"proxy", or related terms is a lead for later review, not proof of behavior.
Obfuscated or dynamically loaded classes may not be detected.

Both decoders invoke local SDK tooling with argument arrays, no shell, and a
30-second timeout. Standard output and standard error are drained concurrently
with a strict per-stream memory ceiling; the child process is terminated as soon
as either stream exceeds its limit. Missing tooling fails clearly; no executable
is downloaded.
Treat APKs and SDK tools as untrusted software and use an isolated analysis
environment for unknown samples. Neither report verifies runtime behavior or
discovers APNA server endpoints.

Official command reference: [Android APK Analyzer](https://developer.android.com/tools/apkanalyzer).

## Combined structural report

To generate one report with the APK hash and correlate manifest-declared VPN
services against class definitions in DEX, run:

```powershell
py -3 tools/inspect_apk_report.py .\path\to\application.apk
```

The report first records the safe ZIP inventory and SHA-256, then obtains
manifest and DEX metadata from Android SDK APK Analyzer. It checks that both
inventory and APK Analyzer agree on the number of DEX files. Relative service
names such as `.TunnelService` are resolved using the manifest package name
and compared with the defined class set. The result distinguishes a declared
VPN service from whether a corresponding class was found in DEX. A positive
match is static evidence only; it does not prove that the service starts,
establishes a tunnel, or carries traffic. A negative match may also occur when
the manifest name is aliased, obfuscated, or loaded through other mechanisms.

## Native library metadata and engine-name leads

The safe ZIP inventory records bounded `.so` basenames, ABI labels and
uncompressed sizes from entries matching `lib/<abi>/lib*.so`. The manual
native-extraction workflow additionally reads each matching member in bounded
memory to hash it and inspect ELF headers; it does not write members to disk,
load them, or execute them. Its `native-elf-inventory.json` output reports
per-split/per-ABI hashes, ELF class, machine, entry point, interpreter presence,
and a conservative execution-model candidate. Invalid ELF data is retained as
a bounded per-file error rather than being mistaken for a valid library. The combined report includes per-ABI library
counts and filename-only engine candidates.

Candidate matching uses name-token boundaries rather than arbitrary substring
searches. For example, `libssr.so` is a Shadowsocks lead, while an unrelated
basename that merely contains the letters "ssr" inside a longer token is not.
A small numeric suffix such as the "5" in `hev-socks5` is accepted for the
tun2socks marker. These remain heuristic leads: filenames can be misleading,
libraries can be statically linked or obfuscated, and a match does not
establish that code is loaded or used.

Android ABI libraries (such as `arm64-v8a`) are not Windows DLLs and are not
treated as reusable Windows binaries. No Windows binary compatibility is
inferred.


The combined interpretation also reports counts of VPN service classes matched in DEX, resolvable-but-missing classes, and unresolved service names. `vpn_service_class_resolution_complete` is false whenever a service could not be resolved because package context was unavailable; this prevents an incomplete join from being presented as a definitive negative result.


For each exact manifest-service-to-defined-class match, the DEX report also
includes the APK Analyzer numeric metadata for that class: defined-method
count, referenced-method count, and reported byte count. These values are
class-level structural metadata, not method names or bytecode. They are null
when the service class cannot be resolved or is not present among defined
classes. Referenced-only DEX rows are not treated as class definitions.


The combined report also summarizes filename-based engine candidates by
candidate name and ABI. Its interpretation may mark that a manifest-declared
VPN service class and one or more native engine-name candidates are both
present in the same APK. This is only co-presence in the package: it does not
establish a class-to-library dependency, dynamic loading, or runtime use.



## Native method declarations in VPN service classes

For each manifest-declared VPN service whose exact class name resolves and is
present among DEX-defined classes, the combined DEX inspection additionally
runs the documented `apkanalyzer dex code --class CLASS APK` command. The
smali output is processed in memory and discarded; only the count of method
declarations carrying the DEX `native` access flag is retained. Method names,
signatures, bytecode, strings, and raw tool output are not included in the
report. Classes that cannot be resolved or are absent from defined DEX classes
are not disassembled and have a null count with inspection marked incomplete.

A positive count establishes that the service class declares native methods;
it does not establish which library implements them, whether JNI resolution
succeeds, or whether those methods are invoked. A zero count does not rule out
native code elsewhere in the application. This remains static structural
evidence, not proof of native-service linkage or runtime behavior.

The command and smali output format are documented by the
[Android APK Analyzer reference](https://developer.android.com/tools/apkanalyzer).


## ELF identity and JNI export metadata

The combined report reads selected native-library members in bounded memory
(no archive member is written to disk and no native code is executed). It
parses ELF identification and section metadata for supported 32-bit and
64-bit, little- or big-endian ELF layouts. It records machine architecture,
file type, ELF entry-point address, whether a PT_INTERP segment is present,
whether a dynamic symbol table is available, and counts of exported function
symbols using the JNI-style `Java_...` naming convention and an exported function symbol named `JNI_OnLoad`. Data objects with those names are not counted as callable JNI entry points.
Raw symbol names, symbol values, addresses, and binary contents are never
included in the report. Per-library reads are capped at 64 MiB, aggregate
reads at 256 MiB, analysis at 256 libraries, and each dynamic symbol table
at 16 MiB and dynamic symbol count at 262,144 entries. Symbol-name
termination checks process sorted unique offsets to prevent repeated scans
of the same string-table suffix. ELF extended section numbering is supported with the same
section-count and bounds limits. Dynamic symbol tables must link to a valid
ELF string-table section. The section-name string-table index is checked; referenced section names
must be in range and NUL-terminated. A missing section-name table
(`SHN_UNDEF`) remains valid. `SHN_XINDEX` section-name indexes are rejected
because their reserved index range exceeds this parser's 4096-section limit.

A conservative `execution_model` hint distinguishes an ELF `ET_DYN`
file with a nonzero entry point and a valid interpreter segment
(`pie_executable_candidate`) from an `ET_DYN` file with no entry point and no
interpreter (`shared_object_candidate`). Other combinations are
`other_or_ambiguous`. These are structural candidates, not loader acceptance
or runtime proof; a filename ending in `.so` does not prove that a file is a
JNI library or that Java loads it through JNI.

A matching exported `Java_...` name is evidence of a JNI-style export, not
proof that a particular DEX native method resolves to it. An exported
`JNI_OnLoad` can be used for explicit `RegisterNatives` registration, but
its presence alone does not prove which methods are registered. Conversely,
a stripped or section-header-free library, hidden symbols, or registration
performed through another mechanism can make static symbol counts
incomplete. The report therefore never upgrades these observations to
verified service-to-library linkage or runtime behavior.

The parsing approach follows the Android NDK JNI guidance on dynamic lookup
and `RegisterNatives`: [JNI tips](https://developer.android.com/ndk/guides/jni-tips).



## Android ABI and ELF identity consistency

For each readable native library under a recognized Android ABI directory, the
combined report compares ELF class, machine number, and byte order with the
ABI's expected identity: `armeabi-v7a` (ELF32/EM_ARM), `arm64-v8a`
(ELF64/EM_AARCH64), `x86` (ELF32/EM_386), and `x86_64`
(ELF64/EM_X86_64). Recognized Android ABIs are expected to use little-endian
ELF. Per-library results are `compatible`, `mismatch`, `unknown_abi`, or
`not_checked`; aggregate counts and the mismatch count are included.

This checks only ELF header identity against the APK path's ABI label. A match
does not prove Android loader acceptance, required shared libraries, CPU
feature compatibility, JNI resolution, or runtime use. Unknown ABI labels and
unreadable or skipped ELF files are not classified as compatible or mismatched.


The top-level interpretation section repeats the number of ABI mismatches,
the number of libraries with a known identity check, and a boolean mismatch
indicator. Unknown ABI labels and unreadable or skipped files are excluded
from the checked-library count; inspect native.elf_analysis for the full
per-library classifications and all category counts.


## ELF header consistency checks

The ELF metadata parser also verifies that the main header's version field is
the current ELF version and that e_ehsize matches the class-specific ELF
header size (64 bytes for ELF64 and 52 bytes for ELF32). Inputs with inconsistent
header metadata are classified as invalid rather than being interpreted using
assumed offsets. This is a structural consistency check; it does not establish
that a library is accepted by an Android loader.


Section metadata validation also checks that the section-header table begins
at the class-required alignment (8 bytes for ELF64 and 4 bytes for ELF32),
and that each section's declared alignment is either zero, one, or a power of
two. These checks reject structurally inconsistent alignment metadata; they
do not attempt to map sections into memory or prove loader compatibility.

The ELF program-header table envelope is validated without interpreting
segment types or mapping addresses: a non-empty table must have a nonzero,
class-aligned offset, class-sized-or-larger entries, a bounded entry count,
and a complete in-file range. The extended PN_XNUM count is read from
section-zero sh_info and is subject to the same limit. Segment contents,
virtual addresses, and file-to-memory mappings are not interpreted.

Every file-backed section (other than the special null section) is also
checked to ensure its declared byte range lies within the ELF input.
SHT_NOBITS sections are exempt because they occupy memory size but have no
file payload. This prevents unrelated malformed section ranges from being
silently accepted while preserving valid NOBITS layouts.

Regression tests exercise both out-of-bounds file-backed ranges and valid
out-of-file SHT_NOBITS layouts for ELF32 and ELF64.


Dynamic symbol-table validation also checks that its linked string table is
non-empty and begins with the required NUL byte (the empty string at index
zero), that the local-symbol boundary (sh_info) does not exceed the number of
entries, and that every symbol's name offset is in range and NUL-terminated.
These checks include local or otherwise non-exported entries excluded from
JNI counting. Malformed metadata is rejected instead of being silently
ignored because the affected symbol would not contribute to the report.



## ELF symbol-table section references

Before counting JNI-style exports, the parser validates section metadata for
both static and dynamic symbol tables. Each symbol table must link to an
in-range string-table section, use a nonzero entry size large enough for the
ELF class, have a section size divisible by that entry size, and keep its
symbol data and linked strings within the file. The local-symbol boundary
must not exceed the number of entries, and the linked string table must begin
with its required NUL byte. When present, symbol-table entry zero (STN_UNDEF)
must have all-zero class-specific fields, as required for the reserved
undefined symbol. Invalid references, null-entry contents, or bounds cause
that ELF member to be classified as invalid; static symbol names are not
emitted or counted as JNI exports.


## ELF relocation-section metadata

Before interpreting dynamic symbols, the ELF parser validates relocation
section metadata for both ELF32 and ELF64. REL and RELA sections must reference
an in-range static or dynamic symbol-table section, identify an in-range target
section index, use an entry size at least as large as the class-specific
standard record, have a section size divisible by that entry size, and keep
the relocation bytes within the file. For ET_REL objects, the target index must identify a nonzero section;
for ET_EXEC and ET_DYN objects, zero remains permitted for dynamic relocation
sections. Relocation records themselves are not decoded: their architecture-specific symbol indexes, relocation types, and
addends are outside this metadata-only inspection. Passing these checks does
not establish that relocations can be applied or that the library is loadable.


## ELF RELR relocation-section metadata

SHT_RELR sections are accepted only in ET_EXEC and ET_DYN objects. Their
entries are class-sized relocation words: 4 bytes for ELF32 and 8 bytes for
ELF64. The parser checks the exact entry size, divisibility of the section
size, and file bounds. It does not decode RELR bitmaps or apply relocations.
The ELF specification does not assign SHT_RELR-specific sh_link or sh_info
semantics in the section-header interpretation table, so those fields are not
given invented constraints here. These checks establish structural metadata
only, not relocation correctness or loader compatibility.


## ELF extended symbol section-index metadata

SHT_SYMTAB_SHNDX sections are checked against their linked SHT_SYMTAB or
SHT_DYNSYM section. The link must identify a symbol table, sh_info must be
zero, sh_entsize must be four bytes, and the section must contain exactly one
32-bit word for each symbol-table entry. A symbol using SHN_XINDEX must have
a companion extended-index section; its corresponding word must identify an
in-range section index. For symbols not using SHN_XINDEX, the corresponding
word must be SHN_UNDEF (zero). Duplicate companion sections and orphaned
extended-index sections are rejected.

The parser caps section headers at 4096, below the reserved SHN_XINDEX range
(starting at 0xff00). Consequently, an actual extended section index cannot
be represented within the current analysis limit and is rejected explicitly.
This is a bounded metadata check; it does not decode or resolve symbol names
or establish loader compatibility.

## ELF section-group metadata

SHT_GROUP sections are accepted only in ET_REL objects and are checked
as bounded arrays of 32-bit words. Their section-header flags must be zero.
The parser validates the linked symbol-table reference and signature-symbol
index, the required four-byte entry size, and every member section index.
GRP_COMDAT is recognized; the GRP_MASKOS and GRP_MASKPROC ranges are preserved
for ABI-specific meanings, while other undefined flag bits are rejected.
Members must follow the group header, carry SHF_GROUP, and cannot be listed
more than once or shared between groups. The parser caps each group at 65,536
32-bit words before allocating the decoded word array, preventing a large
untrusted group payload from causing disproportionate Python-object memory
use. Conversely, every section carrying SHF_GROUP must be referenced by
exactly one group. Group records are not used to infer linker selection or
runtime behavior; this is structural metadata validation only.


## ELF dynamic and SysV hash section metadata

SHT_DYNAMIC sections must link to an in-range SHT_STRTAB section, have
sh_info equal to zero, use the class-specific Elf32_Dyn / Elf64_Dyn record
size (8 bytes for ELF32 and 16 bytes for ELF64), and contain a whole number
of records within the file bounds. The final record must carry the
DT_NULL tag that terminates the dynamic array; the parser reads only that tag.
Other dynamic tag values and pointer-valued addresses are not resolved: doing
so requires mapping program headers and applying ABI-specific interpretation.

SHT_GNU_HASH sections must link to an in-range SHT_DYNSYM section and
have sh_info equal to zero. The section alignment must match the ELF address
size; sh_entsize is four for ELF32 and zero for ELF64. The parser checks the
four-word header, class-sized Bloom-filter array (4-byte words for ELF32 and
8-byte words for ELF64), nonzero bucket count, a nonzero power-of-two Bloom
count, the symbol-offset boundary, and exact section bounds for the bucket
and chain arrays. Non-empty buckets must point to dynamic-symbol indexes at
or after the symbol offset and within the linked symbol table. Each referenced
forward chain must reach a hash word whose low bit marks the end of that chain.
Hash values and Bloom-filter bits are not recomputed, and no symbol names or
runtime lookups are performed. These checks establish bounded structural
metadata only, not loader compatibility.


SHT_HASH sections must link to an in-range SHT_SYMTAB or SHT_DYNSYM section,
have sh_info equal to zero, and use four-byte Elf32_Word entries. The parser
checks the bounded SysV hash layout (nbucket, nchain, bucket array, chain
array), requires a nonzero bucket count, nchain equal to the linked symbol
table's entry count, and an exact section size matching both arrays. It rejects
bucket or chain indexes outside that table and trailing bytes beyond the
declared hash structure.
It does not calculate symbol hashes or perform dynamic symbol resolution.
These checks establish structural metadata only, not loader compatibility or
runtime behavior.


## ELF local-symbol ordering

For each SHT_SYMTAB and SHT_DYNSYM section, the parser validates the ELF
local-symbol boundary recorded in sh_info. Every symbol before that index must
have STB_LOCAL binding, and every symbol at or after it must have a non-local
binding. Dynamic symbol names are validated first so malformed-name diagnostics
are not masked by this ordering check. Static symbol tables receive the same
ordering check after dynamic-symbol inspection. The binding is read from the
class-specific st_info byte; symbol names, values, and addresses are not
needed for this check. ELF32 and ELF64 regression tests cover valid ordering
and both directions of boundary inconsistency. This is a structural
consistency check and does not establish symbol resolution.


## ELF symbol-table work limits

Both static (SHT_SYMTAB) and dynamic (SHT_DYNSYM) symbol tables are capped
at 262,144 entries during the initial section-metadata validation, before
extended-index processing or any per-symbol iteration. Dynamic tables retain
their separate 16 MiB byte-size ceiling. These limits bound parser CPU work
for untrusted APK-native ELF metadata; exceeding a limit classifies the
library as invalid for this analysis and does not imply anything about
Android loader acceptance.
