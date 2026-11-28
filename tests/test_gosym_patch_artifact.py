from pathlib import Path
import re


_PATCH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "patches"
    / "GoReSym-v3.4.1-moduledata-scan.patch"
)


def test_gosym_patch_hunk_line_counts_match():
    lines = _PATCH.read_text(encoding="utf-8").splitlines()
    hunks = []
    for index, line in enumerate(lines):
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if match is None:
            continue
        old_count = 0
        new_count = 0
        for entry in lines[index + 1 :]:
            if entry.startswith("@@ ") or entry.startswith("diff --git "):
                break
            if entry.startswith((" ", "-")):
                old_count += 1
            if entry.startswith((" ", "+")):
                new_count += 1
        hunks.append(
            (
                old_count == int(match.group(2) or 1),
                new_count == int(match.group(4) or 1),
            )
        )

    assert hunks
    assert all(old_ok and new_ok for old_ok, new_ok in hunks)


def test_gosym_patch_boundary_regression_test_is_complete():
    patch = _PATCH.read_text(encoding="utf-8")
    marker = "+++ b/objfile/elf_moduledata_scan_test.go\n"
    assert marker in patch
    test_hunk = patch.split(marker, 1)[1].split("\n@@ ", 1)[0]
    source = "\n".join(
        line[1:]
        for line in test_hunk.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )

    tests = re.findall(r"^func (Test\w+)\(", source, re.MULTILINE)
    assert len(tests) == 5
    assert "TestFindModuleDataOffsetRejectsCrossSectionMatch" in tests
    assert source.count("{") == source.count("}")
    assert source.rstrip().endswith("}")
