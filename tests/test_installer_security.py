from pathlib import Path


def test_installer_protects_existing_program_files_tree_before_copying_executables():
    script = (
        Path(__file__).parents[1] / "scripts" / "Install-ApnaWin.ps1"
    ).read_text(encoding="utf-8")

    copy = script.index('Copy-Item -Path (Join-Path $source "*")')
    acl_before_copy = script.rfind("Set-ApnaWinInstallAcl", 0, copy)
    acl_after_copy = script.find("Set-ApnaWinInstallAcl", copy + 1)

    assert 0 <= acl_before_copy < copy < acl_after_copy
    assert "/inheritance:r" in script
    assert "/grant:r" in script
    assert "/C" not in script
    assert "$LASTEXITCODE -ne 0" in script
