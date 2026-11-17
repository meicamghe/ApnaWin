from pathlib import Path


def test_installer_stages_new_tree_and_keeps_previous_install_for_rollback():
    script = (
        Path(__file__).parents[1] / "scripts" / "Install-ApnaWin.ps1"
    ).read_text(encoding="utf-8")

    stage_copy = script.index('Copy-Item -Path (Join-Path $source "*")')
    acl_staging = script.index("Set-ApnaWinInstallAcl -Path $staging")
    backup_existing = script.index("Move-Item -LiteralPath $target -Destination $backup")
    swap_staging = script.index("Move-Item -LiteralPath $staging -Destination $target")
    rollback = script.index("Move-Item -LiteralPath $backup -Destination $target")

    assert stage_copy < acl_staging < backup_existing < swap_staging < rollback
    assert "$targetMovedToBackup = $true" in script
    assert "Previous installation retained for rollback" in script
    assert "User settings are" in script
    assert "/grant:r" in script
    assert "$LASTEXITCODE -ne 0" in script


def test_installer_does_not_rewrite_live_installation_acl_before_copy():
    script = (
        Path(__file__).parents[1] / "scripts" / "Install-ApnaWin.ps1"
    ).read_text(encoding="utf-8")

    assert "Set-ApnaWinInstallAcl -Path $staging" in script
    assert "Set-ApnaWinInstallAcl -Path $target" not in script
    assert "Copy-Item -Path (Join-Path $source \"*\") -Destination $target" not in script



def test_installer_normalizes_acl_for_every_staged_file_and_final_install():
    script = (
        Path(__file__).parents[1] / "scripts" / "Install-ApnaWin.ps1"
    ).read_text(encoding="utf-8")

    assert "& icacls.exe $Path /reset /T /C" in script
    assert "& icacls.exe $Path /inheritance:e /T /C" in script
    assert "Set-ApnaWinInstallAcl -Path $target" in script
    assert "Could not reset inherited ACLs" in script
