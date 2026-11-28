#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

if (-not $env:ProgramFiles) {
    throw "Program Files could not be resolved on this Windows installation."
}
$source = [System.IO.Path]::GetFullPath($PSScriptRoot)
$programFiles = [System.IO.Path]::GetFullPath($env:ProgramFiles)
$target = [System.IO.Path]::GetFullPath((Join-Path $programFiles "ApnaWin"))
$token = [Guid]::NewGuid().ToString("N")
$staging = Join-Path $programFiles (".ApnaWin.staging-" + $token)
$backup = Join-Path $programFiles (".ApnaWin.backup-" + $token)
$targetMovedToBackup = $false
$stagingInstalled = $false

function Set-ApnaWinInstallAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    & icacls.exe $Path /reset /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not reset inherited ACLs for $Path"
    }
    & icacls.exe $Path /inheritance:e /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enable inherited ACLs for $Path"
    }
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply the protected Program Files ACL to $Path"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $source "ApnaWin.exe") -PathType Leaf)) {
    throw "Run this installer from the extracted ApnaWin portable application folder."
}
if (-not (Test-Path -LiteralPath (Join-Path $source "ApnaWinElevator.exe") -PathType Leaf)) {
    throw "The elevated Xray helper is missing from this build."
}
if (-not (Test-Path -LiteralPath (Join-Path $source "engine\xray.exe") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $source "engine\wintun.dll") -PathType Leaf)) {
    throw "The verified Xray/Wintun runtime folder is missing."
}

$sourcePrefix = $source.TrimEnd('\') + '\'
if ($source.StartsWith($target.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $target.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Source and destination folders must not contain one another."
}

New-Item -ItemType Directory -Path $programFiles -Force | Out-Null
try {
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Copy-Item -Path (Join-Path $source "*") -Destination $staging -Recurse -Force
    Set-ApnaWinInstallAcl -Path $staging

    if (-not (Test-Path -LiteralPath (Join-Path $staging "ApnaWin.exe") -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $staging "ApnaWinElevator.exe") -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $staging "engine\xray.exe") -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $staging "engine\wintun.dll") -PathType Leaf)) {
        throw "Staged installation is incomplete; the current installation was not changed."
    }

    if (Test-Path -LiteralPath $target) {
        Move-Item -LiteralPath $target -Destination $backup
        $targetMovedToBackup = $true
    }
    Move-Item -LiteralPath $staging -Destination $target
    $stagingInstalled = $true
    Set-ApnaWinInstallAcl -Path $target

    if (-not (Test-Path -LiteralPath (Join-Path $target "ApnaWinElevator.exe") -PathType Leaf)) {
        throw "Installation did not produce the elevated helper."
    }

    if ($targetMovedToBackup -and (Test-Path -LiteralPath $backup)) {
        Remove-Item -LiteralPath $backup -Recurse -Force
        $targetMovedToBackup = $false
    }
}
catch {
    if ($stagingInstalled -and (Test-Path -LiteralPath $target)) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    if ($targetMovedToBackup -and (Test-Path -LiteralPath $backup)) {
        Move-Item -LiteralPath $backup -Destination $target
        $targetMovedToBackup = $false
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

Write-Output "ApnaWin installed to $target"
Write-Output "Previous installation retained for rollback only during installation; User settings are stored separately and were not changed."
Write-Output "Launch ApnaWin.exe normally. UAC elevation is requested only for the VPN helper."
