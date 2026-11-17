#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
if (-not $env:ProgramFiles) {
    throw "Program Files could not be resolved on this Windows installation."
}
$source = [System.IO.Path]::GetFullPath($PSScriptRoot)
$target = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "ApnaWin"))

if (-not (Test-Path -LiteralPath (Join-Path $source "ApnaWin.exe") -PathType Leaf)) {
    throw "Run this installer from the extracted ApnaWin portable application folder."
}
if (-not (Test-Path -LiteralPath (Join-Path $source "ApnaWinElevator.exe") -PathType Leaf)) {
    throw "The elevated Xray helper is missing from this build."
}
$engine = Join-Path $source "engine"
if (-not (Test-Path -LiteralPath (Join-Path $engine "xray.exe") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $engine "wintun.dll") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $engine "runtime-manifest.json") -PathType Leaf)) {
    throw "The verified Xray/Wintun runtime folder or its integrity manifest is missing."
}

$sourcePrefix = $source.TrimEnd('\') + '\'
if ($source.StartsWith($target.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $target.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Source and destination folders must not contain one another."
}

$parent = Split-Path -Parent $target
$leaf = Split-Path -Leaf $target
$token = [Guid]::NewGuid().ToString("N")
$staging = Join-Path $parent "$leaf.installing-$token"
$backup = Join-Path $parent "$leaf.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$token"
$targetMovedToBackup = $false

function Set-ApnaWinInstallAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    # Apply the protected ACL to a clean staging tree, never to the live
    # installation. Existing files may have empty or otherwise broken DACLs.
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply the protected Program Files ACL to $Path"
    }
}

try {
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    # Build and secure a complete new installation beside the live one.
    Copy-Item -Path (Join-Path $source "*") -Destination $staging -Recurse -Force
    Set-ApnaWinInstallAcl -Path $staging

    foreach ($required in @(
        "ApnaWin.exe",
        "ApnaWinElevator.exe",
        "engine/xray.exe",
        "engine/wintun.dll",
        "engine/runtime-manifest.json"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $staging $required) -PathType Leaf)) {
            throw "Staged installation is missing required file: $required"
        }
    }

    # Stop the desktop process before swapping directories. User settings are
    # stored outside Program Files and are not touched by this installer.
    Get-Process -Name "ApnaWin","ApnaWinElevator" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $target -PathType Container) {
        # Keep the previous installation as a rollback copy. Renaming the
        # directory avoids writing through potentially damaged file ACLs.
        Move-Item -LiteralPath $target -Destination $backup
        $targetMovedToBackup = $true
    }

    try {
        Move-Item -LiteralPath $staging -Destination $target
    }
    catch {
        if ($targetMovedToBackup -and -not (Test-Path -LiteralPath $target)) {
            Move-Item -LiteralPath $backup -Destination $target
            $targetMovedToBackup = $false
        }
        throw
    }

    if (-not (Test-Path -LiteralPath (Join-Path $target "ApnaWinElevator.exe") -PathType Leaf)) {
        throw "Installation did not produce the elevated helper."
    }

    Write-Output "ApnaWin installed to $target"
    if ($targetMovedToBackup) {
        Write-Output "Previous installation retained for rollback at $backup"
    }
    Write-Output "Launch ApnaWin.exe normally. UAC elevation is requested only for the VPN helper."
}
finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
