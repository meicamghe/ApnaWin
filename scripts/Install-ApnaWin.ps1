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
    -not (Test-Path -LiteralPath (Join-Path $engine "runtime-manifest.json") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $engine "udpq-client.exe") -PathType Leaf)) {
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

    # Normalize every object first, then let the secured root ACL inherit
    # consistently. This repairs empty/broken file DACLs instead of merely
    # setting permissions on the top-level directory.
    & icacls.exe $Path /reset /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not reset inherited ACLs in $Path"
    }
    & icacls.exe $Path /inheritance:e /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enable ACL inheritance in $Path"
    }
    & icacls.exe $Path /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" /T /C | Out-Null
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
        "engine/runtime-manifest.json",
        "engine/udpq-client.exe"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $staging $required) -PathType Leaf)) {
            throw "Staged installation is missing required file: $required"
        }
    }

    $manifestPath = Join-Path $staging "engine/runtime-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $expectedUdpqHash = [string]$manifest.udpq.executable_sha256
    if ($expectedUdpqHash -notmatch "^[0-9a-fA-F]{64}$") {
        throw "Runtime manifest has no valid UDPQ executable SHA-256."
    }
    $actualUdpqHash = (Get-FileHash -LiteralPath (Join-Path $staging "engine/udpq-client.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualUdpqHash -ne $expectedUdpqHash.ToLowerInvariant()) {
        throw "Staged UDPQ executable does not match the runtime manifest."
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
        # Re-apply and verify the ACL on the final path as well. Some extraction
        # and move combinations preserve unexpected child DACLs.
        Set-ApnaWinInstallAcl -Path $target
    }
    catch {
        if (Test-Path -LiteralPath $target -PathType Container) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
        if ($targetMovedToBackup -and (Test-Path -LiteralPath $backup -PathType Container)) {
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
