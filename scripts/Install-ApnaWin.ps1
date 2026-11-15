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
if (-not (Test-Path -LiteralPath (Join-Path $source "engine\xray.exe") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $source "engine\wintun.dll") -PathType Leaf)) {
    throw "The verified Xray/Wintun runtime folder is missing."
}

$sourcePrefix = $source.TrimEnd('\') + '\'
if ($source.StartsWith($target.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $target.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Source and destination folders must not contain one another."
}

New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $target -Recurse -Force

# Program Files is the trust boundary for the UAC helper. Standard users can
# read and execute the installed files but cannot replace the elevated helper.
& icacls.exe $target /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not apply the protected Program Files ACL to $target"
}

if (-not (Test-Path -LiteralPath (Join-Path $target "ApnaWinElevator.exe") -PathType Leaf)) {
    throw "Installation did not produce the elevated helper."
}
Write-Output "ApnaWin installed to $target"
Write-Output "Launch ApnaWin.exe normally. UAC elevation is requested only for the VPN helper."
