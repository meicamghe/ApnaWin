[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Destination,
    [string] $UdpqClientPath,
    [string] $UdpqPatchPath
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$XrayVersion = "26.11.9"
$XrayArchiveUrl = "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-windows-64.zip"
$XrayArchiveSha256 = "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d"
$WintunVersion = "0.14.1"
$WintunArchiveUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$WintunArchiveSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$UdpqRedactionPatchSha256 = "6f18ca9871e62ad91db033411d0aaa801bde3b17533d4ce71e20ed33fe01bbe2"

function Assert-Sha256([string] $Path, [string] $Expected, [string] $Name) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "$Name archive SHA-256 mismatch: $actual"
    }
}

function Assert-PeX64([string] $Path, [string] $Name) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "$Name is not a PE image"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt 1048576 -or $peOffset + 6 -gt $stream.Length) {
            throw "$Name has an invalid PE header offset"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "$Name has an invalid PE signature"
        }
        if ($reader.ReadUInt16() -ne 0x8664) {
            throw "$Name must be an AMD64 Windows binary"
        }
    }
    finally {
        $stream.Dispose()
    }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("ApnaWin-runtime-" + [Guid]::NewGuid().ToString("N"))
$xrayZip = Join-Path $work "xray.zip"
$wintunZip = Join-Path $work "wintun.zip"
$xrayExtract = Join-Path $work "xray"
$wintunExtract = Join-Path $work "wintun"
$engine = [System.IO.Path]::GetFullPath($Destination)

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    New-Item -ItemType Directory -Path $engine -Force | Out-Null

    Invoke-WebRequest -Uri $XrayArchiveUrl -OutFile $xrayZip
    Assert-Sha256 $xrayZip $XrayArchiveSha256 "Xray"
    Expand-Archive -LiteralPath $xrayZip -DestinationPath $xrayExtract -Force

    Invoke-WebRequest -Uri $WintunArchiveUrl -OutFile $wintunZip
    Assert-Sha256 $wintunZip $WintunArchiveSha256 "Wintun"
    Expand-Archive -LiteralPath $wintunZip -DestinationPath $wintunExtract -Force

    $xrayExe = Join-Path $xrayExtract "xray.exe"
    $wintunDll = Join-Path $wintunExtract "wintun\bin\amd64\wintun.dll"
    $xrayLicense = Join-Path $xrayExtract "LICENSE"
    $wintunLicense = Join-Path $wintunExtract "wintun\LICENSE.txt"
    foreach ($required in @($xrayExe, $wintunDll, $xrayLicense, $wintunLicense)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required runtime file is missing from a verified archive: $required"
        }
    }

    Assert-PeX64 $xrayExe "xray.exe"
    Assert-PeX64 $wintunDll "wintun.dll"

    $signature = Get-AuthenticodeSignature -FilePath $wintunDll
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Wintun DLL Authenticode signature is not valid: $($signature.Status)"
    }
    if ($signature.SignerCertificate.Subject -notmatch "WireGuard") {
        throw "Wintun DLL signer is not the expected WireGuard publisher"
    }

    Copy-Item -LiteralPath $xrayExe -Destination (Join-Path $engine "xray.exe") -Force
    Copy-Item -LiteralPath $wintunDll -Destination (Join-Path $engine "wintun.dll") -Force
    Copy-Item -LiteralPath $xrayLicense -Destination (Join-Path $engine "LICENSE-Xray.txt") -Force
    Copy-Item -LiteralPath $wintunLicense -Destination (Join-Path $engine "LICENSE-Wintun.txt") -Force

    foreach ($dataFile in @("geoip.dat", "geosite.dat")) {
        $source = Join-Path $xrayExtract $dataFile
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $engine $dataFile) -Force
        }
    }

    $versionOutput = (& (Join-Path $engine "xray.exe") version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch [regex]::Escape($XrayVersion)) {
        throw "Xray version check failed; expected $XrayVersion"
    }

    $manifest = [ordered]@{
        schema_version = 1
        xray = [ordered]@{
            version = $XrayVersion
            archive_sha256 = $XrayArchiveSha256
            executable_sha256 = (Get-FileHash -LiteralPath (Join-Path $engine "xray.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        wintun = [ordered]@{
            version = $WintunVersion
            archive_sha256 = $WintunArchiveSha256
            dll_sha256 = (Get-FileHash -LiteralPath (Join-Path $engine "wintun.dll") -Algorithm SHA256).Hash.ToLowerInvariant()
            signer = $signature.SignerCertificate.Subject
        }
    }
    if ($UdpqClientPath) {
        $udpqSource = [System.IO.Path]::GetFullPath($UdpqClientPath)
        if (-not (Test-Path -LiteralPath $udpqSource -PathType Leaf)) {
            throw "UDPQ client binary does not exist: $udpqSource"
        }
        if (-not $UdpqPatchPath -or -not (Test-Path -LiteralPath $UdpqPatchPath -PathType Leaf)) {
            throw "The UDPQ source patch file is required to record build provenance."
        }
        $patchHash = (Get-FileHash -LiteralPath $UdpqPatchPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($patchHash -ne $UdpqRedactionPatchSha256) {
            throw "UDPQ client source patch SHA-256 does not match the reviewed credential-redaction patch."
        }
        Assert-PeX64 $udpqSource "udpq-client.exe"
        $udpqTarget = Join-Path $engine "udpq-client.exe"
        Copy-Item -LiteralPath $udpqSource -Destination $udpqTarget -Force
        $manifest["udpq"] = [ordered]@{
            source = "starrising321/starudp"
            source_commit = "23fa29bb4fad600330b30e2b703b8029ef091446"
            license = "MIT"
            patch_sha256 = $patchHash
            executable_sha256 = (Get-FileHash -LiteralPath $udpqTarget -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText(
        (Join-Path $engine "runtime-manifest.json"),
        $manifestJson,
        $utf8NoBom
    )
    Write-Output "Verified Xray $XrayVersion and Wintun $WintunVersion in $engine"
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
