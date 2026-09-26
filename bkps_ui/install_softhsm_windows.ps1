[CmdletBinding()]
param(
    [string]$InstallRoot = "",
    [string]$ConfigRoot = "",
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$ProgressPreference = "SilentlyContinue"

$securityModule = Join-Path $PSHOME "Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1"
if (Test-Path -LiteralPath $securityModule -PathType Leaf) {
    Import-Module $securityModule -ErrorAction Stop
}

# This signed portable package supports the BKPS Windows virtual-eFuse demo.
# It is not a production HSM or a production key-protection boundary.
$SoftHsmVersion = "2.5.0"
$PackageUrl = "https://github.com/disig/SoftHSM2-for-Windows/releases/download/v2.5.0/SoftHSM2-2.5.0-portable.zip"
$PackageSha256 = "85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910"
$SignerThumbprint = "84BABDF3BA22669463DB1CCFA7B1C917462BEE4A"
$SignerName = "CN=Disig a.s."

if (-not $env:LOCALAPPDATA) {
    throw "LOCALAPPDATA is not defined; cannot select a per-user BKPS runtime directory."
}
if (-not $InstallRoot -and $env:BKPS_SOFTHSM_INSTALL_ROOT) {
    $InstallRoot = $env:BKPS_SOFTHSM_INSTALL_ROOT
}
if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA "BKPS\SoftHSM2\runtime-$SoftHsmVersion"
}
if (-not $ConfigRoot -and $env:BKPS_SOFTHSM_CONFIG_ROOT) {
    $ConfigRoot = $env:BKPS_SOFTHSM_CONFIG_ROOT
}
if (-not $ConfigRoot) {
    $ConfigRoot = Join-Path $env:LOCALAPPDATA "BKPS\SoftHSM2"
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$ConfigRoot = [IO.Path]::GetFullPath($ConfigRoot)

$ExpectedSignedFiles = @(
    "bin\softhsm2-dump-file.exe",
    "bin\softhsm2-keyconv.exe",
    "bin\softhsm2-util.exe",
    "lib\softhsm2-x64.dll",
    "lib\softhsm2.dll"
)

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($stream)
        return ([BitConverter]::ToString($digest)).Replace("-", "")
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Assert-SignedRuntime {
    param([Parameter(Mandatory = $true)][string]$Root)

    foreach ($relativePath in $ExpectedSignedFiles) {
        $path = Join-Path $Root $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "SoftHSM runtime is incomplete; missing $path"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "SoftHSM signature validation failed for ${path}: $($signature.Status)"
        }
        if (-not $signature.SignerCertificate) {
            throw "SoftHSM signer certificate is missing for $path"
        }
        $thumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        if ($thumbprint -ne $SignerThumbprint) {
            throw "SoftHSM signer thumbprint mismatch for $path"
        }
        if ($signature.SignerCertificate.Subject -notlike "*$SignerName*") {
            throw "SoftHSM signer identity mismatch for $path"
        }
    }

    $provider = Join-Path $Root "lib\softhsm2-x64.dll"
    $providerBytes = [IO.File]::ReadAllBytes($provider)
    if ($providerBytes.Length -lt 256) {
        throw "SoftHSM x64 provider is not a valid PE image: $provider"
    }
    $peOffset = [BitConverter]::ToInt32($providerBytes, 0x3c)
    $machine = [BitConverter]::ToUInt16($providerBytes, $peOffset + 4)
    if ($machine -ne 0x8664) {
        throw "SoftHSM provider is not an AMD64 DLL: $provider"
    }
}

function Find-Pkcs11Tool {
    $command = Get-Command "pkcs11-tool.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $programRoots = @(
        $env:ProgramW6432,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ } | Select-Object -Unique
    foreach ($root in $programRoots) {
        $candidate = Join-Path $root "OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw "pkcs11-tool.exe was not found. Install OpenSC before SoftHSM validation."
}

function Assert-SafeArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destinationPrefix = [IO.Path]::GetFullPath($DestinationRoot) + [IO.Path]::DirectorySeparatorChar
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $archive.Entries) {
            $candidate = [IO.Path]::GetFullPath((Join-Path $DestinationRoot $entry.FullName))
            if (-not $candidate.StartsWith($destinationPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Unsafe path in SoftHSM archive: $($entry.FullName)"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Ensure-SoftHsmConfig {
    New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null
    $tokensDir = Join-Path $ConfigRoot "tokens"
    New-Item -ItemType Directory -Path $tokensDir -Force | Out-Null
    $configPath = Join-Path $ConfigRoot "softhsm2.conf"
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        $portableTokensDir = $tokensDir.Replace("\", "/")
        $content = @(
            "# SoftHSM v2 configuration file",
            "",
            "directories.tokendir = $portableTokensDir",
            "objectstore.backend = file",
            "log.level = ERROR",
            "slots.removable = false"
        ) -join "`n"
        $utf8NoBom = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($configPath, $content + "`n", $utf8NoBom)
    }
    return $configPath
}

function Assert-RuntimeLoads {
    param([Parameter(Mandatory = $true)][string]$Root)

    $configPath = Ensure-SoftHsmConfig
    $provider = Join-Path $Root "lib\softhsm2-x64.dll"
    $utility = Join-Path $Root "bin\softhsm2-util.exe"
    $pkcs11Tool = Find-Pkcs11Tool
    $previousPath = $env:PATH
    $previousConfig = $env:SOFTHSM2_CONF
    try {
        $env:PATH = (Join-Path $Root "lib") + ";" + (Join-Path $Root "bin") + ";" + $env:PATH
        $env:SOFTHSM2_CONF = $configPath

        $versionOutput = & $utility --version 2>&1
        if ($LASTEXITCODE -ne 0 -or "$versionOutput".Trim() -ne $SoftHsmVersion) {
            throw "softhsm2-util.exe did not report expected version $SoftHsmVersion"
        }

        $savedErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $providerOutput = & $pkcs11Tool --module $provider --show-info 2>&1
            $providerExit = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedErrorAction
        }
        if ($providerExit -ne 0 -or "$providerOutput" -notmatch "Cryptoki version") {
            throw "OpenSC could not initialize the SoftHSM x64 provider: $providerOutput"
        }
    }
    finally {
        $env:PATH = $previousPath
        if ($null -eq $previousConfig) {
            Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
        }
        else {
            $env:SOFTHSM2_CONF = $previousConfig
        }
    }
    return $configPath
}

if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
    Assert-SignedRuntime -Root $InstallRoot
    $configPath = Assert-RuntimeLoads -Root $InstallRoot
    Write-Output "  OK: verified signed SoftHSM $SoftHsmVersion lab runtime"
    Write-Output "BKPS_SOFTHSM_ROOT=$InstallRoot"
    Write-Output "BKPS_SOFTHSM_PROVIDER=$(Join-Path $InstallRoot 'lib\softhsm2-x64.dll')"
    Write-Output "BKPS_SOFTHSM_CONF=$configPath"
    exit 0
}

if ($ValidateOnly) {
    throw "SoftHSM runtime is not installed at $InstallRoot"
}

Write-Output "  INFO: downloading signed SoftHSM $SoftHsmVersion Windows lab runtime"
$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("bkps_softhsm_" + [guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $workRoot "SoftHSM2-$SoftHsmVersion-portable.zip"
$extractRoot = Join-Path $workRoot "extract"
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PackageUrl -OutFile $archivePath -UseBasicParsing
    $actualHash = (Get-Sha256Hex -Path $archivePath).ToUpperInvariant()
    if ($actualHash -ne $PackageSha256) {
        throw "SoftHSM package SHA-256 mismatch; expected $PackageSha256, got $actualHash"
    }

    Assert-SafeArchiveEntries -ArchivePath $archivePath -DestinationRoot $extractRoot
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
    $payloadRoot = Join-Path $extractRoot "SoftHSM2"
    Assert-SignedRuntime -Root $payloadRoot

    $installParent = Split-Path -Parent $InstallRoot
    New-Item -ItemType Directory -Path $installParent -Force | Out-Null
    if (Test-Path -LiteralPath $InstallRoot) {
        throw "Refusing to overwrite unexpected SoftHSM path: $InstallRoot"
    }
    Move-Item -LiteralPath $payloadRoot -Destination $InstallRoot
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        $resolvedWork = [IO.Path]::GetFullPath($workRoot)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if ($resolvedWork.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedWork -Recurse -Force
        }
    }
}

Assert-SignedRuntime -Root $InstallRoot
$configPath = Assert-RuntimeLoads -Root $InstallRoot
Write-Output "  OK: installed and validated signed SoftHSM $SoftHsmVersion lab runtime"
Write-Output "BKPS_SOFTHSM_ROOT=$InstallRoot"
Write-Output "BKPS_SOFTHSM_PROVIDER=$(Join-Path $InstallRoot 'lib\softhsm2-x64.dll')"
Write-Output "BKPS_SOFTHSM_CONF=$configPath"
