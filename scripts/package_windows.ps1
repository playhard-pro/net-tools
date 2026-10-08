# Build the Windows distribution archive.
#
# Windows is distributed as a plain zip (executable + license texts) instead of
# a standard installer: the executable performs raw-socket network probing and
# is meant to be started with administrator rights, which packaged installers
# cannot request. The archive keeps every file at its root so that it can be
# extracted and run directly.
#
# Usage:
#     pwsh scripts/package_windows.ps1 -Arch x64
#     pwsh scripts/package_windows.ps1 -Arch arm64

[CmdletBinding()]
param(
    # Target architecture of the already built executable. It is only used in
    # the archive name; the binary must have been built for this architecture.
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string]$Arch,

    # Directory that receives the generated zip.
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

# Resolve the repository root from this script's location.
$root = Split-Path -Parent $PSScriptRoot

# Read the workspace version. The first line that starts with `version = "..."`
# belongs to `[workspace.package]`; member crates use `version.workspace`.
$versionMatch = Select-String -Path (Join-Path $root "Cargo.toml") `
    -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $versionMatch) {
    throw "could not read the workspace version from Cargo.toml"
}
$version = $versionMatch.Matches[0].Groups[1].Value

# Assemble the archive contents in a staging directory. Only files that are
# explicitly copied end up in the archive.
$staging = Join-Path $root "target/windows-package-$Arch"
New-Item -ItemType Directory -Force -Path $staging | Out-Null

Copy-Item -Force (Join-Path $root "target/release/net-tools.exe") `
    (Join-Path $staging "net-tools.exe")

$licenseFiles = @(
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD_PARTY_LICENSES.md",
    "assets/fonts/LICENSE-wqy-microhei.txt",
    "assets/fonts/APACHE-2.0.txt"
)
foreach ($relative in $licenseFiles) {
    $leaf = Split-Path -Leaf $relative
    Copy-Item -Force (Join-Path $root $relative) (Join-Path $staging $leaf)
}

$outputDirectory = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$archive = Join-Path $outputDirectory "net-tools_${version}_windows_${Arch}.zip"
Compress-Archive -Force -Path (Join-Path $staging "*") -DestinationPath $archive

Write-Host "wrote $archive"
