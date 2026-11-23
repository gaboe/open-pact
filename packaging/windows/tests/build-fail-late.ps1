#Requires -Version 7
# Builds the failing fixture, fixture-fail-late.msi, from fail-late.wxs. It skips
# the table checks of build-msi.ps1 on purpose: the fixture has one deferred
# custom action that fails the install after the file copy.
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$scripts = Join-Path $PSScriptRoot '..' '..' '..' 'scripts' 'packaging'
. (Join-Path $scripts 'msi-tools.ps1')

$Exe = (Resolve-Path -LiteralPath $Exe).Path
$wxs = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'fail-late.wxs')).Path
$versionScript = Join-Path $scripts 'check-release-version.py'

$printed = (& $Exe --version) -join ' '
if ($LASTEXITCODE -ne 0) { throw "$Exe --version exits with $LASTEXITCODE." }
if ((($printed -split '\s+')[-1]) -ne $Version) { throw "$Exe prints '$printed', expected $Version." }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path (Resolve-Path -LiteralPath $OutDir).Path 'fixture-fail-late.msi'
$upgradeCode = Get-UpgradeCode -Wxs $wxs
$codes = Get-MsiVersionCodes -Version $Version -UpgradeCode $upgradeCode -Script $versionScript

& wix build -arch x64 -d "Exe=$Exe" -d "ProductVersion=$($codes.ProductVersion)" -d "ProductCode=$($codes.ProductCode)" -o $out $wxs
if ($LASTEXITCODE -ne 0) { throw "wix build exits with $LASTEXITCODE." }
Write-Host "Built $out for the failing install."
