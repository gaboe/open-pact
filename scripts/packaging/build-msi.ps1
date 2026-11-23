#Requires -Version 7
# Builds the per-machine client MSI from open-pact-client.wxs, then checks the
# package tables, the properties, and the client that an administrative image
# extracts. The client must print -Version, or the build stops.
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'msi-tools.ps1')

$Exe = (Resolve-Path -LiteralPath $Exe).Path
$Out = [IO.Path]::GetFullPath($Out)
$wxs = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..' '..' 'packaging' 'windows' 'open-pact-client.wxs')).Path
$versionScript = Join-Path $PSScriptRoot 'check-release-version.py'
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'

$printed = (& $Exe --version) -join ' '
if ($LASTEXITCODE -ne 0) { throw "$Exe --version exits with $LASTEXITCODE." }
if ((($printed -split '\s+')[-1]) -ne $Version) { throw "$Exe prints '$printed', expected $Version." }

$upgradeCode = Get-UpgradeCode -Wxs $wxs
$codes = Get-MsiVersionCodes -Version $Version -UpgradeCode $upgradeCode -Script $versionScript

& wix build -arch x64 -d "Exe=$Exe" -d "ProductVersion=$($codes.ProductVersion)" -d "ProductCode=$($codes.ProductCode)" -o $Out $wxs
if ($LASTEXITCODE -ne 0) { throw "wix build exits with $LASTEXITCODE." }

$database = Get-MsiDatabase -Path $Out
foreach ($table in 'CustomAction', 'Binary', 'MsiPatchCertificate', 'LockPermissions', 'MsiLockPermissionsEx') {
    $rows = Get-MsiRows -Database $database -Table $table -Columns '*'
    if ($rows.Count -ne 0) { throw "$Out has $($rows.Count) $table rows; the machine package has none." }
}
$files = Get-MsiRows -Database $database -Table 'File' -Columns 'File'
if ($files.Count -ne 1) { throw "$Out has $($files.Count) File rows, expected 1." }
$secure = Get-MsiRows -Database $database -Table 'Property' -Columns 'Value' -Where " WHERE Property = 'SecureCustomProperties'"
foreach ($row in $secure) {
    foreach ($name in ([string]$row[0]) -split ';') {
        if ($name -ieq 'InstallFolder') { throw "$Out lists InstallFolder in SecureCustomProperties." }
    }
}
$expected = @{ ProductCode = $codes.ProductCode; ProductVersion = $codes.ProductVersion; UpgradeCode = $upgradeCode }
foreach ($name in $expected.Keys) {
    $actual = Get-MsiProperty -Path $Out -Name $name
    if ($actual -ne $expected[$name]) { throw "$Out has $name $actual, expected $($expected[$name])." }
}

$admin = Join-Path ([IO.Path]::GetTempPath()) ('open-pact-admin-' + [guid]::NewGuid().ToString('N'))
& $msiexec /a $Out "TARGETDIR=$admin" /qn
if ($LASTEXITCODE -ne 0) { throw "msiexec /a exits with $LASTEXITCODE." }
$extracted = @(Get-ChildItem -LiteralPath $admin -Recurse -File -Filter 'open-pact-client.exe')
if ($extracted.Count -ne 1) { throw "The administrative image has $($extracted.Count) client executables, expected 1." }
if ((Get-FileHash -LiteralPath $extracted[0].FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash) {
    throw "The administrative image holds a different client than $Exe."
}
Remove-Item -LiteralPath $admin -Recurse -Force
Write-Host "Built ${Out}: ProductVersion $($codes.ProductVersion), ProductCode $($codes.ProductCode)."
