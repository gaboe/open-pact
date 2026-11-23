#Requires -Version 7
# Installs WiX Toolset 5.0.2 (MS-RL) as a dotnet tool. The package comes from
# nuget.org and is checked against a pinned SHA-256 before it is installed. The
# install reads only that one package, from a feed that holds nothing else.
$ErrorActionPreference = 'Stop'

$version = '5.0.2'
$sha256 = 'f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173'

$work = Join-Path ([IO.Path]::GetTempPath()) ('wix-' + [guid]::NewGuid().ToString('N'))
$feed = Join-Path $work 'feed'
New-Item -ItemType Directory -Force -Path $feed | Out-Null
$package = Join-Path $feed "wix.$version.nupkg"
Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/wix/$version" -OutFile $package -UseBasicParsing

$actual = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $sha256) { throw "The WiX $version package hashes to $actual, expected $sha256." }

$config = Join-Path $work 'nuget.config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$feed" />
  </packageSources>
</configuration>
"@ | Set-Content -LiteralPath $config -Encoding ascii

$env:NUGET_PACKAGES = Join-Path $work 'packages'
& dotnet tool install --global wix --version $version --configfile $config
if ($LASTEXITCODE -ne 0) { throw "dotnet tool install wix exits with $LASTEXITCODE." }

$reported = (& wix --version) -join ' '
if ($LASTEXITCODE -ne 0 -or -not $reported.StartsWith($version)) { throw "wix --version prints '$reported', expected $version." }
Write-Host "Installed WiX $version."
