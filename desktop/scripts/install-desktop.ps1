# Install or update the open-pact desktop apps on Windows without scoop.
#
#   irm https://raw.githubusercontent.com/gaboe/open-pact/vX.Y.Z/desktop/scripts/install-desktop.ps1 | iex
#
# vX.Y.Z is the tag of the release to install. The script of a tag installs the latest release, or
# the release named in $env:OPEN_PACT_DESKTOP_VERSION.
#
# The apps are unsigned unless the release was built with Azure Artifact Signing, so Windows SmartScreen may warn the first time. The zip is checked
# against its line in the SHA256SUMS file of the same release before anything is replaced. The
# release signs SHA256SUMS with Cosign (see docs/client.md, "Verify a release").
#
# Run the same line again to update. Set $env:OPEN_PACT_DESKTOP_VERSION = '0.8.0' to install one
# version, $env:OPEN_PACT_INSTALL_DIR to change the folder (default
# %LOCALAPPDATA%\open-pact-desktop), and $env:OPEN_PACT_NO_OPEN = '1' to skip opening the client.
# With scoop, use 'scoop install open-pact-desktop' and 'scoop update open-pact-desktop' instead.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Fail($message) { throw "open-pact: $message" }

$repo = if ($env:OPEN_PACT_REPOSITORY) { $env:OPEN_PACT_REPOSITORY } else { 'gaboe/open-pact' }
$dir = if ($env:OPEN_PACT_INSTALL_DIR) { $env:OPEN_PACT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'open-pact-desktop' }
$apps = @('open-pact', 'open-pact-admin')

if ($env:OPEN_PACT_DESKTOP_VERSION) {
  $api = "https://api.github.com/repos/$repo/releases/tags/v$($env:OPEN_PACT_DESKTOP_VERSION)"
} else {
  $api = "https://api.github.com/repos/$repo/releases/latest"
}
try { $release = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'open-pact-installer' } }
catch { Fail "no such release on GitHub: $(if ($env:OPEN_PACT_DESKTOP_VERSION) { $env:OPEN_PACT_DESKTOP_VERSION } else { 'latest' })." }
$asset = $release.assets | Where-Object { $_.name -match '^open-pact-desktop-[^/]+-windows-x64\.zip$' } | Select-Object -First 1
if (-not $asset) { Fail 'the release has no desktop apps for Windows.' }

$work = Join-Path ([IO.Path]::GetTempPath()) ("open-pact-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $zip = Join-Path $work $asset.name
  Write-Host "Downloading $($asset.name)"
  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
  try { $sums = (Invoke-WebRequest -Uri ($asset.browser_download_url -replace '/[^/]+$', '/SHA256SUMS') -UseBasicParsing).Content }
  catch { Fail 'the release has no SHA256SUMS file.' }
  $sumsText = if ($sums -is [byte[]]) { [Text.Encoding]::UTF8.GetString($sums) } else { [string]$sums }
  $want = $null
  foreach ($line in ($sumsText -split '\r?\n')) {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $asset.name) { $want = $parts[0].ToLowerInvariant() }
  }
  $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
  if (-not $want -or $want -ne $got) { Fail 'the download does not match its checksum. Nothing was installed.' }
  Write-Host 'Checksum matches.'

  $staged = Join-Path $work 'app'
  Expand-Archive -Path $zip -DestinationPath $staged
  foreach ($file in @('open-pact.exe', 'open-pact-admin.exe', 'open-pact-client.exe')) {
    if (-not (Test-Path (Join-Path $staged $file))) { Fail "the archive has no $file." }
  }

  $target = [IO.Path]::GetFullPath($dir).TrimEnd('\')
  foreach ($app in $apps) {
    $running = Get-Process -Name $app -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([IO.Path]::GetDirectoryName($_.Path).TrimEnd('\') -ieq $target) }
    if ($running) {
      Write-Host "Closing the running $app"
      $running | Stop-Process -Force
      $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }
  }

  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Get-ChildItem -Path $staged -File | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination (Join-Path $dir $_.Name) -Force
  }

  $menu = Join-Path ([Environment]::GetFolderPath('Programs')) 'open-pact'
  New-Item -ItemType Directory -Path $menu -Force | Out-Null
  $shell = New-Object -ComObject WScript.Shell
  foreach ($pair in @(@('open-pact', 'open-pact.exe'), @('open-pact admin', 'open-pact-admin.exe'))) {
    $link = $shell.CreateShortcut((Join-Path $menu "$($pair[0]).lnk"))
    $link.TargetPath = Join-Path $dir $pair[1]
    $link.WorkingDirectory = $dir
    $link.Save()
  }
  Write-Host "Installed in $dir. Start menu: open-pact, open-pact admin."
  if (-not $env:OPEN_PACT_NO_OPEN) { Start-Process -FilePath (Join-Path $dir 'open-pact.exe') }
} finally {
  Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
