# Windows machine install

This page is for IT. It shows how to install the open-pact client for every user of a Windows device. The SYSTEM scheduled job needs this install.

## What the package installs

The package installs the client at `C:\Program Files\open-pact-client\open-pact-client.exe` on 64-bit Windows. This file is the machine client. The SYSTEM job runs only this file. The package does not copy the file to another folder.

## Install with the block

Run this block in an elevated Windows PowerShell 5.1 prompt (`powershell.exe`). Do not use `pwsh`.

```powershell
& {
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this block in Windows PowerShell 5.1: start powershell.exe as administrator, not pwsh.' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = 'Stop'
function AssertProtected($path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected path is a reparse point' }
    $acl = if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($path) } else { [IO.File]::GetAccessControl($path) }
    $allowed = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw 'Protected path has a non-admin owner' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band 0xD0156) -and $allowed -notcontains $rule.IdentityReference.Value) {
            throw 'Protected path ACL grants write or modify to a non-admin principal'
        }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this block from an elevated Windows PowerShell 5.1 prompt (powershell.exe).' }
$base = 'https://github.com/gaboe/open-pact/releases/download/v0.9.0'
$msiName = 'open-pact-client-x86_64-pc-windows-msvc.msi'
$folder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('open-pact-install-' + [guid]::NewGuid())
if (Test-Path -LiteralPath $folder) { throw 'The install folder exists. Run this block again.' }
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true, $false)
$security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $account = New-Object Security.Principal.SecurityIdentifier($sid)
    $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[void][IO.Directory]::CreateDirectory($folder, $security)
AssertProtected $folder
foreach ($name in @($msiName, 'SHA256SUMS', 'SHA256SUMS.sigstore.json')) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $folder $name)
}
$cosign = Join-Path $folder 'cosign.exe'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-windows-amd64.exe' -OutFile $cosign
if ((Get-FileHash -LiteralPath $cosign -Algorithm SHA256).Hash -ne '9b85a88ebff2d9dd30ff4984a6f61f2cedc232dd87d81fa7f2ff3c0ed96c241c') { throw 'cosign.exe does not match its pinned hash.' }
$sums = Join-Path $folder 'SHA256SUMS'
& $cosign verify-blob --bundle (Join-Path $folder 'SHA256SUMS.sigstore.json') --certificate-identity 'https://github.com/gaboe/open-pact/.github/workflows/client-release.yml@refs/tags/v0.9.0' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' $sums
if ($LASTEXITCODE -ne 0) { throw 'Cosign could not verify SHA256SUMS.' }
$lines = @(Get-Content -LiteralPath $sums | Where-Object { $_ -match '\S' -and (($_ -split '\s+', 2)[1].TrimStart('*') -eq $msiName) })
if ($lines.Count -ne 1) { throw 'SHA256SUMS must list the package once.' }
$msi = Join-Path $folder $msiName
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne ($lines[0] -split '\s+')[0]) { throw 'The package does not match SHA256SUMS.' }
$log = Join-Path $folder 'install.log'
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$install = Start-Process -FilePath $msiexec -ArgumentList ('/i "' + $msi + '" /qn /norestart /l*v "' + $log + '"') -Wait -PassThru
Write-Output ('msiexec exit code: ' + $install.ExitCode)
if ($install.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the install.' }
elseif ($install.ExitCode -ne 0) { throw ('The install failed. See ' + $log) }
}
```

The block installs, upgrades and reinstalls the package. It checks the Cosign signature and the SHA-256 hash of the package before it installs. It keeps its folder, because Windows Installer repairs from it. Each failed check stops the block. Exit code 3010 means that Windows needs a restart to finish the install.

## Choose a deployment method

- **Intune line-of-business app.** Upload the MSI and assign it to devices. Follow Microsoft's line-of-business page for updates. This method is not verified on an enrolled device yet.
- **Intune Win32 app.** Detect the install by the ProductCode of the MSI. Treat exit code 3010 as a soft reboot.
- **Group Policy.** Assign the MSI to the computer, not to a user.
- **winget.** A release names winget only after the package is published there. Winget runs in a user session download the package into that user's temp folder first. Use the install block in a user session. Use winget as SYSTEM only through Intune, Group Policy or another SYSTEM tool.
- **Rollback.** Keep Windows Installer rollback on. The package removes the old version inside the new install, so a failed upgrade returns to the old version. A policy that disables rollback removes this protection.

## Start the SYSTEM job for each home

After the package is installed, run this command once for each user home. Run it in an elevated prompt:

```powershell
& 'C:\Program Files\open-pact-client\open-pact-client.exe' --home '<home>' schedule on --system
```

Replace `<home>` with the absolute home path of the user. The command reads the profile of that user from the device.

## Remove the package

1. For each SYSTEM task, run the removal block in an elevated Windows PowerShell 5.1 prompt. Find the task names with `schtasks.exe /Query /FO CSV /NH`. Lines that start with `"\org.open-pact.report.` name the tasks. Change the task name in the block to each name that you found.

```powershell
& {
  $schtasks = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
  function Test-TaskRegistered {
    # The Task Scheduler COM API reports a missing task as HRESULT 0x80070002, in every display language.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    try {
      [void]$service.GetFolder('\').GetTask('\org.open-pact.report.0123abcd')
      return $true
    } catch {
      $e = $_.Exception
      while ($e.InnerException) { $e = $e.InnerException }
      if ($e.HResult -eq -2147024894) { return $false }
      throw ('Could not query the task. ' + $_)
    }
  }
  function End-TaskQuietly {
    # /End fails for a task that is not running. That does not matter here: /Delete decides.
    $ErrorActionPreference = 'Continue'
    & $schtasks /End /TN 'org.open-pact.report.0123abcd' 2>$null | Out-Null
  }
  if (Test-TaskRegistered) {
    End-TaskQuietly
    & $schtasks /Delete /TN 'org.open-pact.report.0123abcd' /F
    if ($LASTEXITCODE -ne 0) { throw 'The task was not removed. Run this block again from an elevated prompt.' }
  }
  if (Test-TaskRegistered) { throw 'The task is still registered. Run this block again.' }
  & 'C:\Program Files\open-pact-client\open-pact-client.exe' --home 'C:\Users\example\pact' schedule off
}
```

2. Uninstall the open-pact client package. Use Settings, Apps, or your deployment tool.

Uninstalling the package does not remove the SYSTEM tasks. Run step 1 before step 2.

A task that runs another program was not made by the client. The client does not change it. The removal block deletes any task with the name that you give it. Check the action of the task in Task Scheduler before you run the block for it.
