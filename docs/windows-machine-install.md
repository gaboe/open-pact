# Windows machine install

This page is for IT. It shows how to install the open-pact client for every user of a Windows device. The SYSTEM scheduled job needs this install.

## What the package installs

The package installs the client in the 64-bit Program Files folder. By default this is `C:\Program Files\open-pact-client\open-pact-client.exe`. This file is the machine client. The SYSTEM job runs only this file. The package does not copy the file to another folder.

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

The block installs exactly version 0.9.0. It upgrades an older package. It does not change a newer package. It checks the Cosign signature and the SHA-256 hash of the package before it installs. It keeps its folder, because Windows Installer repairs from it. Each failed check stops the block. Exit code 3010 means that Windows needs a restart to finish the install. Then do the next section.

To repair a package of the same version, run these commands in an elevated Windows PowerShell 5.1 prompt. Write the full path of the verified MSI between `@'` and `'@`. The block leaves that MSI in its folder under `%ProgramData%`. The commands wait for `msiexec` and stop when it fails.

```powershell
$msi = @'
<the full path of the verified MSI>
'@
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$repair = Start-Process -FilePath $msiexec -ArgumentList ('/fa "' + $msi + '" /qn /norestart') -Wait -PassThru
if ($repair.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the repair.' }
elseif ($repair.ExitCode -ne 0) { throw ('The repair failed. Exit code: ' + $repair.ExitCode) }
```

## Choose a deployment method

- **Intune line-of-business app.** Upload the MSI and assign it to devices. Follow Microsoft's line-of-business page for updates. This method is not verified on an enrolled device yet.
- **Intune Win32 app.** Detect the install by the ProductCode of the MSI. Treat exit code 3010 as a soft reboot.
- **Group Policy.** Assign the MSI to the computer, not to a user.
- **winget.** Do not use the `winget` command-line tool as SYSTEM. Microsoft does not support it there, even when Intune or Group Policy starts it. Deploy the verified MSI with one of the methods above.
- **Rollback.** Keep Windows Installer rollback on. The package removes the old version inside the new install, so a failed upgrade returns to the old version. A policy that disables rollback removes this protection.

## Start the SYSTEM job for each home

After the package is installed, run these commands once for each user home. Run them in an elevated Windows PowerShell 5.1 prompt. They resolve the client by its full path, so an older client on PATH never runs. They stop when the client file is missing or when the command fails.

1. Replace the line `<the absolute client home>` with the absolute client home of the user.
2. Replace the line `<the profile folder of the user>` with the profile folder of the user, for example `C:\Users\example`.
3. Keep each value on its own line, between `@'` and `'@`. Do not add quotes. A path with an apostrophe then needs no escape.

```powershell
$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
$userHome = @'
<the profile folder of the user>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule on --system --user-home $userHome
if ($LASTEXITCODE -ne 0) { throw 'schedule on failed. Fix the error, then run this command again.' }
```

The SYSTEM job reads the repositories below that profile. Without `--user-home`, the client uses the profile that the existing SYSTEM task of this home names. It uses that profile only when the machine client owns the task and the profile is valid. When the machine client owns the task but the profile is not valid, it uses the registered profile of the account that runs the elevated prompt. A task that another program owns blocks the install. The client fails when it finds no profile.

For a device that ran a SYSTEM job before 0.9.0, take both values from the old task. The [release notes](release-notes/v0.9.0.md) show how.

## Remove the package

Run every command in an elevated Windows PowerShell 5.1 prompt. Uninstalling the package does not remove SYSTEM tasks. Remove each task first.

1. List the SYSTEM tasks. The command selects tasks by their principal and by the program that they run. It never selects a limited user task by the name prefix alone. Write down the task name, the number of actions, the program and the `--home` value of each task:

```powershell
& {
  $legacy = Join-Path $env:ProgramW6432 'open-pact\open-pact-client.exe'
  $machine = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
  $system = @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')
  $programs = @($legacy, $machine)
  Get-ScheduledTask -TaskPath '\' | Where-Object {
    $_.TaskName -like 'org.open-pact.report.*' -and
    ($system -contains $_.Principal.UserId) -and
    @($_.Actions | Where-Object { $_.Execute -and ($programs -contains ($_.Execute.Trim('"') -replace '^\\\\\?\\', '')) }).Count -gt 0
  } | ForEach-Object {
    'Task: ' + $_.TaskName
    'Actions: ' + @($_.Actions).Count
    'Program: ' + (($_.Actions | ForEach-Object { $_.Execute }) -join ' ')
    'Arguments: ' + (($_.Actions | ForEach-Object { $_.Arguments }) -join ' ')
  }
}
```

2. A task whose program is the machine client, `open-pact-client\open-pact-client.exe`, needs one command. It removes the task, the job state, and the applied-settings receipt. It saves automatic sending as off in an existing client home. It clears a pending SYSTEM choice. The command stops when the client file is missing or when `schedule off` fails.
   - Replace the line `<the absolute client home>` with the `--home` value of the task.
   - Keep the value on its own line, between `@'` and `'@`. Do not add quotes.

```powershell
$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule off
if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this command again.' }
```

   A task whose Actions line is not 1 is not a task of the client. `schedule off` refuses such a task. Open it in Task Scheduler and read every action. When you know each action, remove the task in Task Scheduler.

3. A task whose program is the old copy, `open-pact\open-pact-client.exe`, and whose Actions line is 1, needs the removal block. The list can show the program with a `\\?\` prefix. It is the same file. Replace two samples in the block:
   - The task name `org.open-pact.report.0123456789abcdef`, in every place where it appears.
   - The home line `C:\Users\example\pact`, between `@'` and `'@`. Use the `--home` value of the task. Do not add quotes.

   The block deletes the task. It then checks that the machine client exists and runs `schedule off`. When the file is missing or `schedule off` fails, the block throws. Do not uninstall the package then. Fix the error and run the block again.

```powershell
& {
  $schtasks = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
  function Test-TaskRegistered {
    # The Task Scheduler COM API reports a missing task as HRESULT 0x80070002, in every display language.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    try {
      [void]$service.GetFolder('\').GetTask('\org.open-pact.report.0123456789abcdef')
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
    & $schtasks /End /TN 'org.open-pact.report.0123456789abcdef' 2>$null | Out-Null
  }
  if (Test-TaskRegistered) {
    End-TaskQuietly
    & $schtasks /Delete /TN 'org.open-pact.report.0123456789abcdef' /F
    if ($LASTEXITCODE -ne 0) { throw 'The task was not removed. Run this block again from an elevated prompt.' }
  }
  if (Test-TaskRegistered) { throw 'The task is still registered. Run this block again.' }
  $q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
  if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this block again.' }
  $clientHome = @'
C:\Users\example\pact
'@
  $global:LASTEXITCODE = $null
  & $q --home $clientHome schedule off
  if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this block again.' }
}
```

4. Run the command of step 1 again. It must print nothing.
5. Uninstall the open-pact client package. Use Settings, Apps, or your deployment tool.

The command of step 1 lists only tasks that run as SYSTEM and run the old copy or the machine client. A SYSTEM task that runs another program can come from an older open-pact client. The client does not change it.

## Remove a task without the package

Use this section when the machine client is not installed, or when a task has more than one action. The block uses Windows tools only.

1. Open the task in Task Scheduler.
2. Read every action of the task.
3. Replace the task name `org.open-pact.report.0123456789abcdef` in every place where it appears in the block below.
4. Run the block below in an elevated Windows PowerShell 5.1 prompt, only when you know each action.

The block deletes the task name that you give it. It does not check the program. It has no home line, because the machine client does not run.

```powershell
& {
  $schtasks = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
  function Test-TaskRegistered {
    # The Task Scheduler COM API reports a missing task as HRESULT 0x80070002, in every display language.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    try {
      [void]$service.GetFolder('\').GetTask('\org.open-pact.report.0123456789abcdef')
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
    & $schtasks /End /TN 'org.open-pact.report.0123456789abcdef' 2>$null | Out-Null
  }
  if (Test-TaskRegistered) {
    End-TaskQuietly
    & $schtasks /Delete /TN 'org.open-pact.report.0123456789abcdef' /F
    if ($LASTEXITCODE -ne 0) { throw 'The task was not removed. Run this block again from an elevated prompt.' }
  }
  if (Test-TaskRegistered) { throw 'The task is still registered. Run this block again.' }
}
```

The block leaves the state folder in `%ProgramData%\open-pact\system`. The next `schedule on --system` writes new job state in that folder and sets its permissions again.
