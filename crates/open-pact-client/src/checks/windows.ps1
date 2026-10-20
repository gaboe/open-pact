
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
function Emit($key, $value) { if ($null -eq $value) { $value = '' }; Write-Output "$key`t$value" }
function RunSection([scriptblock]$work) { & $work }
function RegValue($path, $name) {
    try {
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        if ($null -eq $item.PSObject.Properties[$name]) { return '' }
        return [string]$item.$name
    } catch { return '!' }
}
function PolicyValue($path, $name) {
    try {
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return '' }
        return RegValue $path $name
    } catch { return '!' }
}
function ScreenUserRoots($isSystem) {
    if (-not $isSystem) { return 'HKCU:' }
    $sessions = @(Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10 OR LogonType=11' -ErrorAction Stop)
    $sids = @(foreach ($session in $sessions) {
        Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ResultClassName Win32_Account -ErrorAction Stop | ForEach-Object {
            if ($_.SID -match '^S-1-(5-21|12-1)-') { $_.SID }
        }
    }) | Sort-Object -Unique
    if (@($sids).Count -eq 0) { throw 'No interactive user' }
    foreach ($sid in $sids) { 'Registry::HKEY_USERS\' + $sid }
}
function UserScreenSaver($userRoot) {
    $local = $userRoot + '\Control Panel\Desktop'
    $policy = $userRoot + '\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $values = @{}
    foreach ($name in @('ScreenSaveActive','ScreenSaverIsSecure','ScreenSaveTimeOut','SCRNSAVE.EXE')) {
        $value = PolicyValue $policy $name
        if ($value -eq '') { $value = RegValue $local $name }
        $values[$name] = $value
    }
    $exe = $values['SCRNSAVE.EXE']
    $valid = 'unknown'
    if ($exe -ne '' -and $exe -ne '!') {
        $exe = $exe.Trim('"')
        $exe = $exe -replace '(?i)%windir%|%systemroot%', $env:windir
        if ($exe -notmatch '%' -and [IO.Path]::GetExtension($exe) -eq '.scr') {
            if (-not [IO.Path]::IsPathRooted($exe)) { $exe = Join-Path $env:windir ('System32\' + $exe) }
            try {
                if (Test-Path -LiteralPath $exe -PathType Leaf -ErrorAction Stop) { $valid = 'valid' } else { $valid = 'missing' }
            } catch {}
        }
    }
    return (@($values['ScreenSaveActive'], $values['ScreenSaverIsSecure'], $values['ScreenSaveTimeOut'], $valid) -join '|')
}
RunSection {
    try { $bitlocker = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection'); Emit 'bitlocker' $bitlocker } catch { Emit 'bitlocker' '' }
}
RunSection {
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name)
        if ($profiles.Count -eq 3) { Emit 'firewall' (($profiles | ForEach-Object { $_.Enabled.ToString() }) -join ' ') } else { Emit 'firewall' '' }
    } catch { Emit 'firewall' '' }
}
RunSection {
    try {
        $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop)
        if ($products.Count -gt 0) { Emit 'antimalware' (($products | ForEach-Object { $_.productState }) -join ' ') }
        else { throw 'No Security Center products' }
    } catch {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            if ($null -ne $status.AntivirusEnabled -and $null -ne $status.RealTimeProtectionEnabled) {
                if ($status.AMRunningMode -eq 'Normal' -and $status.AntivirusEnabled -and $status.RealTimeProtectionEnabled) { Emit 'antimalware' 'defender=yes' }
                else { Emit 'antimalware' '' }
            } else { Emit 'antimalware' '' }
        } catch { Emit 'antimalware' '' }
    }
}
RunSection {
    Emit 'secure_boot' (RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')
    Emit 'lock_policy' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs')
    try {
        $isSystem = $identity.IsSystem
        $savers = @(foreach ($userRoot in ScreenUserRoots $isSystem) { UserScreenSaver $userRoot })
        Emit 'screen_savers' ($savers -join ';')
    } catch { Emit 'screen_savers' 'unknown' }
    Emit 'autologin' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
}
RunSection {
    $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $version = $current.DisplayVersion
    if (-not $version) { $version = $current.ReleaseId }
    Emit 'os' (@($current.CurrentBuild, $version, $current.EditionID, $current.InstallationType) -join '|')
}
RunSection {
    try {
        $packages = @(Get-WindowsPackage -Online -ErrorAction Stop | Where-Object {
            $_.PackageName -match '^Package_for_RollupFix~31bf3856ad364e35~(amd64|arm64|x86)~~[0-9.]+$' -and $_.PackageState -eq 'Installed'
        })
        $selected = $null
        $now = [DateTime]::UtcNow
        foreach ($package in $packages) {
            $date = $package.InstallTime
            if ($date -isnot [DateTime] -or $date.Year -lt 2000 -or $date.ToUniversalTime() -gt $now) { throw 'Invalid OS rollup timestamp' }
            if ($null -eq $selected -or $date -gt $selected) { $selected = $date }
        }
        if ($null -ne $selected) { Emit 'patch_date' $selected.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
        else { Emit 'patch_date' '' }
    } catch { Emit 'patch_date' '' }
}

$admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$now = [DateTime]::UtcNow
function Age($date, $unit) {
    if ($null -eq $date -or $date -isnot [DateTime] -or $date.Year -lt 2000) { return 'unknown' }
    $span = $now - $date.ToUniversalTime()
    if ($span.Ticks -lt 0) { return 'unknown' }
    if ($unit -eq 'days') { return [Math]::Floor($span.TotalDays).ToString([Globalization.CultureInfo]::InvariantCulture) }
    return [Math]::Floor($span.TotalHours).ToString([Globalization.CultureInfo]::InvariantCulture)
}
RunSection {
    try {
        if (-not $admin) { throw 'Privilege required' }
        $volume = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop
        if ($null -eq $volume) { throw 'No volume result' }
        $protection = Invoke-CimMethod -InputObject $volume -MethodName GetProtectionStatus -ErrorAction Stop
        if ($protection.ReturnValue -ne 0) { throw 'Protection query failed' }
        if ($protection.ProtectionStatus -eq 0) { Emit 'preboot' '0|'; return }
        if ($protection.ProtectionStatus -ne 1) { throw 'Unknown protection' }
        $ids = Invoke-CimMethod -InputObject $volume -MethodName GetKeyProtectors -Arguments @{KeyProtectorType=[uint32]0} -ErrorAction Stop
        if ($ids.ReturnValue -ne 0) { throw 'Protector query failed' }
        $types = @(foreach ($id in $ids.VolumeKeyProtectorID) {
            $type = Invoke-CimMethod -InputObject $volume -MethodName GetKeyProtectorType -Arguments @{VolumeKeyProtectorID=$id} -ErrorAction Stop
            if ($type.ReturnValue -ne 0) { throw 'Protector type query failed' }
            [string]$type.KeyProtectorType
        })
        Emit 'preboot' ('1|' + ($types -join ','))
    } catch { Emit 'preboot' 'unknown' }
}
RunSection {
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        if ($defender.AMRunningMode -ne 'Normal' -or -not $defender.AntivirusEnabled -or -not $defender.AMServiceEnabled) { throw 'Defender not primary' }
        Emit 'signature_days' (Age $defender.AntivirusSignatureLastUpdated 'days')
        Emit 'full_scan_days' (Age $defender.FullScanEndTime 'days')
        try {
            $detections = @(Get-MpThreatDetection -ErrorAction Stop)
            $dates = @(foreach ($detection in $detections) {
                $date = $detection.InitialDetectionTime
                if ($null -eq $date -or $date -isnot [DateTime] -or $date.Year -lt 2000 -or $date.ToUniversalTime() -gt $now) { throw 'Invalid detection date' }
                $date.ToUniversalTime()
            })
            Emit 'detections_7d' ([string]@($dates | Where-Object { $_ -ge $now.AddDays(-7) }).Count)
            if ($dates.Count -eq 0) { Emit 'last_detection_hours' 'none' }
            else { Emit 'last_detection_hours' (Age ($dates | Sort-Object -Descending | Select-Object -First 1) 'hours') }
        } catch { Emit 'detections_7d' 'unknown'; Emit 'last_detection_hours' 'unknown' }
    } catch {
        Emit 'signature_days' 'unknown'; Emit 'full_scan_days' 'unknown'
        Emit 'detections_7d' 'unknown'; Emit 'last_detection_hours' 'unknown'
    }
}
function EventDate($log, $xpath, $newest) {
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new($log, [Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $query.ReverseDirection = $newest
    $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    try {
        $event = $reader.ReadEvent()
        if ($null -eq $event) { return $null }
        try { return $event.TimeCreated } finally { $event.Dispose() }
    } finally { $reader.Dispose() }
}
RunSection {
    try {
        if (-not $admin) { throw 'Privilege required' }
        $security = Age (EventDate 'Security' '*' $false) 'days'
        $system = Age (EventDate 'System' '*' $false) 'days'
        Emit 'log_retention' ($security + '|' + $system)
    } catch { Emit 'log_retention' 'unknown' }
    try {
        if (-not $admin) { throw 'Privilege required' }
        $clears = @(EventDate 'Security' '*[System[EventID=1102]]' $true; EventDate 'System' '*[System[EventID=104]]' $true) | Where-Object { $null -ne $_ }
        if (@($clears).Count -eq 0) { Emit 'log_cleared' 'none' }
        else { Emit 'log_cleared' (Age ($clears | Sort-Object -Descending | Select-Object -First 1) 'hours') }
    } catch { Emit 'log_cleared' 'unknown' }
}
RunSection {
    try {
        if (-not $admin) { throw 'Privilege required' }
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PactAudit {
    [StructLayout(LayoutKind.Sequential)]
    public struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool AuditQuerySystemPolicy(ref Guid guid, uint count, out IntPtr policy);
    [DllImport("advapi32.dll")] public static extern void AuditFree(IntPtr buffer);
    public static uint ProcessCreation() {
        Guid guid = new Guid("0cce922b-69ae-11d9-bed3-505054503030");
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(ref guid, 1, out buffer)) { throw new System.ComponentModel.Win32Exception(); }
        try { return ((Policy)Marshal.PtrToStructure(buffer, typeof(Policy))).Flags; }
        finally { AuditFree(buffer); }
    }
}
'@ -ErrorAction Stop
        $flags = [PactAudit]::ProcessCreation()
        $commandLine = PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
        Emit 'process_audit' ([string]$flags + '|' + $commandLine)
    } catch { Emit 'process_audit' 'unknown' }
}
RunSection {
    $machine = PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $user = PolicyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Emit 'powershell_logging' ($machine + '|' + $user)
}
function ReadJson($path) {
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return [pscustomobject]@{} }
    $json = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $json -or $json -isnot [pscustomobject]) { throw 'Invalid JSON object' }
    return $json
}
function BrowserPolicy($machinePath, $userPath, $names) {
    $result = @{}
    foreach ($name in @($names | Sort-Object { if ($_ -eq 'SafeBrowsingProtectionLevel') { 0 } else { 1 } })) {
        $machine = PolicyValue $machinePath $name
        if ($machine -eq '!') { throw 'Unreadable policy' }
        $value = $machine
        if ($value -eq '') { $value = PolicyValue $userPath $name }
        if ($value -eq '!') { throw 'Unreadable policy' }
        if ($value -ne '') {
            if ($name -eq 'SafeBrowsingProtectionLevel') {
                if ($value -notmatch '^[012]$') { throw 'Invalid protection level' }
                $result[$name] = [int]$value
                return $result
            } else {
                if ($value -notmatch '^[01]$') { throw 'Invalid policy flag' }
                $result[$name] = ($value -eq '1')
            }
        }
    }
    return $result
}
function ChromiumPrefs($path, $edge) {
    $prefs = ReadJson $path
    $projected = @{}
    if ($edge) {
        if ($null -ne $prefs.PSObject.Properties['edge']) {
            if ($prefs.edge -isnot [pscustomobject]) { throw 'Invalid Edge preferences' }
            if ($null -ne $prefs.edge.PSObject.Properties['smartscreen']) {
                if ($prefs.edge.smartscreen -isnot [pscustomobject]) { throw 'Invalid SmartScreen preferences' }
                if ($null -ne $prefs.edge.smartscreen.PSObject.Properties['enabled']) { $projected.edge = @{smartscreen=@{enabled=$prefs.edge.smartscreen.enabled}} }
            }
        }
    } elseif ($null -ne $prefs.PSObject.Properties['safebrowsing']) {
        if ($prefs.safebrowsing -isnot [pscustomobject]) { throw 'Invalid Safe Browsing preferences' }
        if ($null -ne $prefs.safebrowsing.PSObject.Properties['enabled']) { $projected.safebrowsing = @{enabled=$prefs.safebrowsing.enabled} }
    }
    return $projected
}
function BrowserDirs($root, $firefox) {
    if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) { return }
    if (((Get-Item -LiteralPath $root -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'External profile root' }
    foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop) {
        $isProfile = $firefox -or $dir.Name -eq 'Default' -or $dir.Name -like 'Profile *' -or $dir.Name -eq 'Guest Profile'
        $preferences = Test-Path -LiteralPath (Join-Path $dir.FullName 'Preferences') -ErrorAction Stop
        if ($isProfile -or $preferences) {
            if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'External profile' }
            $dir.FullName
        }
    }
}
function FirefoxRegistry($root) {
    $path = $root + '\SOFTWARE\Policies\Mozilla\Firefox'
    $result = @{}
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return $result }
    $key = Get-Item -LiteralPath $path -ErrorAction Stop
    $raw = $key.GetValue('Preferences', $null)
    if ($null -ne $raw) {
        $parsed = ($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop
        if ($parsed -isnot [pscustomobject]) { throw 'Invalid Firefox policy' }
        foreach ($name in @('browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled')) {
            if ($null -ne $parsed.PSObject.Properties[$name]) { $result[$name] = $parsed.$name }
        }
    }
    foreach ($name in @('browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled')) {
        $old = PolicyValue ($path + '\Preferences') $name
        if ($old -eq '!') { throw 'Unreadable Firefox policy' }
        if ($old -ne '') {
            if ($result.ContainsKey($name)) { throw 'Conflicting Firefox policy formats' }
            if ($old -notmatch '^[01]$') { throw 'Invalid Firefox policy' }
            $result[$name] = [int]$old
        }
    }
    return $result
}
function FirefoxBrowser($homePath, $app, $userRoot) {
    $policy = @{}
    try {
        $machine = FirefoxRegistry 'HKLM:'
        $policy = @{policies=@{Preferences=$machine}}
        if ($userRoot -like 'Registry::HKEY_USERS*' -and -not (Test-Path -LiteralPath $userRoot -ErrorAction Stop)) { throw 'Unloaded user policy hive' }
        $user = FirefoxRegistry $userRoot
        foreach ($name in $user.Keys) { if (-not $machine.ContainsKey($name)) { $machine[$name] = $user[$name] } }
        if ($machine.Count -eq 0) { $policy = ReadJson (Join-Path (Split-Path $app) 'distribution\policies.json') }
        $root = Join-Path $homePath 'AppData\Roaming\Mozilla\Firefox'
        $ini = Join-Path $root 'profiles.ini'
        if (Test-Path -LiteralPath $ini -ErrorAction Stop) {
            foreach ($line in Get-Content -LiteralPath $ini -ErrorAction Stop) {
                if ($line.Trim() -match '^Path=(.*)$') {
                    $relative = $Matches[1].Replace('\', '/')
                    if (-not $relative.StartsWith('Profiles/') -or $relative.Split('/') -contains '..') { throw 'External Firefox profile' }
                }
                if ($line.Trim() -eq 'IsRelative=0') { throw 'Absolute Firefox profile' }
            }
        }
        $dirs = @(BrowserDirs (Join-Path $root 'Profiles') $true)
        if ($dirs.Count -eq 0) { return @{kind='firefox'; policy=$policy; prefs=''} }
        foreach ($dir in $dirs) {
            $lines = @()
            foreach ($file in @('prefs.js', 'user.js')) {
                $path = Join-Path $dir $file
                if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                    $lines += @(Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -match 'browser\.safebrowsing\.(malware|phishing)\.enabled' })
                }
            }
            @{kind='firefox'; policy=$policy; prefs=($lines -join "`n")}
        }
    } catch { @{kind='firefox'; policy=$policy; unreadable=$true} }
}
function ChromiumBrowser($browser, $local, $userRoot) {
    $policy = @{}
    try {
        $suffix = '\SOFTWARE\Policies\' + $browser.Policy
        $names = @('SafeBrowsingProtectionLevel','SafeBrowsingEnabled')
        if ($browser.Kind -eq 'edge') { $names = @('SmartScreenEnabled') }
        $policy = BrowserPolicy ('HKLM:' + $suffix) ($userRoot + $suffix) $names
        if ($userRoot -like 'Registry::HKEY_USERS*' -and -not (Test-Path -LiteralPath $userRoot -ErrorAction Stop)) { throw 'Unloaded user policy hive' }
        $recommended = $null
        try { $recommended = BrowserPolicy ('HKLM:' + $suffix + '\Recommended') ($userRoot + $suffix + '\Recommended') $names } catch {}
        $dataRoot = Join-Path $local $browser.Data
        $override = PolicyValue ('HKLM:' + $suffix) 'UserDataDir'
        if ($override -eq '') { $override = PolicyValue ($userRoot + $suffix) 'UserDataDir' }
        if ($override -eq '!') { throw 'Unreadable user-data policy' }
        if ($override -ne '') {
            $variables = @{'${local_app_data}'=$local; '${roaming_app_data}'=(Join-Path (Split-Path $local) 'Roaming'); '${profile}'=(Split-Path (Split-Path $local)); '${windows}'=$env:windir}
            foreach ($name in $variables.Keys) { if ($variables[$name]) { $override = $override.Replace($name, $variables[$name]) } }
            if (-not [IO.Path]::IsPathRooted($override) -or $override -match '\$\{|%') { throw 'Unsupported user-data policy variable' }
            if (-not (Test-Path -LiteralPath $override -PathType Container -ErrorAction Stop)) { throw 'Missing user-data policy directory' }
            $dataRoot = $override
        }
        $dirs = @(BrowserDirs $dataRoot $false)
        if ($dirs.Count -eq 0) { return @{kind=$browser.Kind; policy=$policy; recommended=$recommended; prefs=@{}} }
        foreach ($dir in $dirs) {
            $prefs = ChromiumPrefs (Join-Path $dir 'Preferences') ($browser.Kind -eq 'edge')
            @{kind=$browser.Kind; policy=$policy; recommended=$recommended; prefs=$prefs}
        }
    } catch { @{kind=$browser.Kind; policy=$policy; unreadable=$true} }
}
RunSection {
    try {
        $screenPolicy = PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        $screenLocal = PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
        Emit 'smartscreen' ($screenPolicy + '|' + $screenLocal)
        $items = @()
        $users = @(@{Home=$env:USERPROFILE; Root='HKCU:'})
        if ($identity.IsSystem) {
            $users = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special } | ForEach-Object {
                @{Home=$_.LocalPath; Root=('Registry::HKEY_USERS\' + $_.SID)}
            })
            if ($users.Count -eq 0) { throw 'No user profiles' }
        }
        foreach ($userInfo in $users) {
            $homePath = $userInfo.Home
            $userRoot = $userInfo.Root
            $local = Join-Path $homePath 'AppData\Local'
            foreach ($browser in @(
                @{Kind='chrome'; Exe='Google\Chrome\Application\chrome.exe'; Data='Google\Chrome\User Data'; Policy='Google\Chrome'},
                @{Kind='edge'; Exe='Microsoft\Edge\Application\msedge.exe'; Data='Microsoft\Edge\User Data'; Policy='Microsoft\Edge'},
                @{Kind='brave'; Exe='BraveSoftware\Brave-Browser\Application\brave.exe'; Data='BraveSoftware\Brave-Browser\User Data'; Policy='BraveSoftware\Brave'},
                @{Kind='firefox'; Exe='Mozilla Firefox\firefox.exe'; Data=''; Policy='Mozilla\Firefox'}
            )) {
                try {
                    $apps = @(foreach ($installRoot in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $local)) {
                        if ($installRoot) {
                            $candidate = Join-Path $installRoot $browser.Exe
                            if (Test-Path -LiteralPath $candidate -ErrorAction Stop) { $candidate }
                        }
                    })
                    if ($apps.Count -eq 0) { continue }
                    if ($browser.Kind -eq 'firefox') {
                        foreach ($app in $apps) { $items += @(FirefoxBrowser $homePath $app $userRoot) }
                    } else {
                        $items += @(ChromiumBrowser $browser $local $userRoot)
                    }
                } catch { $items += @{kind=$browser.Kind; unreadable=$true} }
            }
        }
        Emit 'browsers' (ConvertTo-Json -InputObject @($items) -Depth 15 -Compress)
    } catch { Emit 'browsers' 'unknown' }
}
