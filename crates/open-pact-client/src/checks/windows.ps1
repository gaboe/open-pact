
$ErrorActionPreference = 'Stop'
function Emit($key, $value) { if ($null -eq $value) { $value = '' }; [Console]::WriteLine("$key`t$value") }
function RunSection([scriptblock]$work) { & $work }
function RegValue($path, $name) {
    try {
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        if ($null -eq $item.PSObject.Properties[$name]) { return '' }
        return [string]$item.$name
    } catch { return '!' }
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
    Emit 'screen_active' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive')
    Emit 'screen_secure' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure')
    Emit 'screen_timeout' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut')
    Emit 'autologin' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
}
RunSection {
    $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Emit 'os' (@($current.CurrentBuild, $current.DisplayVersion, $current.EditionID, $current.InstallationType) -join '|')
}
RunSection {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $history = @($searcher.QueryHistory(0, 100) | Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 } | Sort-Object Date -Descending)
        $rollupId = '28BC880E-0592-4CBF-8F95-C79B17911D5F'
        $securityId = '0FA1201D-4330-4FA8-8AE9-B877473B6441'
        $selected = $null
        foreach ($entry in $history) {
            $categories = @($entry.Categories | ForEach-Object { $_.CategoryID })
            if ($categories -notcontains $rollupId -and $categories -notcontains $securityId) { continue }
            $updateId = $entry.UpdateIdentity.UpdateID
            $search = $searcher.Search("UpdateID='$updateId'")
            if ($search.Updates.Count -eq 0) { continue }
            $kbIds = @($search.Updates.Item(0).KBArticleIDs)
            if ($categories -contains $rollupId -or $kbIds -contains '5126646') { $selected = $entry.Date; break }
        }
        if ($null -ne $selected) { Emit 'patch_date' $selected.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
        else { Emit 'patch_date' '' }
    } catch { Emit 'patch_date' '' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$now = [DateTime]::UtcNow
function Age($date, $unit) {
    if ($null -eq $date -or $date -isnot [DateTime] -or $date.Year -lt 2000) { return 'unknown' }
    $span = $now - $date.ToUniversalTime()
    if ($span.Ticks -lt 0) { return 'unknown' }
    if ($unit -eq 'days') { return [Math]::Floor($span.TotalDays).ToString([Globalization.CultureInfo]::InvariantCulture) }
    return [Math]::Floor($span.TotalHours).ToString([Globalization.CultureInfo]::InvariantCulture)
}
function PolicyValue($path, $name) {
    try {
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return '' }
        return RegValue $path $name
    } catch { return '!' }
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
    foreach ($name in $names) {
        $machine = PolicyValue $machinePath $name
        if ($machine -eq '!') { throw 'Unreadable policy' }
        $value = $machine
        if ($value -eq '') { $value = PolicyValue $userPath $name }
        if ($value -eq '!') { throw 'Unreadable policy' }
        if ($value -ne '') {
            if ($name -eq 'SafeBrowsingProtectionLevel') {
                if ($value -notmatch '^[012]$') { throw 'Invalid protection level' }
                $result[$name] = [int]$value
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
    if (((Get-Item -LiteralPath $root -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'External profile root' }
    foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop) {
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
    $machine = FirefoxRegistry 'HKLM:'
    $user = FirefoxRegistry $userRoot
    foreach ($name in $user.Keys) { if (-not $machine.ContainsKey($name)) { $machine[$name] = $user[$name] } }
    $policyFile = ReadJson (Join-Path (Split-Path $app) 'distribution\policies.json')
    if ($machine.Count -gt 0 -and $null -ne $policyFile.PSObject.Properties['policies']) { throw 'Conflicting Firefox policy providers' }
    $policy = $policyFile
    if ($machine.Count -gt 0) { $policy = @{policies=@{Preferences=$machine}} }
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
                    if (-not (Test-Path -LiteralPath $userRoot -ErrorAction Stop)) { throw 'Unloaded user policy hive' }
                    if ($browser.Kind -eq 'firefox') {
                        foreach ($app in $apps) { $items += @(FirefoxBrowser $homePath $app $userRoot) }
                    } else {
                        $suffix = '\SOFTWARE\Policies\' + $browser.Policy
                        $names = @('SafeBrowsingEnabled', 'SafeBrowsingProtectionLevel')
                        if ($browser.Kind -eq 'edge') { $names = @('SmartScreenEnabled') }
                        $policy = BrowserPolicy ('HKLM:' + $suffix) ($userRoot + $suffix) $names
                        $recommended = $null
                        try { $recommended = BrowserPolicy ('HKLM:' + $suffix + '\Recommended') ($userRoot + $suffix + '\Recommended') $names } catch {}
                        $dirs = @(BrowserDirs (Join-Path $local $browser.Data) $false)
                        if ($dirs.Count -eq 0) { $items += @{kind=$browser.Kind; policy=$policy; recommended=$recommended; prefs=@{}} }
                        foreach ($dir in $dirs) {
                            $prefs = ChromiumPrefs (Join-Path $dir 'Preferences') ($browser.Kind -eq 'edge')
                            $items += @{kind=$browser.Kind; policy=$policy; recommended=$recommended; prefs=$prefs}
                        }
                    }
                } catch { $items += @{kind=$browser.Kind; unreadable=$true} }
            }
        }
        Emit 'browsers' (ConvertTo-Json -InputObject @($items) -Depth 15 -Compress)
    } catch { Emit 'browsers' 'unknown' }
}
