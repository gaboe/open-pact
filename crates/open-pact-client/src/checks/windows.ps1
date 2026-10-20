
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
