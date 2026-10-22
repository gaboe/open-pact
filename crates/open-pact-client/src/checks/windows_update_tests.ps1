$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'windows.ps1') -Raw
$match = [regex]::Match($source, '(?s)RunSection \{\s+try \{\s+\$au = New-Object -ComObject Microsoft.Update.AutoUpdate.*?(?=\r?\nRunSection)')
if (-not $match.Success) { throw 'Missing automatic update section' }
$section = [scriptblock]::Create($match.Value)
function RunSection([scriptblock]$work) { & $work }
function New-Object($ComObject) { return [pscustomobject]@{ Settings = [pscustomobject]@{ NotificationLevel = 4 } } }
function PolicyValue($path, $name) {
    $key = $path + '|' + $name
    if ($script:values.ContainsKey($key)) { return $script:values[$key] }
    return ''
}
function Emit($key, $value) {
    if ($key -ne 'os_auto_updates') { throw 'Unexpected metric' }
    $script:actual = $value
}
$gpo = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$effective = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'
$mdm = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update'
$current = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$recent = [DateTime]::UtcNow.AddDays(-1).ToString('o')
$old = [DateTime]::UtcNow.AddDays(-40).ToString('o')
$future = [DateTime]::UtcNow.AddDays(5).ToString('o')
function Check($label, $expected, $values) {
    $script:values = $values
    $script:actual = $null
    & $section
    if ($script:actual -ne $expected) { throw "$label expected $expected got $script:actual" }
    Write-Output "$label=$script:actual"
}
Check 'unpaused' 'on' @{}
foreach ($kind in @('Feature', 'Quality')) {
    Check "$kind-effective-pause" 'off' @{ "$effective|Paused${kind}Status" = '1' }
    Check "$kind-resumed" 'on' @{ "$effective|Paused${kind}Status" = '2'; "$gpo|Pause${kind}Updates" = '1'; "$gpo|Pause${kind}UpdatesStartTime" = $recent; "$ux|Pause${kind}UpdatesEndTime" = $future }
    Check "$kind-not-paused" 'on' @{ "$effective|Paused${kind}Status" = '0'; "$gpo|Pause${kind}Updates" = '1' }
    Check "$kind-expired-policy" 'on' @{ "$gpo|Pause${kind}Updates" = '1'; "$gpo|Pause${kind}UpdatesStartTime" = $old }
    Check "$kind-active-policy" 'off' @{ "$gpo|Pause${kind}Updates" = '1'; "$gpo|Pause${kind}UpdatesStartTime" = $recent }
    Check "$kind-undated-policy" 'unknown' @{ "$gpo|Pause${kind}Updates" = '1' }
    Check "$kind-mdm-policy" 'off' @{ "$mdm\Pause${kind}UpdatesStartTime|value" = $recent }
    Check "$kind-mdm-current" 'off' @{ "$current|Pause${kind}UpdatesStartTime" = $recent }
    Check "$kind-denied-effective" 'unknown' @{ "$effective|Paused${kind}Status" = '!' }
    Check "$kind-denied-mdm" 'unknown' @{ "$mdm\Pause${kind}UpdatesStartTime|value" = '!' }
    Check "$kind-denied-gpo" 'unknown' @{ "$gpo|Pause${kind}UpdatesStartTime" = '!' }
    Check "$kind-invalid-effective" 'unknown' @{ "$effective|Paused${kind}Status" = '3' }
}
Check 'ux-pause' 'off' @{ "$ux|PauseUpdatesExpiryTime" = $future }
Check 'denied-ux' 'unknown' @{ "$ux|PauseUpdatesExpiryTime" = '!' }
Check 'resumed-feature-paused-quality' 'off' @{ "$effective|PausedFeatureStatus" = '2'; "$effective|PausedQualityStatus" = '1' }
