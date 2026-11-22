$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows.ps1'), [ref]$null, [ref]$null)
foreach ($fn in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$now = [DateTime]::UtcNow
function Assert($condition, $message) { if (-not $condition) { throw $message } }
$root = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
try {
    $identity = [pscustomobject]@{IsSystem=$false}
    Assert ((Age ($now.AddMinutes(2)) 'days') -eq 'unknown') 'Future Defender day age accepted'
    Assert ((Age ($now.AddMinutes(2)) 'hours') -eq 'unknown') 'Future Defender hour age accepted'
    Assert ((Age ($now.AddMinutes(-2)) 'days') -eq '0') 'Completed-day age changed'
    $profilePath = Join-Path $root 'UserData\Default'
    New-Item -ItemType Directory -Path $profilePath -Force | Out-Null
    $prefsPath = Join-Path $profilePath 'Preferences'
    Set-Content -LiteralPath $prefsPath -Value '{"safebrowsing":{"enabled":false},"fictional_unrelated":"excluded"}'
    $prefs = ChromiumPrefs $prefsPath $false
    Assert ($prefs.safebrowsing.enabled -eq $false) 'Chromium disabled preference was lost'
    Assert (-not $prefs.ContainsKey('fictional_unrelated')) 'Unrelated preference was retained'
    Assert (@(BrowserDirs (Join-Path $root 'UserData') $false).Count -eq 1) 'Default profile not discovered'
    Set-Content -LiteralPath $prefsPath -Value '{truncated'
    $failed = $false
    try { ChromiumPrefs $prefsPath $false | Out-Null } catch { $failed = $true }
    Assert $failed 'Malformed preferences accepted'
    $registry = @{
        'machine|SafeBrowsingProtectionLevel'='0'
        'user|SafeBrowsingProtectionLevel'='2'
        'user|SafeBrowsingEnabled'='1'
    }
    function PolicyValue($path, $name) {
        $key = $path + '|' + $name
        if ($registry.ContainsKey($key)) { return $registry[$key] }
        return ''
    }
    $policy = BrowserPolicy 'machine' 'user' @('SafeBrowsingProtectionLevel','SafeBrowsingEnabled')
    Assert ($policy.SafeBrowsingProtectionLevel -eq 0) 'Machine policy did not take precedence'
    Assert ((BrowserPolicy 'machine' 'user' @('SafeBrowsingEnabled')).SafeBrowsingEnabled -eq $true) 'User policy fallback failed'
    $registry['user|SafeBrowsingProtectionLevel'] = '!'
    $failed = $false
    try { BrowserPolicy 'machine' 'user' @('SafeBrowsingProtectionLevel') | Out-Null } catch { $failed = $true }
    Assert (-not $failed) 'Lower-priority user policy hid known machine policy'
    $registry.Remove('machine|SafeBrowsingProtectionLevel')
    $failed = $false
    try { BrowserPolicy 'machine' 'user' @('SafeBrowsingProtectionLevel') | Out-Null } catch { $failed = $true }
    Assert $failed 'Unreadable effective user policy accepted'
    $registry.Clear()
    $firefoxRoot = Join-Path $root 'AppData\Roaming\Mozilla\Firefox'
    $firefoxProfile = Join-Path $firefoxRoot 'Profiles\fictional.default'
    New-Item -ItemType Directory -Path $firefoxProfile -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $firefoxRoot 'profiles.ini') -Value "[Profile0]`nPath=Profiles/fictional.default`nIsRelative=1"
    Set-Content -LiteralPath (Join-Path $firefoxProfile 'prefs.js') -Value 'user_pref("browser.safebrowsing.phishing.enabled", false);'
    Set-Content -LiteralPath (Join-Path $firefoxProfile 'user.js') -Value 'user_pref("browser.safebrowsing.phishing.enabled", true);'
    $app = Join-Path $root 'Firefox\firefox.exe'
    function FirefoxRegistry($registryRoot) {
        if ($registryRoot -eq 'HKLM:') { return @{'browser.safebrowsing.phishing.enabled'=0} }
        return @{'browser.safebrowsing.phishing.enabled'=1}
    }
    $items = @(FirefoxBrowser $root $app 'HKCU:')
    Assert ($items.Count -eq 1) 'Firefox profile not collected'
    Assert ($items[0].prefs.Contains('false') -and $items[0].prefs.Contains('true')) 'Firefox user.js order lost'
    Assert ($items[0].policy.policies.Preferences['browser.safebrowsing.phishing.enabled'] -eq 0) 'Firefox machine policy precedence failed'
    Set-Content -LiteralPath (Join-Path $firefoxRoot 'profiles.ini') -Value "[Profile0]`nPath=C:\fictional\external`nIsRelative=0"
    $external = @(FirefoxBrowser $root $app 'HKCU:')
    Assert ($external[0].unreadable -eq $true) 'External Firefox profile accepted'
    Assert ($external[0].policy.policies.Preferences['browser.safebrowsing.phishing.enabled'] -eq 0) 'External profile hid mandatory Firefox policy'
    $identity = [pscustomobject]@{IsSystem=$true}
    $systemPlainPrefs = Join-Path $root 'system-plain\AppData\Local\Google\Chrome\User Data\Default\Preferences'
    New-Item -ItemType Directory -Path (Split-Path $systemPlainPrefs) -Force | Out-Null
    Set-Content -LiteralPath $systemPlainPrefs -Value '{"safebrowsing":{"enabled":false},"fictional_unrelated":"excluded"}'
    $systemPlain = ChromiumPrefs $systemPlainPrefs $false
    Assert ($systemPlain.safebrowsing.enabled -eq $false) 'SYSTEM run lost a plain profile preference'
    $outsideAppData = Join-Path $root 'outside-appdata'
    $outsidePrefs = Join-Path $outsideAppData 'Local\Google\Chrome\User Data\Default\Preferences'
    New-Item -ItemType Directory -Path (Split-Path $outsidePrefs) -Force | Out-Null
    Set-Content -LiteralPath $outsidePrefs -Value '{"safebrowsing":{"enabled":false}}'
    $outsideIni = Join-Path $outsideAppData 'Roaming\Mozilla\Firefox\profiles.ini'
    New-Item -ItemType Directory -Path (Split-Path $outsideIni) -Force | Out-Null
    Set-Content -LiteralPath $outsideIni -Value "[Profile0]`nPath=Profiles/fictional.default`nIsRelative=1"
    $junctionHome = Join-Path $root 'system-junction'
    New-Item -ItemType Directory -Path $junctionHome -Force | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $junctionHome 'AppData') -Target $outsideAppData | Out-Null
    $failed = $false
    try { ChromiumPrefs (Join-Path $junctionHome 'AppData\Local\Google\Chrome\User Data\Default\Preferences') $false | Out-Null } catch { $failed = $true }
    Assert $failed 'SYSTEM run followed a junction at AppData'
    $junctionFirefox = @(FirefoxBrowser $junctionHome $app 'HKCU:')
    Assert ($junctionFirefox[0].unreadable -eq $true) 'SYSTEM run read Firefox through a junction at AppData'
    Assert ($junctionFirefox[0].policy.policies.Preferences['browser.safebrowsing.phishing.enabled'] -eq 0) 'Junction at AppData hid mandatory Firefox policy'
    $vendorHome = Join-Path $root 'system-vendor'
    New-Item -ItemType Directory -Path (Join-Path $vendorHome 'AppData\Local') -Force | Out-Null
    $outsideGoogle = Join-Path $root 'outside-google'
    $vendorPrefs = Join-Path $outsideGoogle 'Chrome\User Data\Default\Preferences'
    New-Item -ItemType Directory -Path (Split-Path $vendorPrefs) -Force | Out-Null
    Set-Content -LiteralPath $vendorPrefs -Value '{"safebrowsing":{"enabled":false}}'
    New-Item -ItemType Junction -Path (Join-Path $vendorHome 'AppData\Local\Google') -Target $outsideGoogle | Out-Null
    $failed = $false
    try { ChromiumPrefs (Join-Path $vendorHome 'AppData\Local\Google\Chrome\User Data\Default\Preferences') $false | Out-Null } catch { $failed = $true }
    Assert $failed 'SYSTEM run followed a junction at the vendor folder'
    $linkHome = Join-Path $root 'system-symlink'
    $linkPrefs = Join-Path $linkHome 'AppData\Local\Google\Chrome\User Data\Default\Preferences'
    New-Item -ItemType Directory -Path (Split-Path $linkPrefs) -Force | Out-Null
    $linkTarget = Join-Path $root 'symlink-target.json'
    Set-Content -LiteralPath $linkTarget -Value '{"safebrowsing":{"enabled":false}}'
    New-Item -ItemType SymbolicLink -Path $linkPrefs -Target $linkTarget | Out-Null
    $failed = $false
    try { ChromiumPrefs $linkPrefs $false | Out-Null } catch { $failed = $true }
    Assert $failed 'SYSTEM run followed a symbolic link at Preferences'
    $hardHome = Join-Path $root 'system-hardlink'
    $hardFirefox = Join-Path $hardHome 'AppData\Roaming\Mozilla\Firefox'
    $hardProfile = Join-Path $hardFirefox 'Profiles\fictional.default'
    New-Item -ItemType Directory -Path $hardProfile -Force | Out-Null
    $hardIni = Join-Path $hardFirefox 'profiles.ini'
    $outsideHardIni = Join-Path $root 'outside-profiles.ini'
    Set-Content -LiteralPath $outsideHardIni -Value "[Profile0]`nPath=Profiles/fictional.default`nIsRelative=1"
    New-Item -ItemType HardLink -Path $hardIni -Target $outsideHardIni | Out-Null
    $hardIniItems = @(FirefoxBrowser $hardHome $app 'HKCU:')
    Assert ($hardIniItems[0].unreadable -eq $true) 'SYSTEM run read a hard-linked profiles.ini'
    Remove-Item -LiteralPath $hardIni -Force
    Set-Content -LiteralPath $hardIni -Value "[Profile0]`nPath=Profiles/fictional.default`nIsRelative=1"
    $outsidePrefsJs = Join-Path $root 'outside-prefs.js'
    Set-Content -LiteralPath $outsidePrefsJs -Value 'user_pref("browser.safebrowsing.phishing.enabled", false);'
    New-Item -ItemType HardLink -Path (Join-Path $hardProfile 'prefs.js') -Target $outsidePrefsJs | Out-Null
    $hardPrefsItems = @(FirefoxBrowser $hardHome $app 'HKCU:')
    Assert ($hardPrefsItems[0].unreadable -eq $true) 'SYSTEM run read a hard-linked prefs.js'
    $identity = [pscustomobject]@{IsSystem=$false}
    $userThroughJunction = ChromiumPrefs (Join-Path $junctionHome 'AppData\Local\Google\Chrome\User Data\Default\Preferences') $false
    Assert ($userThroughJunction.safebrowsing.enabled -eq $false) 'User run refused a junction that the user can read'
    Write-Output 'Windows browser source fixtures passed'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
