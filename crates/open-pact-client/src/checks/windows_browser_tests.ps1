$ErrorActionPreference = 'Stop'
. ([scriptblock]::Create((Get-Content -Raw (Join-Path $PSScriptRoot 'windows.ps1')))) | Out-Null
function Assert($condition, $message) { if (-not $condition) { throw $message } }
$root = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
try {
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
    Assert ($policy.SafeBrowsingEnabled -eq $true) 'User policy fallback failed'
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
    $failed = $false
    try { FirefoxBrowser $root $app 'HKCU:' | Out-Null } catch { $failed = $true }
    Assert $failed 'External Firefox profile accepted'
    Write-Output 'Windows browser source fixtures passed'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
