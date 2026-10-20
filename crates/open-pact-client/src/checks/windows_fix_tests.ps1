param([string]$Source = (Join-Path $PSScriptRoot 'windows.ps1'))
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$null, [ref]$null)
foreach ($fn in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$sections = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'RunSection'}, $false))
function Section($key) {
    $section = $sections | Where-Object { $_.Extent.Text.Contains("Emit '$key'") } | Select-Object -First 1
    & $section.CommandElements[1].ScriptBlock.GetScriptBlock()
}
function Tokens($lines) {
    $result = @{}
    foreach ($line in $lines) {
        $pair = ([string]$line).Split("`t", 2)
        if ($pair.Count -eq 2) { $result[$pair[0]] = $pair[1] }
    }
    return $result
}
function Assert($condition, $message) { if (-not $condition) { throw $message } }
$failures = @()
function Case($name, [scriptblock]$body) {
    try { & $body; Write-Output "PASS $name" }
    catch { $script:failures += $name; Write-Output "FAIL $name : $_" }
}
$now = [DateTime]::UtcNow
$root = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
try {
    Case '1 unrelated Update Rollups cannot refresh OS age' {
        $entry = [pscustomobject]@{ResultCode=2; Operation=1; Date=$now.AddDays(-1); Categories=@([pscustomobject]@{CategoryID='28BC880E-0592-4CBF-8F95-C79B17911D5F'}); UpdateIdentity=[pscustomobject]@{UpdateID='fictional'}}
        $searcher = [pscustomobject]@{}
        $searcher | Add-Member ScriptMethod QueryHistory { param($start,$count) return $entry }
        $updates = [pscustomobject]@{Count=1}
        $updates | Add-Member ScriptMethod Item {param($i) return [pscustomobject]@{KBArticleIDs=@('890830')}}
        $searcher | Add-Member ScriptMethod Search {param($query) return [pscustomobject]@{Updates=$updates}}
        $session = [pscustomobject]@{}
        $session | Add-Member ScriptMethod CreateUpdateSearcher {return $searcher}
        function New-Object {param($ComObject) return $session}
        function Get-WindowsPackage { return [pscustomobject]@{PackageName='Package_for_KB890830';PackageState='Installed';InstallTime=$entry.Date} }
        $actual = (Tokens @(Section 'patch_date')).patch_date
        Assert ($actual -eq '') "Expected unknown patch date, got $actual"
    }
    Case '1 successful OS security rollup counts without a hard-coded KB' {
        $date = $now.AddDays(-7)
        $entry = [pscustomobject]@{ResultCode=2; Operation=1; Date=$date; Categories=@([pscustomobject]@{CategoryID='0FA1201D-4330-4FA8-8AE9-B877473B6441'}); UpdateIdentity=[pscustomobject]@{UpdateID='fictional'}}
        $searcher = [pscustomobject]@{}
        $searcher | Add-Member ScriptMethod QueryHistory {param($start,$count) return $entry}
        $updates = [pscustomobject]@{Count=1}
        $updates | Add-Member ScriptMethod Item {param($i) return [pscustomobject]@{KBArticleIDs=@('5126868')}}
        $searcher | Add-Member ScriptMethod Search {param($query) return [pscustomobject]@{Updates=$updates}}
        $session = [pscustomobject]@{}
        $session | Add-Member ScriptMethod CreateUpdateSearcher {return $searcher}
        function New-Object {param($ComObject) return $session}
        function Get-WindowsPackage { return [pscustomobject]@{PackageName='Package_for_RollupFix~31bf3856ad364e35~amd64~~14393.9612.1.0';PackageState='Installed';InstallTime=$date} }
        $actual = (Tokens @(Section 'patch_date')).patch_date
        Assert ($actual -eq $date.ToString('yyyy-MM-dd')) "Expected OS rollup date, got $actual"
    }
    Case '6 same-day future timestamp stays unknown' {
        $date = $now.AddMinutes(2)
        $entry = [pscustomobject]@{ResultCode=2; Operation=1; Date=$date; Categories=@([pscustomobject]@{CategoryID='28BC880E-0592-4CBF-8F95-C79B17911D5F'}); UpdateIdentity=[pscustomobject]@{UpdateID='fictional'}}
        $searcher = [pscustomobject]@{}
        $searcher | Add-Member ScriptMethod QueryHistory {param($start,$count) return $entry}
        $updates = [pscustomobject]@{Count=1}
        $updates | Add-Member ScriptMethod Item {param($i) return [pscustomobject]@{KBArticleIDs=@('5126646')}}
        $searcher | Add-Member ScriptMethod Search {param($query) return [pscustomobject]@{Updates=$updates}}
        $session = [pscustomobject]@{}
        $session | Add-Member ScriptMethod CreateUpdateSearcher {return $searcher}
        function New-Object {param($ComObject) return $session}
        function Get-WindowsPackage { return [pscustomobject]@{PackageName='Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.33650.1.0';PackageState='Installed';InstallTime=$date} }
        $actual = (Tokens @(Section 'patch_date')).patch_date
        Assert ($actual -eq '') "Expected unknown future date, got $actual"
    }
    Case '8 ReleaseId reaches the legacy lifecycle row' {
        function Get-ItemProperty { return [pscustomobject]@{CurrentBuild='17763';ReleaseId='1809';EditionID='EnterpriseS';InstallationType='Client'} }
        $actual = (Tokens @(Section 'os')).os
        Assert ($actual -eq '17763|1809|EnterpriseS|Client') "Expected legacy release, got $actual"
    }
    Case '4 hidden Chromium and Firefox profiles are discovered' {
        foreach ($firefox in @($false,$true)) {
            $data = Join-Path $root ([Guid]::NewGuid().ToString())
            $dir = New-Item -ItemType Directory -Path (Join-Path $data '.fictional-hidden') -Force
            Set-Content -LiteralPath (Join-Path $dir.FullName 'Preferences') -Value '{"safebrowsing":{"enabled":false}}'
            if ($env:OS -eq 'Windows_NT') { $dir.Attributes = $dir.Attributes -bor [IO.FileAttributes]::Hidden }
            $actual = @(BrowserDirs $data $firefox)
            Assert ($actual.Count -eq 1) "Expected 1 hidden profile, got $($actual.Count)"
        }
    }
    Case '5 Chromium honors policy user-data directory' {
        $saved = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:USERPROFILE)
        try {
            $env:ProgramFiles = Join-Path $root 'Programs'
            ${env:ProgramFiles(x86)} = ''
            $env:USERPROFILE = Join-Path $root 'User'
            $identity = [pscustomobject]@{IsSystem=$false}
            $app = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
            New-Item -ItemType Directory -Path (Split-Path $app) -Force | Out-Null
            Set-Content -LiteralPath $app -Value ''
            $external = Join-Path $root 'ExternalData'
            New-Item -ItemType Directory -Path (Join-Path $external 'Default') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $external 'Default\Preferences') -Value '{"safebrowsing":{"enabled":false}}'
            function PolicyValue($path,$name) {
                if ($name -eq 'UserDataDir' -and $path -like 'HKLM:*Google*') { return $external }
                return ''
            }
            function Test-Path {
                param($LiteralPath,$ErrorAction,$PathType)
                if ($LiteralPath -eq 'HKCU:') { return $true }
                if ($PathType) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
                return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
            }
            $actual = (Tokens @(Section 'smartscreen')).browsers | ConvertFrom-Json
            Assert ($actual[0].prefs.safebrowsing.enabled -eq $false) 'Configured external disabled profile was replaced by defaults'
            Remove-Item -LiteralPath $external -Recurse -Force
            $actual = (Tokens @(Section 'smartscreen')).browsers | ConvertFrom-Json
            Assert ($actual[0].unreadable -eq $true) 'Missing configured external directory accepted as defaults'
        } finally { $env:ProgramFiles = $saved[0]; ${env:ProgramFiles(x86)} = $saved[1]; $env:USERPROFILE = $saved[2] }
    }
    Case '10 Chromium mandatory policy survives malformed profile' {
        $saved = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:USERPROFILE)
        try {
            $env:ProgramFiles = Join-Path $root 'Programs'
            ${env:ProgramFiles(x86)} = ''
            $env:USERPROFILE = Join-Path $root 'User'
            $identity = [pscustomobject]@{IsSystem=$false}
            $app = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
            New-Item -ItemType Directory -Path (Split-Path $app) -Force | Out-Null
            Set-Content -LiteralPath $app -Value ''
            $data = Join-Path $env:USERPROFILE 'AppData\Local\Google\Chrome\User Data\Default'
            New-Item -ItemType Directory -Path $data -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $data 'Preferences') -Value '{broken'
            function PolicyValue($path,$name) { if ($name -eq 'SafeBrowsingProtectionLevel' -and $path -notlike '*Recommended*') { return '0' }; return '' }
            function Test-Path {
                param($LiteralPath,$ErrorAction,$PathType)
                if ($LiteralPath -eq 'HKCU:') { return $true }
                if ($PathType) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
                return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
            }
            $actual = (Tokens @(Section 'smartscreen')).browsers | ConvertFrom-Json
            Assert ($actual[0].policy.SafeBrowsingProtectionLevel -eq 0) 'Known Chromium mandatory off policy was discarded after malformed profile'
        } finally { $env:ProgramFiles = $saved[0]; ${env:ProgramFiles(x86)} = $saved[1]; $env:USERPROFILE = $saved[2] }
    }
    Case '10 cross-key policy ignores unreadable lower-priority flag' {
        function PolicyValue($path,$name) {
            if ($path -eq 'machine' -and $name -eq 'SafeBrowsingProtectionLevel') { return '0' }
            if ($path -eq 'user' -and $name -eq 'SafeBrowsingEnabled') { return '!' }
            return ''
        }
        $actual = BrowserPolicy 'machine' 'user' @('SafeBrowsingEnabled','SafeBrowsingProtectionLevel')
        Assert ($actual.SafeBrowsingProtectionLevel -eq 0) 'Known mandatory off policy was lost'
    }
    Case '10 Firefox machine policy survives unreadable user provider' {
        function FirefoxRegistry($path) {
            if ($path -eq 'HKLM:') { return @{'browser.safebrowsing.malware.enabled'=0} }
            throw 'Unreadable user Firefox policy'
        }
        $actual = @(FirefoxBrowser $root (Join-Path $root 'firefox.exe') 'user')
        Assert ($actual[0].policy.policies.Preferences['browser.safebrowsing.malware.enabled'] -eq 0) 'Known Firefox mandatory off policy was lost'
    }
    Case '3 screen-saver GPO overrides local enabled values' {
        $identity = [pscustomobject]@{IsSystem=$false}
        function RegValue($path,$name) {
            if ($name -eq 'ScreenSaveActive' -or $name -eq 'ScreenSaverIsSecure') { return '1' }
            if ($name -eq 'ScreenSaveTimeOut') { return '300' }
            return ''
        }
        function PolicyValue($path,$name) {
            if ($path -like '*Policies*Desktop' -and $name -eq 'ScreenSaveActive') { return '0' }
            return ''
        }
        $actual = Tokens @(Section 'secure_boot')
        if ($actual.ContainsKey('screen_savers')) { Assert ($actual.screen_savers -like '0|*') "Expected disabled effective policy, got $($actual.screen_savers)" }
        else { Assert ($actual.screen_active -eq '0') "Expected disabled effective policy, got $($actual.screen_active)" }
    }
    Case '11 SYSTEM reads interactive HKU settings rather than its own desktop' {
        $identity = [pscustomobject]@{IsSystem=$true}
        function Get-CimInstance { return [pscustomobject]@{LogonType=2} }
        function Get-CimAssociatedInstance { return [pscustomobject]@{SID='S-1-5-21-111-222-333-1001'} }
        function RegValue($path,$name) {
            if ($path -like 'Registry::HKEY_USERS*') { if ($name -eq 'ScreenSaveActive') { return '0' }; return '' }
            if ($name -eq 'ScreenSaveActive' -or $name -eq 'ScreenSaverIsSecure') { return '1' }
            if ($name -eq 'ScreenSaveTimeOut') { return '300' }
            return ''
        }
        function PolicyValue($path,$name) { return '' }
        $actual = Tokens @(Section 'secure_boot')
        if ($actual.ContainsKey('screen_savers')) { Assert ($actual.screen_savers -like '0|*') "Expected interactive user's disabled timer, got $($actual.screen_savers)" }
        else { Assert ($actual.screen_active -eq '0') "Expected interactive user's disabled timer, got SYSTEM $($actual.screen_active)" }
    }
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
if ($failures.Count -gt 0) { throw "$($failures.Count) Windows fix regressions failed: $($failures -join ', ')" }
Write-Output 'Windows fix source fixtures passed'
