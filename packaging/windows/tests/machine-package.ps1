#Requires -Version 7
# Runs the machine package on a real Windows install, as an administrator. It
# builds the fixtures from four client versions, then runs the install sequence
# and checks the installed state after each step. Any mismatch throws.
param(
    [Parameter(Mandatory)][string]$Work
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..')).Path
. (Join-Path $root 'scripts' 'packaging' 'msi-tools.ps1')

$buildMsi = Join-Path $root 'scripts' 'packaging' 'build-msi.ps1'
$buildFailLate = Join-Path $PSScriptRoot 'build-fail-late.ps1'
$versionScript = Join-Path $root 'scripts' 'packaging' 'check-release-version.py'
$cargoToml = Join-Path $root 'Cargo.toml'
$wxs = Join-Path $root 'packaging' 'windows' 'open-pact-client.wxs'
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$installDir = Join-Path $env:ProgramFiles 'open-pact-client'
$client = Join-Path $installDir 'open-pact-client.exe'
$fixtures = Join-Path $Work 'fixtures'
$logs = Join-Path $Work 'logs'
$exes = Join-Path $Work 'exes'
foreach ($dir in $fixtures, $logs, $exes) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$upgradeCode = Get-UpgradeCode -Wxs $wxs
$manifest = Get-Content -Raw -LiteralPath $cargoToml

function Set-WorkspaceVersion {
    param([Parameter(Mandatory)][string]$Version)
    $text = Get-Content -Raw -LiteralPath $cargoToml
    $regex = [regex]::new('(?ms)(^\[workspace\.package\]\r?\n(?:(?!^\[).*?\r?\n)*?version = )"[^"]*"')
    if (-not $regex.IsMatch($text)) { throw 'Cargo.toml has no [workspace.package] version.' }
    $updated = $regex.Replace($text, { param($match) $match.Groups[1].Value + '"' + $Version + '"' }, 1)
    # The workspace pins open-pact-core to the workspace version, so the fixture
    # build must move that requirement with it.
    $core = [regex]::new('(?m)(^open-pact-core = \{[^}\r\n]*version = )"[^"]*"')
    if (-not $core.IsMatch($updated)) { throw 'Cargo.toml has no open-pact-core version requirement.' }
    $updated = $core.Replace($updated, { param($match) $match.Groups[1].Value + '"' + $Version + '"' }, 1)
    Set-Content -LiteralPath $cargoToml -Value $updated -NoNewline
}

function Build-Client {
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$Name)
    Set-WorkspaceVersion -Version $Version
    & cargo build --package open-pact-client --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "cargo build for $Name exits with $LASTEXITCODE." }
    $copy = Join-Path $exes "$Name.exe"
    Copy-Item -LiteralPath (Join-Path $root 'target' 'x86_64-pc-windows-msvc' 'debug' 'open-pact-client.exe') -Destination $copy -Force
    return $copy
}

function Invoke-Msiexec {
    param([Parameter(Mandatory)][string[]]$Arguments, [Parameter(Mandatory)][string]$LogName)
    $log = Join-Path $logs "$LogName.log"
    & $msiexec @Arguments /qn /norestart '/l*v' $log
    return $LASTEXITCODE
}

function Expect-Exit {
    param([int]$Actual, [int]$Expected, [string]$Step)
    if ($Actual -ne $Expected) { throw "$Step exits with $Actual, expected $Expected." }
}

function Get-MachinePathSegments {
    return @(([Environment]::GetEnvironmentVariable('Path', 'Machine')) -split ';' | Where-Object { $_ -ne '' })
}

function Get-RelatedProducts {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $codes = @()
    foreach ($code in $installer.RelatedProducts($upgradeCode)) { $codes += [string]$code }
    return $codes
}

function Expect-UserCannotWrite {
    # No allowed rule that applies to the folder itself gives Users,
    # Authenticated Users or Everyone a write, delete or permission right.
    $denied = [int]([System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly
    $broad = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0')
    foreach ($rule in (Get-Acl -LiteralPath $installDir).Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (([int]$rule.PropagationFlags -band $inheritOnly) -ne 0) { continue }
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($broad -notcontains $sid) { continue }
        if (([int]$rule.FileSystemRights -band $denied) -ne 0) {
            throw "$installDir grants $($rule.IdentityReference) a write right: $($rule.FileSystemRights)."
        }
    }
}

function Expect-Installed {
    param([Parameter(Mandatory)]$Package)
    $printed = & $client --version
    if ($LASTEXITCODE -ne 0) { throw "$client --version exits with $LASTEXITCODE." }
    $version = (($printed -join ' ') -split '\s+')[-1]
    if ($version -ne $Package.Client) { throw "$client prints $version, expected $($Package.Client)." }
    $held = (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash
    $wanted = (Get-FileHash -LiteralPath $Package.Exe -Algorithm SHA256).Hash
    if ($held -ne $wanted) { throw "$client does not hold the $($Package.Name) bytes." }
    $related = @(Get-RelatedProducts)
    if ($related.Count -ne 1 -or $related[0] -ne $Package.ProductCode) {
        throw "RelatedProducts is [$($related -join ', ')], expected $($Package.ProductCode)."
    }
    $entries = @(Get-MachinePathSegments | Where-Object { $_.TrimEnd('\') -ieq $installDir })
    if ($entries.Count -ne 1) { throw "The machine PATH names $installDir $($entries.Count) times, expected once." }
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($Package.ProductCode)"
    $display = (Get-ItemProperty -LiteralPath $key -Name DisplayVersion).DisplayVersion
    if ($display -ne $Package.Product) { throw "The uninstall key shows $display, expected $($Package.Product)." }
    Expect-UserCannotWrite
}

$specs = @(
    @{ Name = 'a1'; Client = '0.0.1'; Product = '0.0.199' },
    @{ Name = 'rc'; Client = '0.0.2-rc.1'; Product = '0.0.201' },
    @{ Name = 'b2'; Client = '0.0.2'; Product = '0.0.299' },
    @{ Name = 'fixture-fail-late'; Client = '0.0.3'; Product = '0.0.399' }
)
$packages = @{}

try {
    foreach ($spec in $specs) {
        $exe = Build-Client -Version $spec.Client -Name $spec.Name
        $msi = Join-Path $fixtures "$($spec.Name).msi"
        if ($spec.Name -eq 'fixture-fail-late') {
            & $buildFailLate -Exe $exe -Version $spec.Client -OutDir $fixtures
        } else {
            & $buildMsi -Exe $exe -Version $spec.Client -Out $msi
        }
        if ((Get-MsiProperty -Path $msi -Name 'ProductVersion') -ne $spec.Product) {
            throw "$msi has the wrong ProductVersion for $($spec.Client)."
        }
        $packages[$spec.Name] = [pscustomobject]@{
            Name = $spec.Name
            Client = $spec.Client
            Product = $spec.Product
            Exe = $exe
            Msi = $msi
            ProductCode = Get-MsiProperty -Path $msi -Name 'ProductCode'
        }
    }

    # The same b2 client in a second package: same ProductCode, new PackageCode.
    $b2 = $packages['b2']
    $rebuilt = Join-Path $Work 'b2-rebuilt.msi'
    & $buildMsi -Exe $b2.Exe -Version $b2.Client -Out $rebuilt
    if ((Get-MsiPackageCode -Path $rebuilt) -eq (Get-MsiPackageCode -Path $b2.Msi)) {
        throw 'The rebuilt b2 has the same PackageCode, so step 6 cannot show 1638.'
    }
    if ((Get-MsiProperty -Path $rebuilt -Name 'ProductCode') -ne $b2.ProductCode) {
        throw 'The rebuilt b2 has another ProductCode.'
    }

    $sums = Get-ChildItem -LiteralPath $fixtures -Filter '*.msi' | Sort-Object Name | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
    }
    Set-Content -LiteralPath (Join-Path $fixtures 'SHA256SUMS') -Value $sums -Encoding ascii

    $baseline = Get-MachinePathSegments

    # Step 1: a1 installs fresh.
    Expect-Exit (Invoke-Msiexec -Arguments @('/i', $packages['a1'].Msi) -LogName 'step1-a1-install') 0 'step 1: a1 install'
    Expect-Installed $packages['a1']

    # Step 2: rc and then b2 upgrade in place.
    Expect-Exit (Invoke-Msiexec -Arguments @('/i', $packages['rc'].Msi) -LogName 'step2-rc-over-a1') 0 'step 2: rc over a1'
    Expect-Installed $packages['rc']
    Expect-Exit (Invoke-Msiexec -Arguments @('/i', $b2.Msi) -LogName 'step2-b2-over-rc') 0 'step 2: b2 over rc'
    Expect-Installed $b2

    # Step 3: the fixture fails after its file copy, so the old b2 stays.
    $failed = 'step3-fixture-fail-late'
    Expect-Exit (Invoke-Msiexec -Arguments @('/i', $packages['fixture-fail-late'].Msi) -LogName $failed) 1603 'step 3: failing upgrade'
    $failLog = Join-Path $logs "$failed.log"
    $text = [IO.File]::ReadAllText($failLog) + [IO.File]::ReadAllText($failLog, [Text.Encoding]::Unicode)
    foreach ($marker in 'FailLate', 'Return value 3') {
        if (-not $text.Contains($marker)) { throw "The step 3 log lacks '$marker'." }
    }
    Expect-Installed $b2

    # Step 4: repair from the installed source keeps b2.
    Expect-Exit (Invoke-Msiexec -Arguments @('/fa', $b2.Msi) -LogName 'step4-b2-repair') 0 'step 4: b2 repair'
    Expect-Installed $b2

    # Step 5: downgrades fail and leave b2 in place.
    foreach ($name in 'a1', 'rc') {
        $code = Invoke-Msiexec -Arguments @('/i', $packages[$name].Msi) -LogName "step5-$name-over-b2"
        if ($code -eq 0) { throw "step 5: $name over b2 exits 0; a downgrade must fail." }
        Expect-Installed $b2
    }

    # Step 6: a rebuilt package with the same ProductCode is refused.
    Expect-Exit (Invoke-Msiexec -Arguments @('/i', $rebuilt) -LogName 'step6-b2-rebuilt') 1638 'step 6: rebuilt b2'
    Expect-Installed $b2

    # Step 7: uninstall removes the client, its folder and its PATH segment.
    Expect-Exit (Invoke-Msiexec -Arguments @('/x', $b2.Msi) -LogName 'step7-b2-uninstall') 0 'step 7: b2 uninstall'
    if (Test-Path -LiteralPath $client) { throw "$client is still there after uninstall." }
    if (Test-Path -LiteralPath $installDir) { throw "$installDir is still there after uninstall." }
    if (@(Get-RelatedProducts).Count -ne 0) { throw 'A product still registers the upgrade code after uninstall.' }
    if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($b2.ProductCode)") {
        throw 'The uninstall key is still there after uninstall.'
    }
    if (Compare-Object -ReferenceObject $baseline -DifferenceObject (Get-MachinePathSegments)) {
        throw 'The machine PATH differs from its baseline after uninstall.'
    }
    Write-Host 'The machine package install sequence passed all seven steps.'
}
finally {
    Set-Content -LiteralPath $cargoToml -Value $manifest -NoNewline
    if ($packages.ContainsKey('b2') -and (Test-Path -LiteralPath $client)) {
        & $msiexec /x $packages['b2'].Msi /qn /norestart | Out-Null
    }
}
