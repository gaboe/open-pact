# Reads Windows Installer packages through the WindowsInstaller COM API.
# Dot-source this file; it defines functions only.

function Get-MsiDatabase {
    param([Parameter(Mandatory)][string]$Path)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    return $installer.OpenDatabase($Path, 0)
}

function Get-MsiTableNames {
    param([Parameter(Mandatory)]$Database)
    $view = $Database.OpenView('SELECT `Name` FROM `_Tables`')
    $view.Execute()
    $names = @()
    while ($null -ne ($record = $view.Fetch())) {
        $names += $record.StringData(1)
    }
    $view.Close()
    return $names
}

function Get-MsiRows {
    # Each row is an array of the string values of the named columns. A table
    # that the package does not have has no rows.
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$Columns,
        [string]$Where = ''
    )
    if ((Get-MsiTableNames -Database $Database) -notcontains $Table) {
        return , @()
    }
    $view = $Database.OpenView("SELECT $Columns FROM ``$Table``$Where")
    $view.Execute()
    $count = @($Columns -split ',').Count
    $rows = [System.Collections.Generic.List[object]]::new()
    while ($null -ne ($record = $view.Fetch())) {
        $values = @(for ($i = 1; $i -le $count; $i++) { $record.StringData($i) })
        $rows.Add($values)
    }
    $view.Close()
    return , $rows.ToArray()
}

function Get-MsiProperty {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $rows = Get-MsiRows -Database (Get-MsiDatabase -Path $Path) -Table 'Property' -Columns 'Value' -Where " WHERE Property = '$Name'"
    if ($rows.Count -ne 1) { throw "$Path has $($rows.Count) rows for the property $Name, expected 1." }
    return [string]$rows[0][0]
}

function Get-MsiPackageCode {
    # The package code is the revision number in the summary information.
    param([Parameter(Mandatory)][string]$Path)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $summary = $installer.SummaryInformation($Path, 0)
    return [string]$summary.Property(9)
}

function Get-UpgradeCode {
    param([Parameter(Mandatory)][string]$Wxs)
    $match = [regex]::Match((Get-Content -Raw -LiteralPath $Wxs), 'UpgradeCode="(\{[0-9A-F-]{36}\})"')
    if (-not $match.Success) { throw "$Wxs has no UpgradeCode." }
    return $match.Groups[1].Value
}

function Get-MsiVersionCodes {
    # The ProductVersion and ProductCode that check-release-version.py derives for a release version.
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$UpgradeCode,
        [Parameter(Mandatory)][string]$Script
    )
    $output = & python $Script --msi $Version $UpgradeCode
    if ($LASTEXITCODE -ne 0) { throw "check-release-version.py --msi $Version exits with $LASTEXITCODE." }
    $parts = ([string]$output).Trim() -split '\s+'
    return [pscustomobject]@{ ProductVersion = $parts[0]; ProductCode = $parts[1] }
}
