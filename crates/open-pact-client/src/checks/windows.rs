use chrono::{NaiveDate, Utc};
use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::buckets;
use open_pact_core::ControlValue;
use super::exec::run;
const POWERSHELL: &str = r#"
$ErrorActionPreference = 'Stop'
function Emit($key, $value) { if ($null -eq $value) { $value = '' }; [Console]::WriteLine("$key`t$value") }
function RegValue($path, $name) {
    try {
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        if ($null -eq $item.PSObject.Properties[$name]) { return '' }
        return [string]$item.$name
    } catch { return '!' }
}
try { $bitlocker = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection'); Emit 'bitlocker' $bitlocker } catch { Emit 'bitlocker' '' }
try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name)
    if ($profiles.Count -eq 3) { Emit 'firewall' (($profiles | ForEach-Object { $_.Enabled.ToString() }) -join ' ') } else { Emit 'firewall' '' }
} catch { Emit 'firewall' '' }
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
Emit 'secure_boot' (RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')
Emit 'lock_policy' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs')
Emit 'screen_active' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive')
Emit 'screen_secure' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure')
Emit 'screen_timeout' (RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut')
$current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Emit 'os' (@($current.CurrentBuild, $current.DisplayVersion, $current.EditionID, $current.InstallationType) -join '|')
Emit 'autologin' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
try {
    $dates = @(Get-HotFix | Where-Object InstalledOn | ForEach-Object { try { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch {} })
    Emit 'updates' ($dates -join ' ')
} catch { Emit 'updates' '' }
"#;

static VALUES: OnceLock<BTreeMap<String, String>> = OnceLock::new();

pub fn disk_encryption() -> &'static str {
    value("bitlocker").map_or("unknown", parse_bitlocker)
}

pub fn firewall() -> &'static str {
    value("firewall").map_or("unknown", parse_firewall)
}

/// A lock timeout set by policy wins over the user's secure screen saver.
pub fn screen_lock() -> &'static str {
    match value("lock_policy") {
        Some("!") | None => return "unknown",
        Some(value) if !value.is_empty() => match parse_dword(value) {
            Some(seconds) if seconds > 0 => return buckets::lock_delay(u64::from(seconds)),
            Some(_) => {}
            None => return "unknown",
        },
        _ => {}
    }
    parse_screen_saver(
        value("screen_active"),
        value("screen_secure"),
        value("screen_timeout"),
    )
}

pub fn os_supported() -> &'static str {
    value("os").map_or("unknown", |data| {
        parse_os_supported(data, Utc::now().date_naive())
    })
}

pub fn os_patch_age_days() -> ControlValue {
    value("patch_date").and_then(parse_last_update).and_then(|date| {
        let days = Utc::now().date_naive().signed_duration_since(date).num_days();
        (days >= 0).then_some(ControlValue::Integer(days))
    }).unwrap_or_else(|| "unknown".into())
}

pub fn auto_login() -> &'static str {
    value("autologin").map_or("unknown", |value| {
        if value == "!" {
            "unknown"
        } else {
            parse_auto_login(value)
        }
    })
}

pub fn secure_boot() -> &'static str {
    value("secure_boot")
        .filter(|v| *v != "!")
        .and_then(parse_dword)
        .map_or("unknown", |v| match v {
            0 => "off",
            1 => "on",
            _ => "unknown",
        })
}

pub fn antimalware_active() -> &'static str {
    value("antimalware").map_or("unknown", parse_antimalware)
}

fn value(name: &str) -> Option<&'static str> {
    let values = VALUES.get_or_init(|| {
        let out = run(
            "powershell.exe",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL,
            ],
        )
        .unwrap_or_default();
        parse_values(&out)
    });
    values.get(name).map(String::as_str)
}

fn parse_values(out: &str) -> BTreeMap<String, String> {
    out.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('\t')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn parse_dword(value: &str) -> Option<u32> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse().ok())
}

/// The Shell property has no official value table, so unrecognized values stay unknown.
pub fn parse_bitlocker(out: &str) -> &'static str {
    match out.trim() {
        "1" => "full",
        "3" | "4" | "5" | "8" => "partial",
        "2" | "7" => "none",
        _ => "unknown",
    }
}

pub fn parse_firewall(out: &str) -> &'static str {
    let profiles: Vec<&str> = out.split_whitespace().collect();
    if profiles.len() != 3 || !profiles.iter().all(|p| matches!(*p, "True" | "False")) {
        "unknown"
    } else if profiles.iter().all(|p| *p == "True") {
        "on"
    } else {
        "off"
    }
}

pub fn parse_screen_saver(
    active: Option<&str>,
    secure: Option<&str>,
    timeout: Option<&str>,
) -> &'static str {
    match (active, secure) {
        (Some("0"), _) | (Some("1"), Some("0")) => "off",
        (Some("1"), Some("1")) => timeout
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map_or("unknown", buckets::lock_delay),
        _ => "unknown",
    }
}

pub fn parse_os_supported(data: &str, today: NaiveDate) -> &'static str {
    let mut fields = data.split('|');
    let (Some(build), Some(version), Some(edition), Some(install_type)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return "unknown";
    };
    let Ok(build) = build.parse::<u32>() else {
        return "unknown";
    };
    if !install_type.eq_ignore_ascii_case("Client") {
        return "no";
    }
    if !is_known_client_edition(edition) {
        return "unknown";
    }
    let supported_until = match (build, version, edition) {
        (14393, "1607", "EnterpriseS") => Some((2026, 10, 13)),
        (14393, "1607", "IoTEnterpriseS") => Some((2032, 1, 13)),
        (17763, "1809", "EnterpriseS" | "IoTEnterpriseS") => Some((2029, 1, 9)),
        (19044, "21H2", "EnterpriseS") => Some((2027, 1, 12)),
        (19044, "21H2", "IoTEnterpriseS") => Some((2032, 1, 13)),
        (22631, "23H2", "Enterprise" | "Education") => Some((2026, 11, 10)),
        (26100, "24H2", "EnterpriseS") => Some((2029, 10, 9)),
        (26100, "24H2", "IoTEnterpriseS") => Some((2034, 10, 10)),
        (26100, "24H2", "Enterprise" | "Education") => Some((2027, 10, 12)),
        (
            26100,
            "24H2",
            "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation",
        ) => Some((2026, 10, 13)),
        (
            26200,
            "25H2",
            "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation",
        ) => Some((2027, 10, 12)),
        (26200, "25H2", "Enterprise" | "Education") => Some((2028, 10, 11)),
        (build, "26H1", edition) if build >= 28000 && is_consumer_edition(edition) => {
            Some((2028, 3, 15))
        }
        (build, "26H1", "Enterprise" | "Education") if build >= 28000 => Some((2029, 3, 14)),
        (build, "26H2", edition) if build >= 26300 && is_consumer_edition(edition) => {
            Some((2028, 10, 9))
        }
        (build, "26H2", "Enterprise" | "Education") if build >= 26300 => Some((2029, 10, 9)),
        (19045, "22H2", _) => return "unknown",
        (_, _, edition) if edition.ends_with('S') => return "unknown",
        _ => None,
    };
    supported_until
        .and_then(|(y, m, d)| NaiveDate::from_ymd_opt(y, m, d))
        .map_or("no", |end| if today <= end { "yes" } else { "no" })
}

fn is_consumer_edition(edition: &str) -> bool {
    matches!(
        edition,
        "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation"
    )
}

fn is_known_client_edition(edition: &str) -> bool {
    is_consumer_edition(edition)
        || matches!(
            edition,
            "Enterprise" | "Education" | "EnterpriseS" | "IoTEnterprise" | "IoTEnterpriseS"
        )
}

pub fn parse_last_update(out: &str) -> Option<NaiveDate> {
    out.split_whitespace()
        .filter_map(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .max()
}

pub fn parse_auto_login(value: &str) -> &'static str {
    match value.trim() {
        "1" => "on",
        "0" | "" => "off",
        _ => "unknown",
    }
}

/// Security Center does not document `productState`; its bit layout is community-derived.
pub fn parse_antimalware(out: &str) -> &'static str {
    if out.trim() == "defender=yes" {
        return "yes";
    }
    let states: Vec<u32> = out
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if states.is_empty() {
        "unknown"
    } else if states.iter().any(|s| (s >> 12) & 0xF == 1) {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dword() {
        assert_eq!(parse_dword("0x1"), Some(1));
        assert_eq!(parse_dword("0x384"), Some(900));
        assert_eq!(parse_dword("900"), Some(900));
        assert_eq!(parse_dword("bad"), None);
    }

    #[test]
    fn values_use_tagged_lines() {
        let out = "bitlocker\t1\r\nfirewall\tTrue False True\r\nwarning text\r\n";
        let values = parse_values(out);
        assert_eq!(values.get("bitlocker").map(String::as_str), Some("1"));
        assert_eq!(
            values.get("firewall").map(String::as_str),
            Some("True False True")
        );
        assert!(!values.contains_key("warning text"));
    }

    #[test]
    fn bitlocker() {
        assert_eq!(parse_bitlocker("1\r\n"), "full");
        assert_eq!(parse_bitlocker("2"), "none");
        assert_eq!(parse_bitlocker("3"), "partial");
        assert_eq!(parse_bitlocker("4"), "partial");
        assert_eq!(parse_bitlocker("5"), "partial");
        assert_eq!(parse_bitlocker("6"), "unknown");
        assert_eq!(parse_bitlocker("7"), "none");
        assert_eq!(parse_bitlocker("8"), "partial");
        assert_eq!(parse_bitlocker("0"), "unknown");
        assert_eq!(parse_bitlocker(""), "unknown");
    }

    #[test]
    fn firewall() {
        assert_eq!(parse_firewall("True\r\nTrue\r\nTrue\r\n"), "on");
        assert_eq!(parse_firewall("True\r\nFalse\r\nTrue\r\n"), "off");
        assert_eq!(parse_firewall("True\r\nTrue\r\n"), "unknown");
        assert_eq!(
            parse_firewall("Get-NetFirewallProfile : Access denied"),
            "unknown"
        );
    }

    #[test]
    fn screen_saver() {
        let saver = |t| parse_screen_saver(Some("1"), Some("1"), Some(t));
        assert_eq!(saver("300"), "le_5min");
        assert_eq!(saver("900"), "le_15min");
        assert_eq!(saver("1200"), "gt_15min");
        assert_eq!(parse_screen_saver(Some("1"), Some("0"), Some("300")), "off");
        assert_eq!(parse_screen_saver(Some("0"), Some("1"), Some("300")), "off");
        assert_eq!(parse_screen_saver(None, None, None), "unknown");
    }

    #[test]
    fn os_supported() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        assert_eq!(
            parse_os_supported("26200|25H2|Professional|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported("26100|24H2|Professional|Client", today),
            "no"
        );
        assert_eq!(
            parse_os_supported("19045|22H2|Professional|Client", today),
            "unknown"
        );
        assert_eq!(
            parse_os_supported("19044|21H2|EnterpriseS|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported("19044|21H2|IoTEnterpriseS|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported(
                "19044|21H2|EnterpriseS|Client",
                NaiveDate::from_ymd_opt(2027, 1, 13).unwrap()
            ),
            "no"
        );
        assert_eq!(parse_os_supported("bad", today), "unknown");
    }

    #[test]
    fn last_update() {
        let out = "2026-08-12\r\n2026-09-09\r\n2026-07-08\r\n";
        assert_eq!(parse_last_update(out), NaiveDate::from_ymd_opt(2026, 9, 9));
        assert_eq!(parse_last_update(""), None);
    }

    #[test]
    fn auto_login() {
        assert_eq!(parse_auto_login("1"), "on");
        assert_eq!(parse_auto_login("0"), "off");
        assert_eq!(parse_auto_login(""), "off");
        assert_eq!(parse_auto_login("enabled"), "unknown");
    }

    #[test]
    fn antimalware() {
        assert_eq!(parse_antimalware("397568\r\n"), "yes");
        assert_eq!(parse_antimalware("393472\r\n"), "no");
        assert_eq!(parse_antimalware("393472\r\n397568\r\n"), "yes");
        assert_eq!(parse_antimalware(""), "unknown");
        assert_eq!(parse_antimalware("defender=yes"), "yes");
    }
}
