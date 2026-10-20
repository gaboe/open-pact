use std::fs::File;
use std::io::Read;

use chrono::{DateTime, Utc};
use open_pact_core::ControlValue;
use serde_json::Value;

use super::exec::run_status;
use super::macos_v3::bounded_age;

pub fn preboot_auth() -> ControlValue {
    let output = run_status(
        "lsblk",
        &["-s", "-n", "-o", "NAME,TYPE,RO,RM,FSTYPE,MOUNTPOINT"],
    );
    output
        .filter(|r| r.success)
        .map_or("unknown", |r| parse_preboot(&r.text))
        .into()
}

fn parse_preboot(text: &str) -> &'static str {
    match super::linux::parse_lsblk_inverse(text) {
        "none" => "none",
        // LUKS keyslots do not distinguish passwords from keyfiles. A standard user
        // cannot reliably inspect the root volume metadata to establish its unlock method.
        _ => "unknown",
    }
}

pub fn antimalware_signature_age_days() -> ControlValue {
    for root in ["/var/lib/clamav", "/usr/local/share/clamav"] {
        let mut dates = vec![];
        for extension in ["cld", "cvd"] {
            let path = format!("{root}/daily.{extension}");
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return "unknown".into(),
            };
            let mut header = [0; 512];
            if file.read_exact(&mut header).is_err() {
                return "unknown".into();
            }
            let Some(date) = parse_cvd_header(&header) else {
                return "unknown".into();
            };
            dates.push(date);
        }
        if let Some(last) = dates.into_iter().max() {
            return bounded_age((Utc::now() - last).num_days(), 3650);
        }
    }
    "unknown".into()
}

fn parse_cvd_header(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let fields: Vec<_> = text.trim().split(':').collect();
    if fields.first() != Some(&"ClamAV-VDB") || fields.len() != 9 {
        return None;
    }
    DateTime::from_timestamp(fields[8].trim().parse().ok()?, 0)
}

pub fn local_log_retention_days() -> ControlValue {
    let Some(output) = run_status(
        "journalctl",
        &[
            "--system",
            "--no-pager",
            "--output=json",
            "--output-fields=__REALTIME_TIMESTAMP",
            "--lines=+1",
        ],
    )
    .filter(|r| r.success) else {
        return "unknown".into();
    };
    parse_journal_age(&output.text, Utc::now())
}

fn parse_journal_age(text: &str, now: DateTime<Utc>) -> ControlValue {
    // Do not suppress journalctl warnings: a permission warning means partial visibility.
    let Some(micros) = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v["__REALTIME_TIMESTAMP"].as_str()?.parse::<i64>().ok())
    else {
        return "unknown".into();
    };
    let Some(oldest) = DateTime::from_timestamp_micros(micros) else {
        return "unknown".into();
    };
    if oldest > now {
        return "unknown".into();
    }
    bounded_age((now - oldest).num_days(), i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn luks_without_verified_unlock_method_is_unknown() {
        assert_eq!(
            parse_preboot("sda2 part 0 0 ext4 /\n sda disk 0 0\n"),
            "none"
        );
        assert_eq!(
            parse_preboot(
                "cryptroot crypt 0 0 ext4 /\n sda2 part 0 0 crypto_LUKS\n sda disk 0 0\n"
            ),
            "unknown"
        );
        assert_eq!(parse_preboot(""), "unknown");
    }
    #[test]
    fn daily_database_uses_embedded_timestamp_not_file_mtime() {
        let text = "ClamAV-VDB:14 Oct 2026 08-00 +0000:28000:3000000:90:00000000000000000000000000000000:fictional-signature:fictional-builder:1791964800";
        assert_eq!(
            parse_cvd_header(text.as_bytes()).unwrap().timestamp(),
            1791964800
        );
        assert!(parse_cvd_header(b"not a database").is_none());
        assert!(parse_cvd_header(b"ClamAV-VDB:date:1:2:3:hash:sig:builder:no-date").is_none());
    }
    #[test]
    fn oldest_readable_system_entry_and_permission_warnings() {
        let now = DateTime::from_timestamp(1791964800, 0).unwrap();
        let text = format!(
            "{{\"__REALTIME_TIMESTAMP\":\"{}\"}}\n",
            (now.timestamp() - 10 * 86400) * 1_000_000
        );
        assert_eq!(parse_journal_age(&text, now), ControlValue::Integer(10));
        assert_eq!(
            parse_journal_age(
                &(text.clone() + "Hint: You are currently not seeing messages from other users.\n"),
                now
            ),
            "unknown"
        );
        assert_eq!(parse_journal_age("-- No entries --", now), "unknown");
        assert_eq!(
            parse_journal_age(&text, now - chrono::Duration::days(11)),
            "unknown"
        );
    }
}
