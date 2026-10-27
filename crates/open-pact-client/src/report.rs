use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use open_pact_core::{Manifest, Os, Pseudonym};
use serde::Serialize;
use serde_json::Value;

use crate::{DeviceKey, Home, checks, collect_results, current_os};

pub(crate) const SPEC_VERSION: &str = "1.1";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReportType {
    Periodic,
    Connect,
    Event,
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    spec_version: &'static str,
    device_id: Pseudonym,
    report_id: String,
    time: String,
    report_type: ReportType,
    solution: String,
    os: Os,
    os_version: String,
    key_protection: &'static str,
    results: BTreeMap<String, Value>,
}

pub(crate) fn collector_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("invalid collector URL")?;
    if url.scheme() != "https" || url.host_str().is_none() {
        bail!("collector must be an HTTPS URL");
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("collector URL must not contain credentials or a fragment");
    }
    Ok(url)
}

fn result_values<T: Serialize>(results: BTreeMap<String, T>) -> Result<BTreeMap<String, Value>> {
    results
        .into_iter()
        .map(|(id, value)| {
            let value = serde_json::to_value(value)?;
            if !value.is_string() && !value.is_i64() && !value.is_u64() && !value.is_null() {
                bail!("control {id} did not return text, an integer, or null");
            }
            Ok((id, value))
        })
        .collect()
}

impl Report {
    fn new<T: Serialize>(
        key: &DeviceKey,
        os: Os,
        os_version: String,
        results: BTreeMap<String, T>,
    ) -> Result<Self> {
        Ok(Self {
            spec_version: SPEC_VERSION,
            device_id: Pseudonym::of(&key.public_key()),
            report_id: uuid::Uuid::new_v4().to_string(),
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            report_type: ReportType::Periodic,
            solution: format!("open-pact-client {}", env!("CARGO_PKG_VERSION")),
            os,
            os_version,
            key_protection: match key {
                DeviceKey::Software(_) => "os_permissions",
                #[cfg(target_os = "macos")]
                DeviceKey::SecureEnclave(_) => "secure_enclave",
            },
            results: result_values(results)?,
        })
    }

    fn sign(&self, key: &DeviceKey) -> Result<String> {
        if self.device_id != Pseudonym::of(&key.public_key()) {
            bail!("report device does not match signing key");
        }
        let input = format!(
            "{}.{}",
            B64.encode(r#"{"alg":"ES256","typ":"JOSE"}"#),
            B64.encode(serde_json::to_vec(self)?)
        );
        Ok(format!(
            "{input}.{}",
            String::from(key.sign(input.as_bytes())?)
        ))
    }
}

fn os_version(os: Os) -> Result<String> {
    let (program, args): (&str, &[&str]) = match os {
        Os::Macos => ("/usr/bin/sw_vers", &["-productVersion"]),
        Os::Linux => ("uname", &["-r"]),
        Os::Windows => return Ok(windows_os_version()),
    };
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .context("read OS version")?;
    if !output.status.success() {
        bail!("OS version command failed");
    }
    let version = String::from_utf8(output.stdout)?.trim().to_owned();
    if version.is_empty() {
        bail!("OS version was empty");
    }
    Ok(version)
}

struct WindowsVersionParts<'a> {
    build: Option<&'a str>,
    ubr: Option<&'a str>,
    display_version: Option<&'a str>,
}

fn windows_os_version() -> String {
    let script = concat!(
        "$ErrorActionPreference = 'Stop'; ",
        "try { ",
        "$v = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop; ",
        "$build = [string]$v.CurrentBuildNumber; ",
        "if ([string]::IsNullOrWhiteSpace($build)) { $build = [string]$v.CurrentBuild }; ",
        "$ubr = [string]$v.UBR; $display = [string]$v.DisplayVersion; ",
        "[Console]::Out.WriteLine(\"$build`t$ubr`t$display\") ",
        "} catch { [Console]::Out.WriteLine(\"`t`t\") }",
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
    format_windows_version(output.as_deref())
}

fn format_windows_version(raw: Option<&str>) -> String {
    let mut fields = raw
        .unwrap_or_default()
        .trim_end_matches(['\r', '\n'])
        .split('\t');
    let parts = WindowsVersionParts {
        build: fields
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        ubr: fields
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        display_version: fields
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    };
    let build = parts
        .build
        .and_then(|value| value.parse::<u32>().ok().map(|number| (value, number)));
    let ubr = parts.ubr.filter(|value| value.parse::<u32>().is_ok());
    let mut version = Vec::new();
    if let Some((_, build_number)) = build {
        let product = if build_number >= 22_000 { "11" } else { "10" };
        version.push(product.to_owned());
    }
    if let Some(display_version) = parts.display_version {
        version.push(display_version.to_owned());
    }
    if let Some((build, _)) = build {
        version.push(match ubr {
            Some(ubr) => format!("{build}.{ubr}"),
            None => build.to_owned(),
        });
    }
    if version.is_empty() {
        "unknown".into()
    } else {
        version.join(" ")
    }
}

pub(crate) fn prepare(home: &Home) -> Result<(Report, BTreeMap<String, bool>)> {
    let enrolment = home.enrolment()?;
    let manifest = Manifest::parse(&crate::read_home_file(&home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    checks::check_supported(&manifest).map_err(anyhow::Error::msg)?;
    let key = DeviceKey::load(&home.0)?;
    if enrolment.device != Pseudonym::of(&key.public_key()) {
        bail!("device key does not match enrolment");
    }
    let os = current_os()?;
    let config = crate::device_config::DeviceConfig::load(home)?;
    let repo_scan = crate::stored_repo_scan(home)?;
    let results = collect_results(&manifest, os, config.as_ref(), repo_scan.as_ref());
    let compliance = open_pact_core::control_compliance(&manifest, os, &results);
    Ok((Report::new(&key, os, os_version(os)?, results)?, compliance))
}

pub(crate) async fn run(home: &Home, collector: &str, dry_run: bool) -> Result<()> {
    collector_url(collector)?;
    let (report, _) = prepare(home)?;
    send(home, collector, report, dry_run, None)
        .await
        .map(|_| ())
}

pub(crate) async fn run_scheduled(
    home: &Home,
    collector: &str,
    probe: &str,
    mut report: Report,
    report_type: ReportType,
) -> Result<bool> {
    report.report_type = report_type;
    send(home, collector, report, false, Some(probe)).await
}

async fn send(
    home: &Home,
    collector: &str,
    report: Report,
    dry_run: bool,
    probe: Option<&str>,
) -> Result<bool> {
    let url = collector_url(collector)?;
    let key = DeviceKey::load(&home.0)?;
    let jws = report.sign(&key)?;
    if dry_run {
        println!("{}", serde_json::to_string_pretty(&report)?);
        println!("{jws}");
        return Ok(false);
    }
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    if let Some(probe) = probe
        && !crate::schedule::vpn_up(probe).await
    {
        return Ok(false);
    }
    let response = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/jose")
        .body(jws)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("send report to collector")?;
    if !response.status().is_success() {
        bail!(
            "collector did not acknowledge report: HTTP {}",
            response.status()
        );
    }
    println!("Collector acknowledged report {}", report.report_id);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_pact_core::dev_key;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    #[test]
    fn formats_windows_version_from_registry_parts() {
        assert_eq!(
            format_windows_version(Some("26100\t4061\t24H2")),
            "11 24H2 26100.4061"
        );
        assert_eq!(
            format_windows_version(Some("19045\t6216\t22H2")),
            "10 22H2 19045.6216"
        );
    }

    #[test]
    fn windows_version_uses_available_registry_parts() {
        assert_eq!(format_windows_version(None), "unknown");
        assert_eq!(format_windows_version(Some("\t\t")), "unknown");
        assert_eq!(
            format_windows_version(Some("22631\t\t24H2")),
            "11 24H2 22631"
        );
        assert_eq!(format_windows_version(Some("\t4061\t24H2")), "24H2");
        assert_eq!(format_windows_version(Some("invalid\t4061\t24H2")), "24H2");
        assert_eq!(format_windows_version(Some("22000\tinvalid\t")), "11 22000");
    }

    #[test]
    fn builds_report_and_verifies_jws_with_public_key() {
        let key = DeviceKey::Software(dev_key::generate());
        let report = Report::new(
            &key,
            Os::Linux,
            "6.0".into(),
            BTreeMap::from([("firewall".into(), "on")]),
        )
        .unwrap();
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "device_id",
                "key_protection",
                "os",
                "os_version",
                "report_id",
                "report_type",
                "results",
                "solution",
                "spec_version",
                "time"
            ]
        );
        assert_eq!(value["spec_version"], "1.1");
        assert_eq!(
            value["device_id"],
            Pseudonym::of(&key.public_key()).to_string()
        );
        assert_eq!(value["results"]["firewall"], "on");
        assert_eq!(value["report_type"], "periodic");
        assert_eq!(value["os"], "linux");
        assert_eq!(value["os_version"], "6.0");
        assert_eq!(value["key_protection"], "os_permissions");
        assert_eq!(
            value["solution"],
            format!("open-pact-client {}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            uuid::Uuid::parse_str(&report.report_id)
                .unwrap()
                .get_version_num(),
            4
        );
        assert!(chrono::DateTime::parse_from_rfc3339(&report.time).is_ok());
        let jws = report.sign(&key).unwrap();
        let parts: Vec<_> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            serde_json::from_slice::<Value>(&B64.decode(parts[0]).unwrap()).unwrap()["alg"],
            "ES256"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&B64.decode(parts[1]).unwrap()).unwrap(),
            value
        );
        let signature = Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
        let verifier =
            VerifyingKey::from_sec1_bytes(&key.public_key().sec1_uncompressed()).unwrap();
        assert!(
            verifier
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .is_ok()
        );
        assert!(
            verifier
                .verify(format!("{}.{}x", parts[0], parts[1]).as_bytes(), &signature)
                .is_err()
        );
        assert!(
            report
                .sign(&DeviceKey::Software(dev_key::generate()))
                .is_err()
        );
    }

    #[test]
    fn all_report_types_are_signed_and_preserve_json_types() {
        let key = DeviceKey::Software(dev_key::generate());
        for (report_type, name) in [
            (ReportType::Periodic, "periodic"),
            (ReportType::Connect, "connect"),
            (ReportType::Event, "event"),
        ] {
            let mut report = Report::new(
                &key,
                Os::Windows,
                "10.0".into(),
                BTreeMap::from([("age".into(), 42)]),
            )
            .unwrap();
            report.report_type = report_type;
            let jws = report.sign(&key).unwrap();
            let parts: Vec<_> = jws.split('.').collect();
            let value: Value = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(value["report_type"], name);
            assert_eq!(value["results"]["age"], 42);
            for field in [
                "spec_version",
                "device_id",
                "report_id",
                "time",
                "report_type",
                "solution",
                "os",
                "os_version",
                "key_protection",
            ] {
                assert!(value[field].is_string(), "{field}");
            }
            assert!(value["results"].is_object());
            let signature = Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
            let verifier =
                VerifyingKey::from_sec1_bytes(&key.public_key().sec1_uncompressed()).unwrap();
            verifier
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .unwrap();
        }
    }

    #[test]
    fn adapter_preserves_numbers_without_converting_numeric_text() {
        assert_eq!(
            result_values(BTreeMap::from([("age".into(), 42)])).unwrap()["age"],
            42
        );
        assert_eq!(
            result_values(BTreeMap::from([("age".into(), "42")])).unwrap()["age"],
            "42"
        );
        assert!(result_values(BTreeMap::from([("age".into(), true)])).is_err());
        assert!(result_values(BTreeMap::from([("last_event".into(), None::<String>)])).unwrap()["last_event"].is_null());
    }

    #[test]
    fn collector_requires_https_and_no_embedded_credentials() {
        for url in [
            "http://localhost/report",
            "file:///report",
            "https://user:pass@example.org/report",
            "https://example.org/report#fragment",
        ] {
            assert!(collector_url(url).is_err(), "{url}");
        }
        assert!(collector_url("https://collector.example.org/report").is_ok());
    }
}
