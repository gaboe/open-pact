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
    #[cfg(test)]
    let local_test_http = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    #[cfg(not(test))]
    let local_test_http = false;
    if (url.scheme() != "https" && !local_test_http) || url.host_str().is_none() {
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
            key_protection: key.protection(),
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
    send(home, home, collector, report, dry_run, None)
        .await
        .map(|_| ())
}

pub(crate) async fn run_scheduled(
    home: &Home,
    state_home: &Home,
    collector: &str,
    probe: &str,
    mut report: Report,
    report_type: ReportType,
) -> Result<bool> {
    report.report_type = report_type;
    send(home, state_home, collector, report, false, Some(probe)).await
}

async fn send(
    home: &Home,
    log_home: &Home,
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
        .https_only(!cfg!(test))
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
    let mut response = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/jose")
        .body(jws.as_bytes().to_vec())
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("send report to collector")?;
    let status = response.status();
    let mut response_body = Vec::new();
    let _response_incomplete = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => response_body.extend_from_slice(&chunk),
            Ok(None) => break false,
            Err(_) => {
                eprintln!(
                    "warning: could not read collector response body for local report history"
                );
                break true;
            }
        }
    };
    if let Err(error) = crate::locallog::append_report_retained(
        &log_home.file("reports.jsonl"),
        &log_home.file("report-state.json"),
        jws.as_bytes(),
        &response_body,
        status.as_u16(),
        false,
    ) {
        eprintln!("warning: could not write local report history: {error}");
    }
    if !status.is_success() {
        bail!("collector did not acknowledge report: HTTP {}", status);
    }
    println!("Collector acknowledged report {}", report.report_id);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_pact_core::dev_key;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn collector(
        status: u16,
        response: &'static [u8],
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        collector_with_response_length(status, response, response.len()).await
    }

    async fn collector_with_response_length(
        status: u16,
        response: &'static [u8],
        response_length: usize,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let body_start = loop {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..body_start]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap();
            while request.len() < body_start + content_length {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
            }
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "Error"
            };
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_length
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(response).await.unwrap();
            request[body_start..body_start + content_length].to_vec()
        });
        (format!("http://{address}/report"), task)
    }

    fn report_home() -> (tempfile::TempDir, Home, Report) {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let key = dev_key::generate();
        std::fs::write(home.file("device-dev.pem"), dev_key::to_pem(&key)).unwrap();
        let report = Report::new(
            &DeviceKey::Software(key),
            Os::Linux,
            "test".into(),
            BTreeMap::from([("firewall".into(), "on")]),
        )
        .unwrap();
        (dir, home, report)
    }

    #[tokio::test]
    async fn acknowledged_report_records_exact_request_and_response() {
        let (_dir, home, report) = report_home();
        let state_dir = tempfile::tempdir().unwrap();
        let state_home = Home(state_dir.path().to_path_buf());
        let (url, server) = collector(201, b"{\"accepted\":true}").await;
        send(&home, &state_home, &url, report, false, None)
            .await
            .unwrap();
        let sent = server.await.unwrap();
        let records = crate::locallog::read(&state_home.file("reports.jsonl")).unwrap();
        assert!(!home.file("reports.jsonl").exists());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sent().unwrap(), sent);
        assert_eq!(records[0].status, Some(201));
        assert_eq!(records[0].response().unwrap(), b"{\"accepted\":true}");
    }

    #[tokio::test]
    async fn non_success_response_is_recorded_and_keeps_send_error() {
        let (_dir, home, report) = report_home();
        let (url, server) = collector(503, b"unavailable").await;
        let error = send(&home, &home, &url, report, false, None)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("collector did not acknowledge report: HTTP 503"));
        let sent = server.await.unwrap();
        let records = crate::locallog::read(&home.file("reports.jsonl")).unwrap();
        assert_eq!(records[0].sent().unwrap(), sent);
        assert_eq!(records[0].status, Some(503));
        assert_eq!(records[0].response().unwrap(), b"unavailable");
    }

    #[tokio::test]
    async fn connect_failure_and_dry_run_do_not_create_history() {
        let (_dir, home, report) = report_home();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert!(
            send(
                &home,
                &home,
                &format!("http://{address}/report"),
                report,
                false,
                None
            )
            .await
            .is_err()
        );
        assert!(!home.file("reports.jsonl").exists());

        let (_dry_dir, dry_home, dry_report) = report_home();
        send(
            &dry_home,
            &dry_home,
            "https://collector.example.org/report",
            dry_report,
            true,
            None,
        )
        .await
        .unwrap();
        assert!(!dry_home.file("reports.jsonl").exists());
    }

    #[tokio::test]
    async fn history_write_failure_does_not_change_acknowledgement() {
        let (_dir, home, report) = report_home();
        std::fs::create_dir(home.file("reports.jsonl")).unwrap();
        let (url, server) = collector(200, b"ok").await;
        assert!(send(&home, &home, &url, report, false, None).await.unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_response_body_is_marked_in_report_history() {
        let (_dir, home, report) = report_home();
        let (url, server) = collector_with_response_length(200, b"ok", 10).await;

        assert!(send(&home, &home, &url, report, false, None).await.unwrap());
        server.await.unwrap();
        let line = std::fs::read_to_string(home.file("reports.jsonl")).unwrap();
        let record: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        assert!(record["response_incomplete"].as_bool().unwrap());
    }

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
            "http://collector.example.org/report",
            "file:///report",
            "https://user:pass@example.org/report",
            "https://example.org/report#fragment",
        ] {
            assert!(collector_url(url).is_err(), "{url}");
        }
        assert!(collector_url("http://localhost/report").is_ok());
        assert!(collector_url("https://collector.example.org/report").is_ok());
    }
}
