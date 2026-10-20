use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use open_pact_core::{Manifest, Os, Pseudonym};
use serde::Serialize;
use serde_json::Value;

use crate::{DeviceKey, Home, checks, collect_results, current_os};

#[derive(Debug, Serialize)]
struct Report {
    spec_version: &'static str,
    device_id: Pseudonym,
    report_id: String,
    time: String,
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
            if !value.is_string() && !value.is_i64() && !value.is_u64() {
                bail!("control {id} did not return text or an integer");
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
            spec_version: "1.0",
            device_id: Pseudonym::of(&key.public_key()),
            report_id: uuid::Uuid::new_v4().to_string(),
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            solution: format!("open-pact {}", env!("CARGO_PKG_VERSION")),
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
        Os::Windows => (
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Environment]::OSVersion.Version.ToString()",
            ],
        ),
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

pub(crate) async fn run(home: &Home, collector: &str, dry_run: bool) -> Result<()> {
    run_with_probe(home, collector, dry_run, None)
        .await
        .map(|_| ())
}

pub(crate) async fn run_scheduled(home: &Home, collector: &str, probe: &str) -> Result<bool> {
    run_with_probe(home, collector, false, Some(probe)).await
}

async fn run_with_probe(
    home: &Home,
    collector: &str,
    dry_run: bool,
    probe: Option<&str>,
) -> Result<bool> {
    let url = collector_url(collector)?;
    let enrolment = home.enrolment()?;
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    checks::check_supported(&manifest).map_err(anyhow::Error::msg)?;
    let key = DeviceKey::load(&home.0)?;
    if enrolment.device != Pseudonym::of(&key.public_key()) {
        bail!("device key does not match enrolment");
    }
    let os = current_os()?;
    let report = Report::new(&key, os, os_version(os)?, collect_results(&manifest, os))?;
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
                "results",
                "solution",
                "spec_version",
                "time"
            ]
        );
        assert_eq!(value["spec_version"], "1.0");
        assert_eq!(
            value["device_id"],
            Pseudonym::of(&key.public_key()).to_string()
        );
        assert_eq!(value["results"]["firewall"], "on");
        assert_eq!(value["os"], "linux");
        assert_eq!(value["os_version"], "6.0");
        assert_eq!(value["key_protection"], "os_permissions");
        assert_eq!(
            value["solution"],
            format!("open-pact {}", env!("CARGO_PKG_VERSION"))
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
