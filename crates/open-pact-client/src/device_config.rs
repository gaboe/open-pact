use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{Home, report, schedule};

pub(crate) const FILE: &str = "open-pact.toml";

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceConfig {
    pub(crate) report: Option<Report>,
    pub(crate) schedule: Option<Schedule>,
    pub(crate) managed_repos: Option<ManagedRepos>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub(crate) collector: String,
    pub(crate) vpn_probe: Option<String>,
}

impl Report {
    pub(crate) fn probe(&self) -> String {
        self.vpn_probe.clone().unwrap_or_else(|| {
            let url = report::collector_url(&self.collector).expect("validated collector");
            format!(
                "{}:{}",
                url.host().unwrap(),
                url.port_or_known_default().unwrap()
            )
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Schedule {
    pub(crate) enabled: bool,
    pub(crate) run_as: RunAs,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RunAs {
    User,
    System,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRepos {
    pub(crate) folders: Vec<PathBuf>,
}

impl DeviceConfig {
    pub(crate) fn load(home: &Home) -> Result<Option<Self>> {
        let path = home.file(FILE);
        let text = match crate::read_home_file(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let text =
            String::from_utf8(text).with_context(|| format!("{} must be UTF-8", path.display()))?;
        let user_home =
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
        Self::parse(&text, user_home.as_deref())
            .with_context(|| format!("{}", path.display()))
            .map(Some)
    }

    pub(crate) fn parse(text: &str, user_home: Option<&Path>) -> Result<Self> {
        let mut config: Self = toml::from_str(text).context("section/key")?;
        if let Some(report) = &config.report {
            report::collector_url(&report.collector).context("[report].collector")?;
            schedule::probe_address(&report.probe()).context("[report].vpn_probe")?;
        }
        if let Some(schedule) = &config.schedule
            && schedule.run_as == RunAs::System
            && !cfg!(windows)
        {
            bail!("[schedule].run_as: system is available only on Windows");
        }
        if let Some(repos) = &mut config.managed_repos {
            for folder in &mut repos.folders {
                if folder == Path::new("~") || folder.starts_with("~/") {
                    let home = user_home
                        .context("[managed_repos].folders: cannot expand ~ without a user home")?;
                    *folder = home.join(folder.strip_prefix("~").unwrap());
                }
                if !folder.is_absolute() {
                    bail!(
                        "[managed_repos].folders: {} must be absolute after ~ expansion",
                        folder.display()
                    );
                }
            }
        }
        Ok(config)
    }
}

pub(crate) fn example(manifest: &open_pact_core::Manifest, os: open_pact_core::Os) -> String {
    let mut output = String::from(
        "# Save the sections you need as open-pact.toml next to manifest.toml.\n# The client reads this file and never writes it.\n",
    );
    for control in &manifest.body().controls {
        let requirement = control
            .required
            .get(&os)
            .map(ToString::to_string)
            .unwrap_or_else(|| "report only".into());
        for line in format!("{} requires {} on {}", control.id, requirement, os).lines() {
            output.push_str(&format!("# {line}\n"));
        }
    }
    output.push_str(
        r#"
[report]
collector = "https://collector.example.org/status"
# vpn_probe defaults to the collector host and port.
# vpn_probe = "vpn.example.org:443"

[schedule]
# Set enabled to true, then run open-pact-client apply.
enabled = false
# Use system only on Windows, from an elevated PowerShell prompt.
run_as = "user"

[managed_repos]
# Use absolute paths or ~/ paths. Paths stay on this device.
# These folders are reserved for managed repository checks.
folders = []
"#,
    );
    output
}

pub(crate) fn print_table(
    manifest: &open_pact_core::Manifest,
    os: open_pact_core::Os,
    config: Option<&DeviceConfig>,
    results: &std::collections::BTreeMap<String, open_pact_core::ControlValue>,
) {
    println!("control | manifest requirement | device setting | result");
    for control in &manifest.body().controls {
        let requirement = control
            .required
            .get(&os)
            .map(ToString::to_string)
            .unwrap_or_else(|| "report only".into());
        let setting = if matches!(
            control.id.as_str(),
            "managed_repos_outside" | "managed_repos_total"
        ) {
            config
                .and_then(|config| config.managed_repos.as_ref())
                .map(|repos| format!("managed_repos.folders = {:?}", repos.folders))
                .unwrap_or_else(|| "-".into())
        } else {
            "-".into()
        };
        let result = results
            .get(&control.id)
            .map(ToString::to_string)
            .unwrap_or_else(|| "-".into());
        println!("{} | {requirement} | {setting} | {result}", control.id);
    }
    if let Some(repos) = config.and_then(|config| config.managed_repos.as_ref()) {
        println!("managed_repos.folders = {:?}", repos.folders);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_config_load_names_the_file_section_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_owned());
        assert!(DeviceConfig::load(&home).unwrap().is_none());
        std::fs::write(
            home.file(FILE),
            "[report]\ncollector = 'http://example.org'",
        )
        .unwrap();
        let error = format!("{:#}", DeviceConfig::load(&home).unwrap_err());
        assert!(
            error.contains(FILE) && error.contains("[report].collector"),
            "{error}"
        );
        std::fs::write(
            home.file(FILE),
            "[schedule]\nenabled = false\nrun_as = 'user'",
        )
        .unwrap();
        assert!(DeviceConfig::load(&home).unwrap().unwrap().report.is_none());
    }

    #[test]
    fn device_config_example_is_valid_and_names_every_manifest_control() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let text = example(&manifest, open_pact_core::Os::Macos);
        let config = DeviceConfig::parse(&text, Some(Path::new("/home/example"))).unwrap();
        assert!(!config.schedule.unwrap().enabled);
        for control in &manifest.body().controls {
            assert!(text.contains(&format!("# {} requires ", control.id)));
        }
    }

    #[test]
    fn device_config_sections_and_expansion_need_no_filesystem() {
        let user_home = if cfg!(windows) {
            Path::new(r"C:\Users\example")
        } else {
            Path::new("/home/example")
        };
        let absolute = user_home.join("work");
        let text = format!(
            r#"
[report]
collector = "https://collector.example.org/status"
[schedule]
enabled = true
run_as = "user"
[managed_repos]
folders = ['~/missing', '{}']
"#,
            absolute.display()
        );
        let config = DeviceConfig::parse(&text, Some(user_home)).unwrap();
        assert_eq!(config.report.unwrap().probe(), "collector.example.org:443");
        assert_eq!(
            config.managed_repos.unwrap().folders,
            [user_home.join("missing"), absolute]
        );
        assert_eq!(
            DeviceConfig::parse("", None).unwrap(),
            DeviceConfig::default()
        );
    }

    #[test]
    fn device_config_rejects_unknown_keys_and_bad_values() {
        for (text, key) in [
            ("other = 1", "other"),
            ("[report]\ncollector = 'http://example.org'", "collector"),
            (
                "[report]\ncollector = 'https://example.org'\nvpn_probe = 'bad'",
                "vpn_probe",
            ),
            (
                "[report]\ncollector = 'https://example.org'\nextra = 1",
                "extra",
            ),
            ("[schedule]\nenabled = true\nrun_as = 'root'", "run_as"),
            (
                "[schedule]\nenabled = true\nrun_as = 'user'\nextra = 1",
                "extra",
            ),
            ("[managed_repos]\nfolders = ['relative']", "folders"),
            ("[managed_repos]\nfolders = []\nextra = 1", "extra"),
        ] {
            let error = format!("{:#}", DeviceConfig::parse(text, None).unwrap_err());
            assert!(error.contains(key), "{error}");
        }
    }

    #[test]
    fn device_config_probe_defaults_include_ipv6_and_explicit_port() {
        for (collector, expected) in [
            ("https://[::1]:8443/status", "[::1]:8443"),
            ("https://example.org:8443/status", "example.org:8443"),
        ] {
            let config =
                DeviceConfig::parse(&format!("[report]\ncollector = '{collector}'"), None).unwrap();
            assert_eq!(config.report.unwrap().probe(), expected);
        }
    }
}
