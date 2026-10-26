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
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_config_sections_and_expansion_need_no_filesystem() {
        let config = DeviceConfig::parse(
            r#"
[report]
collector = "https://collector.example.org/status"
[schedule]
enabled = true
run_as = "user"
[managed_repos]
folders = ["~/missing", "/missing/work"]
"#,
            Some(Path::new("/home/example")),
        )
        .unwrap();
        assert_eq!(config.report.unwrap().probe(), "collector.example.org:443");
        assert_eq!(
            config.managed_repos.unwrap().folders,
            [
                PathBuf::from("/home/example/missing"),
                PathBuf::from("/missing/work")
            ]
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
