mod checks;
mod locallog;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use open_pact_core::{
    Claim, Manifest, Os, Pseudonym, PublicKey, TrustLevel, Virtualized, dev_key, sign_claim,
};
use serde::Deserialize;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    gateway: String,
    #[arg(long, default_value = "examples/manifest.toml")]
    manifest: PathBuf,
    /// Development-only software device key; created on first use.
    #[arg(long)]
    dev_key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Check,
}

#[derive(Deserialize)]
struct NonceResponse {
    nonce: String,
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

fn disk_encryption() -> &'static str {
    match run("fdesetup", &["status"]) {
        Some(t) if t.contains("FileVault is On") => "full",
        Some(t) if t.contains("FileVault is Off") => "none",
        _ => "unknown",
    }
}

fn firewall() -> &'static str {
    match run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        Some(t) if t.contains("enabled") => "on",
        Some(t) if t.contains("disabled") => "off",
        _ => "unknown",
    }
}

fn screen_lock() -> &'static str {
    let Some(t) = run("sysadminctl", &["-screenLock", "status"]) else {
        return "unknown";
    };
    if t.contains("screenLock is off") {
        return "off";
    }
    if t.contains("delay is immediate") {
        return "le_5min";
    }
    let seconds = t
        .split("delay is ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok());
    match seconds {
        Some(s) if s <= 300 => "le_5min",
        Some(s) if s <= 900 => "le_15min",
        Some(_) => "gt_15min",
        None => "unknown",
    }
}

fn os_supported() -> Option<&'static str> {
    let version = run("sw_vers", &["-productVersion"])?;
    let major: u32 = version.trim().split('.').next()?.parse().ok()?;
    Some(if major >= 14 { "yes" } else { "no" })
}

fn virtualized() -> Virtualized {
    match run("sysctl", &["-n", "kern.hv_vmm_present"]) {
        Some(t) if t.trim() == "1" => Virtualized::Yes,
        _ => Virtualized::No,
    }
}

fn builtin(check: &str) -> Option<&'static str> {
    if !cfg!(target_os = "macos") {
        return Some("unknown");
    }
    match check {
        "builtin:disk_encryption@1" => Some(disk_encryption()),
        "builtin:firewall@1" => Some(firewall()),
        "builtin:screen_lock@1" => Some(screen_lock()),
        "builtin:os_supported@1" => os_supported(),
        _ => Some("unknown"),
    }
}

fn current_os() -> Result<Os> {
    match std::env::consts::OS {
        "macos" => Ok(Os::Macos),
        "windows" => Ok(Os::Windows),
        "linux" => Ok(Os::Linux),
        other => anyhow::bail!("unsupported OS {other}"),
    }
}

fn default_dev_key() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/open-pact/device-dev.pem"))
}

async fn check(cli: &Cli) -> Result<bool> {
    let bytes =
        std::fs::read(&cli.manifest).with_context(|| format!("read {}", cli.manifest.display()))?;
    let manifest = Manifest::parse(&bytes)?;
    let key_path = match &cli.dev_key {
        Some(p) => p.clone(),
        None => default_dev_key()?,
    };
    let key = dev_key::load_or_create(&key_path)?;

    let results: BTreeMap<String, String> = manifest
        .body()
        .controls
        .iter()
        .filter_map(|c| {
            let value = builtin(&c.check)?;
            c.output
                .iter()
                .any(|o| o == value)
                .then(|| (c.id.clone(), value.to_string()))
        })
        .collect();

    let http = reqwest::Client::new();
    let base = cli.gateway.trim_end_matches('/');
    let nonce: NonceResponse = http
        .post(format!("{base}/v1/nonce"))
        .send()
        .await?
        .error_for_status()
        .context("nonce request")?
        .json()
        .await?;

    let device_key = PublicKey::from(&key);
    let claim = Claim {
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: nonce.nonce,
        time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .context("clock")?,
        client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
        os: current_os()?,
        trust_level: TrustLevel::L0,
        virtualized: virtualized(),
        results,
        csr_pem: None,
    };
    let jws = sign_claim(&claim, &key)?;
    let resp = http
        .post(format!("{base}/v1/claim"))
        .json(&serde_json::json!({ "jws": jws }))
        .send()
        .await?;
    let ok = resp.status().is_success();
    println!("{}", resp.text().await?);
    Ok(ok)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Check = cli.command;
    match check(&cli).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
