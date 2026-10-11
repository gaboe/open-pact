use std::collections::BTreeMap;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use open_pact_core::Claim;
use serde::Deserialize;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    gateway: String,
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

fn disk_encryption() -> &'static str {
    if !cfg!(target_os = "macos") {
        return "unknown";
    }
    let Ok(out) = std::process::Command::new("fdesetup").arg("status").output() else {
        return "unknown";
    };
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("FileVault is On") {
        "full"
    } else if text.contains("FileVault is Off") {
        "none"
    } else {
        "unknown"
    }
}

async fn check(gateway: &str) -> Result<bool> {
    let http = reqwest::Client::new();
    let base = gateway.trim_end_matches('/');
    let nonce: NonceResponse = http
        .post(format!("{base}/v1/nonce"))
        .send()
        .await?
        .error_for_status()
        .context("nonce request")?
        .json()
        .await?;
    let claim = Claim {
        manifest: "sha256:poc".into(),
        device: "pseudonym:poc-software-key".into(),
        nonce: nonce.nonce,
        time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
        results: BTreeMap::from([("disk_encryption".to_string(), disk_encryption().to_string())]),
    };
    let resp = http.post(format!("{base}/v1/claim")).json(&claim).send().await?;
    let ok = resp.status().is_success();
    println!("{}", resp.text().await?);
    Ok(ok)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Check = cli.command;
    match check(&cli.gateway).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
