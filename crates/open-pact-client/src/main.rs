mod checks;
mod locallog;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use open_pact_core::{
    Claim, Endorsement, Entry, Head, Manifest, ManifestHash, Os, Pseudonym, PublicKey,
    SignedManifest, TrustLevel, Virtualized, dev_key, sign_claim, verify_chain, verify_claim,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "open-pact-client",
    about = "Prove this device meets the company's signed manifest, nothing more"
)]
struct Cli {
    /// Directory for keys, the signed manifest and logs [default: ~/.config/open-pact]
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the company's manifest, sign it as the device owner and enrol this device
    Join {
        #[arg(long)]
        gateway: String,
        /// Sign without asking
        #[arg(long)]
        yes: bool,
    },
    /// Run the manifest's checks, send a signed claim and fetch a VPN certificate
    Check,
    /// Transparency log and local claim log
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Nothing runs in the background; uninstall = delete the binary and ~/.config/open-pact
    Stop,
}

#[derive(Subcommand)]
enum LogCommand {
    /// Print the verified, gateway-signed log head held on this device
    Head,
    /// Print every claim this device sent and the gateway's response
    Show,
}

#[derive(Serialize, Deserialize)]
struct Enrolment {
    gateway: String,
    manifest: ManifestHash,
    device: Pseudonym,
    salt: String,
}

#[derive(Deserialize)]
struct PublishedManifest {
    toml: String,
    company: Endorsement,
}

#[derive(Deserialize)]
struct LogPage {
    entries: Vec<Entry>,
    head: Head,
}

#[derive(Deserialize)]
struct Nonce {
    nonce: String,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Response {
    Accepted {
        warnings: Vec<String>,
        certificate_pem: Option<String>,
        ca_pem: String,
    },
    Denied {
        reasons: Vec<String>,
    },
}

struct Home(PathBuf);

impl Home {
    fn new(dir: Option<PathBuf>) -> Result<Home> {
        match dir {
            Some(dir) => Ok(Home(dir)),
            None => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                Ok(Home(PathBuf::from(home).join(".config/open-pact")))
            }
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let path = self.file(name);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).with_context(|| format!("{}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.0)?;
        let path = self.file(name);
        std::fs::write(&path, bytes).with_context(|| format!("{}", path.display()))?;
        Ok(path)
    }

    fn enrolment(&self) -> Result<Enrolment> {
        self.read_json("enrolment.json")?
            .context("not enrolled; run `open-pact-client join --gateway <url>` first")
    }
}

fn current_os() -> Result<Os> {
    match std::env::consts::OS {
        "macos" => Ok(Os::Macos),
        "windows" => Ok(Os::Windows),
        "linux" => Ok(Os::Linux),
        other => bail!("unsupported OS {other}"),
    }
}

fn virtualized() -> Virtualized {
    let probe = if cfg!(target_os = "macos") {
        std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_vmm_present"])
            .output()
    } else {
        std::process::Command::new("systemd-detect-virt")
            .arg("--quiet")
            .output()
    };
    match probe {
        Ok(out) if cfg!(target_os = "macos") && out.stdout.trim_ascii() == b"1" => Virtualized::Yes,
        Ok(out) if !cfg!(target_os = "macos") && out.status.success() => Virtualized::Yes,
        _ => Virtualized::No,
    }
}

fn collect_results(manifest: &Manifest, os: Os) -> BTreeMap<String, String> {
    let mut all = checks::run_all(os);
    manifest
        .body()
        .controls
        .iter()
        .filter_map(|c| {
            let value = all.remove(&c.id)?;
            c.output.contains(&value).then(|| (c.id.clone(), value))
        })
        .collect()
}

fn base(gateway: &str) -> &str {
    gateway.trim_end_matches('/')
}

async fn get_json<T: for<'de> Deserialize<'de>>(http: &reqwest::Client, url: String) -> Result<T> {
    http.get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .json()
        .await
        .with_context(|| format!("GET {url}"))
}

fn print_summary(manifest: &Manifest, company: &PublicKey, os: Os) {
    let b = manifest.body();
    let list = |set: &std::collections::BTreeSet<String>| {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    };
    println!("Manifest     {}", manifest.hash());
    println!(
        "Company key  {}  (compare with the fingerprint IT gave you)",
        company.fingerprint()
    );
    println!("Issuer       {}, valid from {}", b.issuer, b.valid_from);
    println!("Controller   {}", b.data_controller);
    println!("Retention    claims kept {}", b.claim_retention);
    println!("Recipients   {}", list(&b.claim_recipients));
    println!("Metadata     {}", list(&b.disclosed_metadata));
    println!(
        "Claims       valid {}, unknown results tolerated for {}, minimum trust {:?}",
        b.claim_max_age, b.unknown_grace, b.min_trust_level
    );
    println!();
    println!("Controls (this device runs {os}):");
    for c in &b.controls {
        let required = c
            .required
            .get(&os)
            .map_or("not required".to_string(), |r| format!("required {r}"));
        println!("  {:<20} {required}, grace {}", c.id, c.grace);
        if let Some(why) = &c.rationale {
            println!("  {:<20} why: {why}", "");
        }
        println!("  {:<20} can report: {}", "", c.output.join(", "));
    }
    println!();
}

fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

enum LogSync {
    Verified(Head),
    Alarm(open_pact_core::Error),
}

async fn sync_log(http: &reqwest::Client, home: &Home, gateway: &str) -> Result<LogSync> {
    let prev: Option<Head> = home.read_json("log-head.json")?;
    let from = prev.as_ref().map_or(0, |h| h.index + 1);
    let page: LogPage = get_json(http, format!("{}/v1/log?from={from}", base(gateway))).await?;
    match verify_chain(prev.as_ref(), &page.entries, &page.head) {
        Ok(head) => {
            home.write("log-head.json", &serde_json::to_vec_pretty(&head)?)?;
            Ok(LogSync::Verified(head))
        }
        Err(e) => Ok(LogSync::Alarm(e)),
    }
}

fn report_log(sync: LogSync, home: &Home) -> bool {
    match sync {
        LogSync::Verified(head) => {
            println!(
                "Transparency log verified: head #{} {}",
                head.index, head.hash
            );
            true
        }
        LogSync::Alarm(e) => {
            let bar = "!".repeat(72);
            eprintln!(
                "\n{bar}\n!! TRANSPARENCY LOG ALARM\n!! The gateway's history does not match the copy on this device.\n!! {e}"
            );
            eprintln!(
                "!! Keep {}: it is the last head the gateway signed for you.\n!! Compare it with colleagues: open-pact-client log head\n{bar}\n",
                home.file("log-head.json").display()
            );
            false
        }
    }
}

async fn join(home: &Home, gateway: &str, yes: bool) -> Result<bool> {
    let http = reqwest::Client::new();
    let published: PublishedManifest =
        get_json(&http, format!("{}/v1/manifest", base(gateway))).await?;
    let manifest = Manifest::parse(published.toml.as_bytes())?;
    if !published.company.verify(manifest.hash()) {
        bail!("the company signature does not match this manifest; refusing to show it");
    }
    let os = current_os()?;
    print_summary(&manifest, &published.company.key, os);
    if !yes && !confirm("Sign this manifest as the device owner?")? {
        println!("Not signed. Nothing was sent.");
        return Ok(false);
    }
    let owner = dev_key::load_or_create(&home.file("owner-dev.pem"))?;
    let device = dev_key::load_or_create(&home.file("device-dev.pem"))?;
    let signed = SignedManifest {
        toml: published.toml.clone(),
        company: published.company,
        owner: Endorsement::sign(&owner, manifest.hash()),
    };
    let resp = http
        .post(format!("{}/v1/enroll", base(gateway)))
        .json(&json!({"signed_manifest": signed, "device_key": PublicKey::from(&device)}))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        println!("Enrolment refused ({status}): {body}");
        return Ok(false);
    }
    home.write("manifest.toml", published.toml.as_bytes())?;
    let enrolment = Enrolment {
        gateway: gateway.to_string(),
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&PublicKey::from(&device)),
        salt: body["salt"].as_str().context("salt")?.to_string(),
    };
    home.write("enrolment.json", &serde_json::to_vec_pretty(&enrolment)?)?;
    println!("Owner signed {}", manifest.hash());
    println!("Enrolled as {}", enrolment.device);
    println!(
        "The public log records only sha256(salt || pseudonym); the salt stays in enrolment.json."
    );
    Ok(report_log(sync_log(&http, home, gateway).await?, home))
}

fn vpn_csr(home: &Home) -> Result<String> {
    let path = home.file("vpn-key.pem");
    let key = if path.exists() {
        KeyPair::from_pem(&std::fs::read_to_string(&path)?)?
    } else {
        let key = KeyPair::generate()?;
        std::fs::create_dir_all(&home.0)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&path)?
            .write_all(key.serialize_pem().as_bytes())?;
        key
    };
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    Ok(params.serialize_request(&key)?.pem()?)
}

fn describe_cert(pem: &str) -> Result<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
    let cert = pem.parse_x509()?;
    Ok(format!(
        "subject {}, expires {}",
        cert.subject(),
        cert.validity().not_after
    ))
}

fn print_hints(manifest: &Manifest, results: &BTreeMap<String, String>, os: Os) {
    for c in &manifest.body().controls {
        let (Some(required), Some(value)) = (c.required.get(&os), results.get(&c.id)) else {
            continue;
        };
        if required.contains(value) {
            continue;
        }
        if let Some(hint) = checks::fix_hint(&c.id, value, os) {
            println!("  fix {}: {hint}", c.id);
        }
    }
}

async fn check(home: &Home) -> Result<ExitCode> {
    let enrolment = home.enrolment()?;
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let device = dev_key::load(&home.file("device-dev.pem"))?;
    let os = current_os()?;
    let results = collect_results(&manifest, os);

    let http = reqwest::Client::new();
    let gateway = base(&enrolment.gateway);
    let nonce: Nonce = http
        .post(format!("{gateway}/v1/nonce"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let device_key = PublicKey::from(&device);
    let claim = Claim {
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: nonce.nonce,
        time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .context("clock")?,
        client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
        os,
        trust_level: TrustLevel::L0,
        virtualized: virtualized(),
        results,
        csr_pem: Some(vpn_csr(home)?),
    };
    let sent = serde_json::to_vec(&json!({ "jws": sign_claim(&claim, &device)? }))?;
    let resp = http
        .post(format!("{gateway}/v1/claim"))
        .header("content-type", "application/json")
        .body(sent.clone())
        .send()
        .await?;
    let received = resp.bytes().await?;
    locallog::append(&home.file("claims.jsonl"), &sent, &received)?;

    println!(
        "Sent {} results for {}:",
        claim.results.len(),
        manifest.hash()
    );
    for (id, value) in &claim.results {
        println!("  {id} = {value}");
    }
    let accepted = match serde_json::from_slice::<Response>(&received)
        .with_context(|| String::from_utf8_lossy(&received).into_owned())?
    {
        Response::Accepted {
            warnings,
            certificate_pem,
            ca_pem,
        } => {
            println!("ACCEPTED");
            for w in &warnings {
                println!("  warning: {w}");
            }
            print_hints(&manifest, &claim.results, os);
            let ca = home.write("ca.pem", ca_pem.as_bytes())?;
            if let Some(cert) = certificate_pem {
                let path = home.write("vpn-cert.pem", cert.as_bytes())?;
                println!(
                    "VPN certificate {} ({})",
                    path.display(),
                    describe_cert(&cert)?
                );
                println!("VPN CA          {}", ca.display());
            }
            true
        }
        Response::Denied { reasons } => {
            println!("DENIED");
            for r in &reasons {
                println!("  {r}");
            }
            print_hints(&manifest, &claim.results, os);
            false
        }
    };
    let log_ok = report_log(sync_log(&http, home, &enrolment.gateway).await?, home);
    Ok(match (log_ok, accepted) {
        (false, _) => ExitCode::from(2),
        (true, true) => ExitCode::SUCCESS,
        (true, false) => ExitCode::FAILURE,
    })
}

fn log_head(home: &Home) -> Result<()> {
    let head: Head = home
        .read_json("log-head.json")?
        .context("no log head yet; run join or check")?;
    println!("{}", serde_json::to_string_pretty(&head)?);
    println!("key fingerprint {}", head.key.fingerprint());
    Ok(())
}

fn log_show(path: &Path) -> Result<()> {
    let records = locallog::read(path)?;
    if records.is_empty() {
        println!("No claims sent yet.");
    }
    for r in records {
        println!("== {}  sent sha256:{}", r.time, r.sent_sha256);
        let sent: Value = serde_json::from_slice(&r.sent()?)?;
        match sent["jws"].as_str().map(verify_claim) {
            Some(Ok(verified)) => println!("{}", serde_json::to_string_pretty(verified.claim())?),
            _ => println!("{sent}"),
        }
        println!("-- response");
        println!("{}\n", String::from_utf8_lossy(&r.response()?));
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let home = Home::new(cli.home)?;
    let ok = |b: bool| {
        if b {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    };
    match cli.command {
        Command::Join { gateway, yes } => Ok(ok(join(&home, &gateway, yes).await?)),
        Command::Check => check(&home).await,
        Command::Log {
            command: LogCommand::Head,
        } => log_head(&home).map(|()| ExitCode::SUCCESS),
        Command::Log {
            command: LogCommand::Show,
        } => log_show(&home.file("claims.jsonl")).map(|()| ExitCode::SUCCESS),
        Command::Stop => {
            println!("Nothing runs in the background: the client runs only when you start it.");
            println!("To uninstall, delete the binary and {}.", home.0.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
