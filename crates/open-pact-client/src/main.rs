mod checks;
mod locallog;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use open_pact_core::{
    Checkpoint, Claim, Endorsement, Entry, EntryKind, LogCheckpoint, LogHash, LogKey, Manifest,
    ManifestHash, Note, Os, Pseudonym, PublicKey, SignedManifest, TrustLevel, Virtualized, dev_key,
    root, sign_claim, verify_claim, verify_consistency, verify_inclusion,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
    /// Print the last verified, gateway-signed log checkpoint held on this device
    Head,
    /// Fetch and verify the inclusion proof of one log entry [default: this device's enrolment]
    Prove { index: Option<u64> },
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
struct Entries {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Proof {
    proof: Vec<LogHash>,
}

const LOG_KEY: &str = "log-key.txt";
const LOG_CHECKPOINT: &str = "log-checkpoint.txt";
const LEGACY_LOG_HEAD: &str = "log-head.json";

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

    fn read_text(&self, name: &str) -> Result<Option<String>> {
        let path = self.file(name);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }

    /// The last checkpoint this device verified. It was verified when stored, so it is trusted as is.
    fn checkpoint(&self) -> Result<Option<Checkpoint>> {
        self.read_text(LOG_CHECKPOINT)?
            .map(|text| -> Result<Checkpoint> {
                let note = Note::parse(&text)?;
                Ok(Checkpoint::parse(&note.text)?)
            })
            .transpose()
            .with_context(|| format!("{}", self.file(LOG_CHECKPOINT).display()))
    }

    /// A v0.1.0 hash-chain head with no Merkle checkpoint next to it.
    fn has_legacy_log_head(&self) -> bool {
        self.file(LEGACY_LOG_HEAD).exists() && !self.file(LOG_CHECKPOINT).exists()
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
    disclosable(manifest, os, checks::run_all(os))
}

fn disclosable(
    manifest: &Manifest,
    os: Os,
    mut all: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    manifest
        .body()
        .controls
        .iter()
        .filter(|c| c.required.contains_key(&os))
        .filter_map(|c| {
            let value = all.remove(&c.id)?;
            c.output.contains(&value).then(|| (c.id.clone(), value))
        })
        .collect()
}

/// The checkpoint goes into the claim only if the signed manifest discloses it.
fn disclosable_checkpoint(manifest: &Manifest, cp: Option<Checkpoint>) -> Option<LogCheckpoint> {
    cp.filter(|_| {
        manifest
            .body()
            .disclosed_metadata
            .contains("log_checkpoint")
    })
    .map(|cp| LogCheckpoint {
        size: cp.size,
        root: cp.root,
    })
}

fn base(gateway: &str) -> &str {
    gateway.trim_end_matches('/')
}

async fn get_text(http: &reqwest::Client, url: String) -> Result<String> {
    http.get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .text()
        .await
        .with_context(|| format!("GET {url}"))
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
    Verified(Checkpoint),
    Alarm(String),
}

fn alarm(e: impl std::fmt::Display) -> LogSync {
    LogSync::Alarm(e.to_string())
}

async fn pinned_log_key(http: &reqwest::Client, home: &Home, gateway: &str) -> Result<LogKey> {
    if let Some(vkey) = home.read_text(LOG_KEY)? {
        return Ok(LogKey::parse(&vkey)?);
    }
    let vkey = get_text(http, format!("{}/v1/log/key", base(gateway))).await?;
    let key = LogKey::parse(&vkey)?;
    home.write(LOG_KEY, format!("{}\n", key.vkey()).as_bytes())?;
    println!("Pinned log key {}", key.vkey());
    Ok(key)
}

/// Fetches the gateway's checkpoint and checks that it extends the one stored on this device.
/// On first contact it downloads every entry and recomputes the root instead.
async fn sync_log(http: &reqwest::Client, home: &Home, gateway: &str) -> Result<LogSync> {
    let key = pinned_log_key(http, home, gateway).await?;
    let prev = home.checkpoint()?;
    let text = get_text(http, format!("{}/v1/log/checkpoint", base(gateway))).await?;
    let new = match Note::parse(&text).and_then(|note| key.verify(&note)) {
        Ok(checkpoint) => checkpoint,
        Err(e) => return Ok(alarm(e)),
    };
    let checked = match &prev {
        None => {
            let page: Entries = get_json(
                http,
                format!("{}/v1/log/entries?from=0&to={}", base(gateway), new.size),
            )
            .await?;
            let leaves: Vec<LogHash> = page.entries.iter().map(Entry::leaf_hash).collect();
            let indexes_ok = page
                .entries
                .iter()
                .enumerate()
                .all(|(i, e)| e.index == i as u64);
            if indexes_ok && leaves.len() as u64 == new.size && root(&leaves) == new.root {
                Ok(())
            } else {
                Err(format!(
                    "the entries the gateway served do not hash to its signed root {}",
                    new.root
                ))
            }
        }
        Some(old) if old.size == new.size => {
            verify_consistency(old.size, new.size, &old.root, &new.root, &[])
                .map_err(|e| e.to_string())
        }
        Some(old) => {
            let url = format!(
                "{}/v1/log/proof/consistency?from={}&to={}",
                base(gateway),
                old.size,
                new.size
            );
            match get_json::<Proof>(http, url).await {
                Ok(p) => verify_consistency(old.size, new.size, &old.root, &new.root, &p.proof)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(format!("no consistency proof from the gateway: {e:#}")),
            }
        }
    };
    if let Err(e) = checked {
        return Ok(alarm(e));
    }
    home.write(LOG_CHECKPOINT, text.as_bytes())?;
    Ok(LogSync::Verified(new))
}

/// A root as the checkpoint text shows it.
fn b64(root: &LogHash) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(root.0)
}

fn report_log(sync: LogSync, home: &Home) -> bool {
    match sync {
        LogSync::Verified(cp) => {
            println!(
                "Transparency log verified: checkpoint size {} root {}",
                cp.size,
                b64(&cp.root)
            );
            true
        }
        LogSync::Alarm(e) => {
            let bar = "!".repeat(72);
            eprintln!(
                "\n{bar}\n!! TRANSPARENCY LOG ALARM\n!! The gateway's history does not match the copy on this device.\n!! {e}"
            );
            eprintln!(
                "!! Keep {}: it is the last checkpoint the gateway signed for you.\n!! Compare it with colleagues: open-pact-client log head\n{bar}\n",
                home.file(LOG_CHECKPOINT).display()
            );
            false
        }
    }
}

fn print_log_upgrade(home: &Home) {
    eprintln!(
        "The transparency log format was upgraded: it is now a Merkle tree with signed checkpoints.\n\
         {} holds a head in the old hash-chain format, which cannot be compared with a checkpoint.\n\
         This is not a log alarm. Run `open-pact-client join --gateway <url>` again to review the\n\
         manifest and pin the new log.",
        home.file(LEGACY_LOG_HEAD).display()
    );
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
    if let Some(index) = body["log_index"].as_u64() {
        println!("Enrolment is log entry #{index}; prove it with: open-pact-client log prove");
    }
    println!(
        "The public log records only sha256(salt || pseudonym); the salt stays in enrolment.json."
    );
    if home.has_legacy_log_head() {
        std::fs::remove_file(home.file(LEGACY_LOG_HEAD))?;
        println!("Removed the old hash-chain log head; this device now pins the Merkle log.");
    }
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
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
        return Ok(ExitCode::FAILURE);
    }
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let device = dev_key::load(&home.file("device-dev.pem"))?;
    let os = current_os()?;
    let results = collect_results(&manifest, os);

    let http = reqwest::Client::new();
    let gateway = base(&enrolment.gateway);
    let sync = sync_log(&http, home, gateway).await?;
    let log_checkpoint = disclosable_checkpoint(&manifest, home.checkpoint()?);
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
        log_checkpoint,
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
    let log_ok = report_log(sync, home);
    Ok(match (log_ok, accepted) {
        (false, _) => ExitCode::from(2),
        (true, true) => ExitCode::SUCCESS,
        (true, false) => ExitCode::FAILURE,
    })
}

fn log_head(home: &Home) -> Result<()> {
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
    }
    let text = home
        .read_text(LOG_CHECKPOINT)?
        .context("no log checkpoint yet; run join or check")?;
    print!("{text}");
    if let Some(vkey) = home.read_text(LOG_KEY)? {
        println!("\npinned log key {}", vkey.trim_end());
    }
    Ok(())
}

fn commitment(enrolment: &Enrolment) -> Result<String> {
    let mut h = Sha256::new();
    h.update(hex::decode(&enrolment.salt).context("salt in enrolment.json")?);
    h.update(enrolment.device.as_str());
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

async fn log_prove(home: &Home, index: Option<u64>) -> Result<ExitCode> {
    let enrolment = home.enrolment()?;
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
        return Ok(ExitCode::FAILURE);
    }
    let http = reqwest::Client::new();
    let gateway = base(&enrolment.gateway);
    let sync = sync_log(&http, home, gateway).await?;
    let LogSync::Verified(cp) = sync else {
        report_log(sync, home);
        return Ok(ExitCode::from(2));
    };
    let mine = commitment(&enrolment)?;
    let is_mine =
        |e: &Entry| e.kind == EntryKind::DeviceEnrolled && e.data["commitment"] == mine.as_str();
    let entry = match index {
        Some(i) => {
            let url = format!("{gateway}/v1/log/entries?from={i}&to={}", i + 1);
            let page: Entries = get_json(&http, url).await?;
            page.entries
                .into_iter()
                .find(|e| e.index == i)
                .with_context(|| format!("the gateway did not serve entry #{i}"))?
        }
        None => {
            let url = format!("{gateway}/v1/log/entries?from=0&to={}", cp.size);
            let page: Entries = get_json(&http, url).await?;
            page.entries
                .into_iter()
                .find(is_mine)
                .context("no enrolment entry for this device in the log")?
        }
    };
    let leaf = entry.leaf_hash();
    let url = format!(
        "{gateway}/v1/log/proof/inclusion?index={}&size={}",
        entry.index, cp.size
    );
    let proof: Proof = get_json(&http, url).await?;
    println!("Entry #{} {}", entry.index, serde_json::to_string(&entry)?);
    println!("Leaf hash  {leaf}  (sha256 of 0x00 || JCS({{kind, data}}))");
    println!("Proof      {} hashes", proof.proof.len());
    for h in &proof.proof {
        println!("           {h}");
    }
    if let Err(e) = verify_inclusion(&leaf, entry.index, cp.size, &proof.proof, &cp.root) {
        report_log(alarm(e), home);
        return Ok(ExitCode::from(2));
    }
    println!(
        "INCLUDED in the checkpoint this device verified: size {} root {}",
        cp.size,
        b64(&cp.root)
    );
    if is_mine(&entry) {
        println!(
            "This entry is your enrolment: sha256(salt || pseudonym) from enrolment.json matches."
        );
    }
    Ok(ExitCode::SUCCESS)
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
            command: LogCommand::Prove { index },
        } => log_prove(&home, index).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_only_results_the_manifest_requires_on_this_os() {
        let toml = include_str!("../../../examples/manifest.toml").replace(
            r#"required = { macos = "on", windows = "on", linux = "on" }"#,
            r#"required = { macos = "on" }"#,
        );
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let all = BTreeMap::from(
            [
                ("disk_encryption", "full"),
                ("firewall", "on"),
                ("screen_lock", "le_5min"),
                ("os_supported", "unknown"),
                ("antimalware_active", "yes"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let ids = |os| -> Vec<String> {
            disclosable(&manifest, os, all.clone())
                .into_keys()
                .collect()
        };
        assert_eq!(
            ids(Os::Macos),
            ["disk_encryption", "firewall", "screen_lock"]
        );
        assert_eq!(ids(Os::Linux), ["disk_encryption", "screen_lock"]);
    }

    #[test]
    fn sends_log_checkpoint_only_if_the_manifest_discloses_it() {
        let toml = include_str!("../../../examples/manifest.toml");
        let cp = Checkpoint {
            origin: "pact.example.com/log".into(),
            size: 3,
            root: LogHash([1; 32]),
        };
        let listed = Manifest::parse(toml.as_bytes()).unwrap();
        assert_eq!(
            disclosable_checkpoint(&listed, Some(cp.clone())),
            Some(LogCheckpoint {
                size: 3,
                root: LogHash([1; 32])
            })
        );
        let unlisted = toml.replace(r#", "log_checkpoint"]"#, "]");
        assert_ne!(unlisted, toml);
        let unlisted = Manifest::parse(unlisted.as_bytes()).unwrap();
        assert_eq!(disclosable_checkpoint(&unlisted, Some(cp)), None);
    }
}
