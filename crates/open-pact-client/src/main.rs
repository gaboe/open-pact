mod checks;
mod device_key;
mod locallog;
#[cfg(target_os = "macos")]
mod secure_enclave;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use device_key::DeviceKey;
use open_pact_core::{
    Checkpoint, Claim, Endorsement, EnrolRequest, Entry, EntryKind, Invitation, LogCheckpoint,
    LogHash, LogKey, Manifest, ManifestHash, Note, Os, Pseudonym, PublicKey, SignedManifest,
    Virtualized, dev_key, root, verify_claim, verify_consistency, verify_inclusion,
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
    /// Allow a plain http:// gateway other than localhost. For development only
    #[arg(long, global = true)]
    insecure_dev: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the gateway against the invitation from IT, show the manifest, sign it and enrol
    Join {
        /// The opi1: invitation string from IT
        invitation: String,
        /// Sign without asking
        #[arg(long)]
        yes: bool,
        /// Keep a new device key in a file (trust level L0) even when a Secure Enclave is available
        #[arg(long)]
        software_key: bool,
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
    /// Where the log holds this enrolment's entries. A hint only: every check verifies them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_entries: Option<OwnEntries>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct OwnEntries {
    manifest: u64,
    enrolment: u64,
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
const COMPANY_KEY: &str = "company-key.txt";
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
            .context("not enrolled; run `open-pact-client join <invitation from IT>` first")
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

fn check_scheme(gateway: &str, insecure_dev: bool) -> Result<()> {
    let url = reqwest::Url::parse(gateway).with_context(|| format!("gateway URL {gateway:?}"))?;
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if local || insecure_dev => Ok(()),
        "http" => bail!(
            "refusing plain http:// to {gateway}: the invitation code and claims would travel unencrypted. \
             Use https://, or --insecure-dev for a development gateway"
        ),
        other => bail!("unsupported gateway URL scheme {other:?}"),
    }
}

/// The API never redirects, so a redirect cannot move the client from https to http.
fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
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
        "Company key  {}  (matches your invitation)",
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
    Verified(Checkpoint, OwnEntries),
    Alarm(String),
}

fn alarm(e: impl std::fmt::Display) -> LogSync {
    LogSync::Alarm(e.to_string())
}

/// The gateway serves at most this many entries per request.
const ENTRIES_PAGE: u64 = 256;

/// Entries `from..to`, fetched page by page.
async fn fetch_entries(
    http: &reqwest::Client,
    gateway: &str,
    from: u64,
    to: u64,
) -> Result<Vec<Entry>> {
    let mut entries = vec![];
    let mut next = from;
    while next < to {
        let end = to.min(next + ENTRIES_PAGE);
        let url = format!("{}/v1/log/entries?from={next}&to={end}", base(gateway));
        let page: Entries = get_json(http, url).await?;
        if page.entries.is_empty() {
            bail!("the gateway served no entries from #{next}");
        }
        next += page.entries.len() as u64;
        entries.extend(page.entries);
    }
    Ok(entries)
}

struct Pins {
    company: String,
    log: LogKey,
}

impl Pins {
    fn load(home: &Home) -> Result<Pins> {
        let (Some(company), Some(log)) = (home.read_text(COMPANY_KEY)?, home.read_text(LOG_KEY)?)
        else {
            bail!(
                "this device has no pinned company key and log key; run `open-pact-client join <invitation from IT>`"
            );
        };
        Ok(Pins {
            company: company.trim().to_string(),
            log: LogKey::parse(log.trim())?,
        })
    }

    fn save(&self, home: &Home) -> Result<()> {
        home.write(COMPANY_KEY, format!("{}\n", self.company).as_bytes())?;
        home.write(LOG_KEY, format!("{}\n", self.log.vkey()).as_bytes())?;
        Ok(())
    }

    /// What differs between the pinned keys and the ones a gateway serves, if anything.
    fn differs(&self, company: &str, log: &str) -> Option<String> {
        if company != self.company {
            return Some(format!(
                "the company key changed: pinned {}, gateway now shows {company}",
                self.company
            ));
        }
        if log.trim() != self.log.vkey() {
            return Some(format!(
                "the log key changed: pinned {}, gateway now shows {}",
                self.log.vkey(),
                log.trim()
            ));
        }
        None
    }

    async fn compare(&self, http: &reqwest::Client, gateway: &str) -> Result<Option<String>> {
        let published: PublishedManifest =
            get_json(http, format!("{}/v1/manifest", base(gateway))).await?;
        let log = get_text(http, format!("{}/v1/log/key", base(gateway))).await?;
        Ok(self.differs(&published.company.key.fingerprint(), &log))
    }
}

/// Fetches the gateway's checkpoint and checks that it extends the one stored on this device.
/// On first contact it downloads every entry and recomputes the root instead.
async fn sync_checkpoint(
    http: &reqwest::Client,
    home: &Home,
    gateway: &str,
) -> Result<Result<Checkpoint, String>> {
    let pins = Pins::load(home)?;
    if let Some(changed) = pins.compare(http, gateway).await? {
        return Ok(Err(changed));
    }
    let key = pins.log;
    let prev = home.checkpoint()?;
    let text = get_text(http, format!("{}/v1/log/checkpoint", base(gateway))).await?;
    let new = match Note::parse(&text).and_then(|note| key.verify(&note)) {
        Ok(checkpoint) => checkpoint,
        Err(e) => return Ok(Err(e.to_string())),
    };
    let checked = match &prev {
        None => {
            let entries = fetch_entries(http, gateway, 0, new.size).await?;
            let leaves: Vec<LogHash> = entries.iter().map(Entry::leaf_hash).collect();
            let indexes_ok = entries.iter().enumerate().all(|(i, e)| e.index == i as u64);
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
        return Ok(Err(e));
    }
    home.write(LOG_CHECKPOINT, text.as_bytes())?;
    Ok(Ok(new))
}

/// Fetches entry `index` and its inclusion proof, and checks both against `cp`.
async fn prove_entry(
    http: &reqwest::Client,
    gateway: &str,
    cp: &Checkpoint,
    index: u64,
    what: &str,
    expected: impl Fn(&Entry) -> bool,
) -> Result<(Entry, Vec<LogHash>), String> {
    if index >= cp.size {
        return Err(format!(
            "{what} (entry #{index}) is outside the checkpoint of size {}",
            cp.size
        ));
    }
    let entry = match fetch_entries(http, gateway, index, index + 1).await {
        Ok(mut page) if page.len() == 1 && page[0].index == index => page.remove(0),
        Ok(_) => return Err(format!("the gateway did not serve entry #{index}")),
        Err(e) => return Err(format!("the gateway did not serve entry #{index}: {e:#}")),
    };
    if !expected(&entry) {
        return Err(format!("entry #{index} is not {what}"));
    }
    let url = format!(
        "{}/v1/log/proof/inclusion?index={index}&size={}",
        base(gateway),
        cp.size
    );
    let proof = get_json::<Proof>(http, url)
        .await
        .map_err(|e| format!("no inclusion proof for {what}: {e:#}"))?
        .proof;
    verify_inclusion(&entry.leaf_hash(), index, cp.size, &proof, &cp.root)
        .map_err(|e| format!("{what}: {e}"))?;
    Ok((entry, proof))
}

fn signed_manifest_entry(enrolment: &Enrolment) -> impl Fn(&Entry) -> bool + '_ {
    |e: &Entry| {
        e.kind == EntryKind::ManifestPublished && e.data["manifest"] == enrolment.manifest.as_str()
    }
}

fn own_enrolment_entry(commitment: &str) -> impl Fn(&Entry) -> bool + '_ {
    move |e: &Entry| e.kind == EntryKind::DeviceEnrolled && e.data["commitment"] == commitment
}

/// Proves that the verified tree holds the manifest the owner signed and this device's enrolment.
/// Without stored indexes it searches the log once and stores what it finds.
async fn check_own_entries(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &mut Enrolment,
    cp: &Checkpoint,
) -> Result<Result<OwnEntries, String>> {
    let gateway = enrolment.gateway.clone();
    let mine = commitment(enrolment)?;
    let own = match enrolment.log_entries {
        Some(own) => own,
        None => {
            let entries = fetch_entries(http, &gateway, 0, cp.size).await?;
            let find = |f: &dyn Fn(&Entry) -> bool| entries.iter().find(|e| f(e)).map(|e| e.index);
            let Some(manifest) = find(&signed_manifest_entry(enrolment)) else {
                return Ok(Err(format!(
                    "the log has no entry for the manifest you signed, {}",
                    enrolment.manifest
                )));
            };
            let Some(index) = find(&own_enrolment_entry(&mine)) else {
                return Ok(Err(format!(
                    "the log has no entry for this device's enrolment, {mine}"
                )));
            };
            let own = OwnEntries {
                manifest,
                enrolment: index,
            };
            enrolment.log_entries = Some(own);
            home.write("enrolment.json", &serde_json::to_vec_pretty(&enrolment)?)?;
            own
        }
    };
    let manifest_entry = format!("the manifest you signed, {}", enrolment.manifest);
    let checked = async {
        prove_entry(
            http,
            &gateway,
            cp,
            own.manifest,
            &manifest_entry,
            signed_manifest_entry(enrolment),
        )
        .await?;
        prove_entry(
            http,
            &gateway,
            cp,
            own.enrolment,
            "this device's enrolment",
            own_enrolment_entry(&mine),
        )
        .await?;
        Ok(own)
    };
    Ok(checked.await)
}

/// Verifies the new checkpoint against the stored one, then this enrolment's entries in it.
async fn sync_log(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &mut Enrolment,
) -> Result<LogSync> {
    let gateway = enrolment.gateway.clone();
    let cp = match sync_checkpoint(http, home, &gateway).await? {
        Ok(cp) => cp,
        Err(e) => return Ok(alarm(e)),
    };
    Ok(match check_own_entries(http, home, enrolment, &cp).await? {
        Ok(own) => LogSync::Verified(cp, own),
        Err(e) => alarm(e),
    })
}

/// A root as the checkpoint text shows it.
fn b64(root: &LogHash) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(root.0)
}

fn report_log(sync: LogSync, home: &Home) -> bool {
    match sync {
        LogSync::Verified(cp, own) => {
            println!(
                "Transparency log verified: checkpoint size {} root {}",
                cp.size,
                b64(&cp.root)
            );
            println!(
                "Inclusion proofs verified: the manifest you signed (#{}) and your enrolment (#{})",
                own.manifest, own.enrolment
            );
            true
        }
        LogSync::Alarm(e) => {
            let bar = "!".repeat(72);
            eprintln!(
                "\n{bar}\n!! TRANSPARENCY LOG ALARM\n!! The gateway's keys or history do not match the copy on this device.\n!! {e}"
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
         This is not a log alarm. Run `open-pact-client join <invitation>` again to review the\n\
         manifest and pin the new log.",
        home.file(LEGACY_LOG_HEAD).display()
    );
}

async fn join(
    home: &Home,
    invitation: &str,
    yes: bool,
    software_key: bool,
    insecure_dev: bool,
) -> Result<ExitCode> {
    let invitation = Invitation::decode(invitation)?;
    let gateway = invitation.gateway.as_str();
    check_scheme(gateway, insecure_dev)?;
    let wanted = Pins {
        company: invitation.company.clone(),
        log: invitation.log_key(),
    };
    if let Ok(pinned) = Pins::load(home)
        && let Some(changed) = pinned.differs(&wanted.company, &wanted.log.vkey())
    {
        report_log(
            alarm(format!(
                "{changed} (the new invitation). Use a separate --home for another company"
            )),
            home,
        );
        return Ok(ExitCode::from(2));
    }
    let http = http_client()?;
    let published: PublishedManifest =
        get_json(&http, format!("{}/v1/manifest", base(gateway))).await?;
    let manifest = Manifest::parse(published.toml.as_bytes())?;
    if !published.company.verify(manifest.hash()) {
        bail!("the company signature does not match this manifest; refusing to show it");
    }
    if let Some(mismatch) = wanted.compare(&http, gateway).await? {
        bail!(
            "{gateway} is not the gateway in your invitation: {}. Nothing was sent. \
             Ask IT for a new invitation and report this",
            mismatch.replace(" changed: pinned ", " differs: the invitation names ")
        );
    }
    wanted.save(home)?;
    println!("Gateway keys match the invitation:");
    print!("{}", invitation.describe());
    if home.has_legacy_log_head() {
        std::fs::remove_file(home.file(LEGACY_LOG_HEAD))?;
        println!("Removed the old hash-chain log head; this device now pins the Merkle log.");
    }
    if let Err(e) = sync_checkpoint(&http, home, gateway).await? {
        report_log(alarm(e), home);
        return Ok(ExitCode::from(2));
    }
    println!();
    let os = current_os()?;
    print_summary(&manifest, &published.company.key, os);
    if !yes && !confirm("Sign this manifest as the device owner?")? {
        println!("Not signed. Nothing was sent.");
        return Ok(ExitCode::FAILURE);
    }
    let owner = dev_key::load_or_create(&home.file("owner-dev.pem"))?;
    let device = DeviceKey::load_or_create(&home.0, software_key)?;
    let signed = SignedManifest {
        toml: published.toml.clone(),
        company: published.company,
        owner: Endorsement::sign(&owner, manifest.hash()),
    };
    let request = EnrolRequest::sign_with(
        signed,
        invitation.code.clone(),
        &owner,
        &device.public_key(),
        |statement| device.sign(statement),
    )?;
    let resp = http
        .post(format!("{}/v1/enroll", base(gateway)))
        .json(&request)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        println!("Enrolment refused ({status}): {body}");
        return Ok(ExitCode::FAILURE);
    }
    home.write("manifest.toml", published.toml.as_bytes())?;
    let log_entries = match (
        body["manifest_log_index"].as_u64(),
        body["log_index"].as_u64(),
    ) {
        (Some(manifest), Some(enrolment)) => Some(OwnEntries {
            manifest,
            enrolment,
        }),
        _ => None,
    };
    let mut enrolment = Enrolment {
        gateway: gateway.to_string(),
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device.public_key()),
        salt: body["salt"].as_str().context("salt")?.to_string(),
        log_entries,
    };
    home.write("enrolment.json", &serde_json::to_vec_pretty(&enrolment)?)?;
    println!("Owner signed {}", manifest.hash());
    println!("Enrolled as {}", enrolment.device);
    println!(
        "Device key: {}, trust level {:?}",
        device.describe(),
        device.trust_level()
    );
    if let Some(index) = body["log_index"].as_u64() {
        println!("Enrolment is log entry #{index}; prove it with: open-pact-client log prove");
    }
    println!(
        "The public log records only sha256(salt || pseudonym); the salt stays in enrolment.json."
    );
    match body["state"].as_str() {
        Some("pending") => {
            let hex = enrolment.device.as_str().trim_start_matches("pseudonym:");
            println!(
                "Waiting for IT approval. Read this device code to IT: {}",
                &hex[..12]
            );
        }
        Some("revoked") => println!("This device key is revoked."),
        _ => {}
    }
    Ok(
        if report_log(sync_log(&http, home, &mut enrolment).await?, home) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        },
    )
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

async fn check(home: &Home, insecure_dev: bool) -> Result<ExitCode> {
    let mut enrolment = home.enrolment()?;
    check_scheme(&enrolment.gateway, insecure_dev)?;
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
        return Ok(ExitCode::FAILURE);
    }
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let device = DeviceKey::load(&home.0)?;
    let os = current_os()?;
    let results = collect_results(&manifest, os);

    let http = http_client()?;
    let sync = sync_log(&http, home, &mut enrolment).await?;
    let gateway = base(&enrolment.gateway);
    let log_checkpoint = disclosable_checkpoint(&manifest, home.checkpoint()?);
    let nonce: Nonce = http
        .post(format!("{gateway}/v1/nonce"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let device_key = device.public_key();
    let claim = Claim {
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: nonce.nonce,
        time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .context("clock")?,
        client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
        os,
        trust_level: device.trust_level(),
        virtualized: virtualized(),
        results,
        csr_pem: Some(vpn_csr(home)?),
        log_checkpoint,
    };
    let sent = serde_json::to_vec(&json!({ "jws": device.sign_claim(&claim)? }))?;
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
    if let Ok(pins) = Pins::load(home) {
        println!("\npinned company key {}", pins.company);
        println!("pinned log key {}", pins.log.vkey());
    }
    Ok(())
}

fn commitment(enrolment: &Enrolment) -> Result<String> {
    let mut h = Sha256::new();
    h.update(hex::decode(&enrolment.salt).context("salt in enrolment.json")?);
    h.update(enrolment.device.as_str());
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

async fn log_prove(home: &Home, index: Option<u64>, insecure_dev: bool) -> Result<ExitCode> {
    let mut enrolment = home.enrolment()?;
    check_scheme(&enrolment.gateway, insecure_dev)?;
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
        return Ok(ExitCode::FAILURE);
    }
    let http = http_client()?;
    let sync = sync_log(&http, home, &mut enrolment).await?;
    let LogSync::Verified(cp, own) = sync else {
        report_log(sync, home);
        return Ok(ExitCode::from(2));
    };
    let index = index.unwrap_or(own.enrolment);
    let what = format!("entry #{index}");
    let (entry, proof) =
        match prove_entry(&http, &enrolment.gateway, &cp, index, &what, |_| true).await {
            Ok(proved) => proved,
            Err(e) => {
                report_log(alarm(e), home);
                return Ok(ExitCode::from(2));
            }
        };
    println!("Entry #{} {}", entry.index, serde_json::to_string(&entry)?);
    println!(
        "Leaf hash  {}  (sha256 of 0x00 || JCS({{kind, data}}))",
        entry.leaf_hash()
    );
    println!("Proof      {} hashes", proof.len());
    for h in &proof {
        println!("           {h}");
    }
    println!(
        "INCLUDED in the checkpoint this device verified: size {} root {}",
        cp.size,
        b64(&cp.root)
    );
    if index == own.enrolment {
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
    match cli.command {
        Command::Join {
            invitation,
            yes,
            software_key,
        } => join(&home, &invitation, yes, software_key, cli.insecure_dev).await,
        Command::Check => check(&home, cli.insecure_dev).await,
        Command::Log {
            command: LogCommand::Head,
        } => log_head(&home).map(|()| ExitCode::SUCCESS),
        Command::Log {
            command: LogCommand::Prove { index },
        } => log_prove(&home, index, cli.insecure_dev).await,
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
    fn plain_http_only_to_this_machine_unless_insecure_dev() {
        for ok in [
            "https://pact.example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080",
        ] {
            assert!(check_scheme(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "http://pact.example.com",
            "http://localhost.pact.example.com",
            "http://10.0.0.1",
        ] {
            assert!(check_scheme(bad, false).is_err(), "{bad}");
            assert!(check_scheme(bad, true).is_ok(), "{bad}");
        }
        assert!(check_scheme("ftp://pact.example.com", true).is_err());
    }

    #[test]
    fn a_changed_company_key_or_log_key_is_reported() {
        let fingerprint = || PublicKey::from(&dev_key::generate()).fingerprint();
        let log = |k: &PublicKey| LogKey::new("pact.example.com/log", k);
        let (log_a, log_b) = (
            log(&PublicKey::from(&dev_key::generate())),
            log(&PublicKey::from(&dev_key::generate())),
        );
        let company = fingerprint();
        let pins = Pins {
            company: company.clone(),
            log: log_a.clone(),
        };
        assert_eq!(pins.differs(&company, &format!("{}\n", log_a.vkey())), None);
        let other = fingerprint();
        assert!(
            pins.differs(&other, &log_a.vkey())
                .unwrap()
                .starts_with("the company key changed")
        );
        assert!(
            pins.differs(&company, &log_b.vkey())
                .unwrap()
                .starts_with("the log key changed")
        );
    }

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
