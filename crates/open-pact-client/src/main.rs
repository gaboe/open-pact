mod checks;
mod device_key;
#[cfg(test)]
mod fake_gateway;
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
    Checkpoint, Claim, CsrHash, Endorsement, EnrolRequest, Entry, EntryKind, Invitation,
    LogCheckpoint, LogHash, LogKey, LogPolicy, Manifest, ManifestHash, Metadata, Note, Os,
    Pseudonym, PublicKey, SignedManifest, Virtualized, dev_key, root, verify_claim,
    verify_consistency, verify_cosignatures, verify_inclusion,
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
        log_checkpoint: Option<String>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

struct Home(PathBuf);

/// The directory of VPN credential generations, the link to the installed one, and the files
/// each generation holds, CA first.
const VPN_DIR: &str = "vpn";
const VPN_CURRENT: &str = "current";
const VPN_FILES: [&str; 2] = ["ca.pem", "vpn-cert.pem"];

#[cfg(test)]
thread_local! {
    /// The number of install steps left before a test interrupts the process, if it does.
    static INTERRUPT_AFTER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Where an interruption could leave the installed files half changed. A test can stop the
/// install here as if the process were killed.
fn interruption_point() {
    #[cfg(test)]
    INTERRUPT_AFTER.with(|left| match left.get() {
        Some(0 | 1) => {
            left.set(None);
            panic!("interrupted");
        }
        Some(n) => left.set(Some(n - 1)),
        None => {}
    });
}

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

    /// Installs a VPN CA and certificate as one generation (R7-L2). Both files go into a new
    /// `vpn/<generation>/` directory, then a single rename points the `vpn/current` link at it.
    /// The documented `ca.pem` and `vpn-cert.pem` are links into `vpn/current/`, so every
    /// interruption leaves the earlier pair or the new one, never a mix.
    fn install_vpn_pair(&self, ca: &[u8], cert: &[u8]) -> Result<()> {
        #[cfg(not(unix))]
        {
            let _ = (ca, cert);
            bail!("installing the VPN pair is not supported on this OS yet");
        }
        #[cfg(unix)]
        {
            self.recover_vpn()?;
            if !self.file(VPN_DIR).join(VPN_CURRENT).exists()
                && let (Ok(ca), Ok(cert)) = (
                    std::fs::read(self.file(VPN_FILES[0])),
                    std::fs::read(self.file(VPN_FILES[1])),
                )
            {
                self.switch_vpn_generation(&ca, &cert)?;
                self.link_vpn_files()?;
            }
            self.switch_vpn_generation(ca, cert)?;
            self.link_vpn_files()?;
            self.recover_vpn()
        }
    }

    /// Writes a new generation and points `vpn/current` at it.
    #[cfg(unix)]
    fn switch_vpn_generation(&self, ca: &[u8], cert: &[u8]) -> Result<()> {
        let vpn = self.file(VPN_DIR);
        let generation = format!(
            "{}-{}",
            chrono::Utc::now().timestamp_nanos_opt().context("clock")?,
            std::process::id()
        );
        let dir = vpn.join(&generation);
        std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
        for (name, bytes) in VPN_FILES.iter().zip([ca, cert]) {
            let mut file = std::fs::File::create(dir.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            interruption_point();
        }
        std::fs::File::open(&dir)?.sync_all()?;
        let link = vpn.join(format!(".{VPN_CURRENT}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&generation, &link)?;
        interruption_point();
        std::fs::rename(&link, vpn.join(VPN_CURRENT))
            .with_context(|| vpn.join(VPN_CURRENT).display().to_string())?;
        interruption_point();
        std::fs::File::open(&vpn)?.sync_all()?;
        Ok(())
    }

    /// Makes each documented VPN file a link into `vpn/current/`, replacing a plain file.
    #[cfg(unix)]
    fn link_vpn_files(&self) -> Result<()> {
        for name in VPN_FILES {
            let target = Path::new(VPN_DIR).join(VPN_CURRENT).join(name);
            let path = self.file(name);
            if std::fs::read_link(&path).is_ok_and(|t| t == target) {
                continue;
            }
            let link = self.file(&format!(".{name}.{}.tmp", std::process::id()));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&target, &link)?;
            std::fs::rename(&link, &path).with_context(|| path.display().to_string())?;
            interruption_point();
        }
        std::fs::File::open(&self.0)?.sync_all()?;
        Ok(())
    }

    /// Restores one whole VPN pair after an interrupted install: keeps only the generation
    /// `vpn/current` points at, and links the documented files to it. Does nothing in a home
    /// that has never installed a generation.
    #[cfg(unix)]
    fn recover_vpn(&self) -> Result<()> {
        let vpn = self.file(VPN_DIR);
        let entries = match std::fs::read_dir(&vpn) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| vpn.display().to_string()),
        };
        let current = std::fs::read_link(vpn.join(VPN_CURRENT)).ok();
        for entry in entries {
            let entry = entry?;
            let name = PathBuf::from(entry.file_name());
            if name == Path::new(VPN_CURRENT) || current.as_ref() == Some(&name) {
                continue;
            }
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            }
            .with_context(|| path.display().to_string())?;
        }
        if current.is_some() {
            self.link_vpn_files()?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn recover_vpn(&self) -> Result<()> {
        Ok(())
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

fn collect_results(manifest: &Manifest, os: Os) -> BTreeMap<String, open_pact_core::ControlValue> {
    let ids: Vec<&str> = manifest
        .body()
        .controls
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    disclosable(manifest, os, checks::run(os, &ids))
}

fn disclosable(
    manifest: &Manifest,
    _os: Os,
    mut all: BTreeMap<String, open_pact_core::ControlValue>,
) -> BTreeMap<String, open_pact_core::ControlValue> {
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

/// Probes and sends `virtualized` only if the signed manifest discloses it.
fn disclosable_virtualized(
    manifest: &Manifest,
    probe: impl FnOnce() -> Virtualized,
) -> Option<Virtualized> {
    manifest.body().discloses(Metadata::Virtualized).then(probe)
}

/// The checkpoint goes into the claim only if the signed manifest discloses it.
fn disclosable_checkpoint(manifest: &Manifest, cp: Option<Checkpoint>) -> Option<LogCheckpoint> {
    cp.filter(|_| manifest.body().discloses(Metadata::LogCheckpoint))
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
    let list = |set: &mut dyn Iterator<Item = String>| set.collect::<Vec<_>>().join(", ");
    println!("Manifest     {}", manifest.hash());
    println!(
        "Company key  {}  (matches your invitation)",
        company.fingerprint()
    );
    println!("Issuer       {}, valid from {}", b.issuer, b.valid_from);
    println!("Controller   {}", b.data_controller);
    println!("Retention    claims kept {}", b.claim_retention);
    println!(
        "Recipients   {}",
        list(&mut b.claim_recipients.iter().cloned())
    );
    println!(
        "Metadata     {}",
        list(&mut b.disclosed_metadata.iter().map(ToString::to_string))
    );
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
        println!("  {:<20} can report: {}", "", c.output);
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

/// Fetches the gateway's checkpoint and verifies it against the one stored on this device.
async fn sync_checkpoint(
    http: &reqwest::Client,
    home: &Home,
    gateway: &str,
    policy: Option<&LogPolicy>,
) -> Result<Result<Checkpoint, String>> {
    let pins = Pins::load(home)?;
    if let Some(changed) = pins.compare(http, gateway).await? {
        return Ok(Err(changed));
    }
    let prev = home.checkpoint()?;
    let text = get_text(http, format!("{}/v1/log/checkpoint", base(gateway))).await?;
    let new = match verify_checkpoint(http, home, gateway, &pins.log, policy, prev.as_ref(), &text)
        .await?
    {
        Ok(new) => new,
        Err(e) => return Ok(Err(e)),
    };
    if policy.is_none_or(|p| p.allow_split_views) {
        eprintln!(
            "\n!!! WARNING: SPLIT VIEWS ALLOWED !!!\n\
             The signed manifest sets allow_split_views = true and lists no witnesses. The gateway \
             could show this device another log history than other devices (a split view) and \
             nothing here would notice.\n"
        );
    }
    Ok(Ok(new))
}

/// Verifies a checkpoint note from the gateway: the pinned log key, the manifest's witness policy,
/// and that it extends `prev`, the last checkpoint this device verified. Without `prev` it
/// downloads every entry and recomputes the root instead. Stores the note only if all hold.
async fn verify_checkpoint(
    http: &reqwest::Client,
    home: &Home,
    gateway: &str,
    key: &LogKey,
    policy: Option<&LogPolicy>,
    prev: Option<&Checkpoint>,
    text: &str,
) -> Result<Result<Checkpoint, String>> {
    let now = u64::try_from(chrono::Utc::now().timestamp()).context("clock")?;
    let new = match Note::parse(text).and_then(|note| {
        let checkpoint = key.verify(&note)?;
        verify_cosignatures(policy, &checkpoint, &note, now)?;
        Ok(checkpoint)
    }) {
        Ok(checkpoint) => checkpoint,
        Err(e) => return Ok(Err(e.to_string())),
    };
    let checked = match prev {
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
    manifest: &Manifest,
    enrolment: &mut Enrolment,
) -> Result<LogSync> {
    let gateway = enrolment.gateway.clone();
    let policy = manifest.body().log.as_ref();
    let cp = match sync_checkpoint(http, home, &gateway, policy).await? {
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
    let log = get_text(&http, format!("{}/v1/log/key", base(gateway))).await?;
    if let Some(mismatch) = wanted.differs(&published.company.key.fingerprint(), &log) {
        bail!(
            "{gateway} is not the gateway in your invitation: {}. Nothing was sent. \
             Ask IT for a new invitation and report this",
            mismatch.replace(" changed: pinned ", " differs: the invitation names ")
        );
    }
    checks::check_supported(&manifest).map_err(|e| {
        anyhow::anyhow!("{e}; refusing to show or sign this manifest. Nothing was sent")
    })?;
    wanted.save(home)?;
    println!("Gateway keys match the invitation:");
    print!("{}", invitation.describe());
    if home.has_legacy_log_head() {
        std::fs::remove_file(home.file(LEGACY_LOG_HEAD))?;
        println!("Removed the old hash-chain log head; this device now pins the Merkle log.");
    }
    if let Err(e) = sync_checkpoint(&http, home, gateway, manifest.body().log.as_ref()).await? {
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
        "Device key: {}, trust level {:?} (asserted by this client; without attestation the gateway counts it as L0)",
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
        if report_log(
            sync_log(&http, home, &manifest, &mut enrolment).await?,
            home,
        ) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        },
    )
}

/// A certificate request for the VPN key with an empty subject and no attributes: it carries the
/// public key and nothing else. Returns the PEM and the DER.
fn vpn_csr(home: &Home) -> Result<(String, Vec<u8>)> {
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
    let csr = params.serialize_request(&key)?;
    Ok((csr.pem()?, csr.der().to_vec()))
}

/// Checks the VPN CA and client certificate that will replace the installed pair, so a pair a
/// VPN client could not use never replaces a working one (R6-L1, R7-L1). Each must be exactly
/// one DER certificate, valid now, with no critical extension this check does not know. The CA
/// must be a CA that may sign certificates. The certificate must carry this device's VPN key,
/// name the CA as its issuer, verify under the CA's key, and be a client certificate that is
/// not a CA, may sign, and is for client authentication. Returns a description of the
/// certificate.
fn check_vpn_pair(ca_pem: &str, cert_pem: &str, vpn_key: &KeyPair) -> Result<String> {
    let ca_der = pem_certificate(ca_pem).context("ca_pem")?;
    let ca = whole_certificate(&ca_der).context("ca_pem")?;
    if !ca.is_ca() || !ca.validity().is_valid() {
        bail!("ca_pem is not a CA certificate valid now");
    }
    if !ca.key_usage()?.is_some_and(|ku| ku.value.key_cert_sign()) {
        bail!("ca_pem may not sign certificates");
    }
    let cert_der = pem_certificate(cert_pem).context("certificate_pem")?;
    let cert = whole_certificate(&cert_der).context("certificate_pem")?;
    if !cert.validity().is_valid() {
        bail!("certificate_pem is not valid now");
    }
    if cert.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(vpn_key).as_slice() {
        bail!("certificate_pem is not for this device's VPN key");
    }
    if cert.issuer().as_raw() != ca.subject().as_raw() {
        bail!("certificate_pem names another issuer than ca_pem");
    }
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|e| anyhow::anyhow!("certificate_pem was not issued by ca_pem: {e}"))?;
    if cert.is_ca() {
        bail!("certificate_pem is a CA certificate");
    }
    if !cert
        .key_usage()?
        .is_some_and(|ku| ku.value.digital_signature())
    {
        bail!("certificate_pem may not sign");
    }
    if !cert
        .extended_key_usage()?
        .is_some_and(|eku| eku.value.client_auth)
    {
        bail!("certificate_pem is not for client authentication");
    }
    Ok(format!(
        "subject {}, expires {}",
        cert.subject(),
        cert.validity().not_after
    ))
}

/// A certificate that is all of `der`, with no critical extension other than the basic
/// constraints, key usages and subject names that `check_vpn_pair` reads or allows.
fn whole_certificate(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    use x509_parser::oid_registry::{
        OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_EXTENDED_KEY_USAGE, OID_X509_EXT_KEY_USAGE,
        OID_X509_EXT_SUBJECT_ALT_NAME,
    };
    let (rest, cert) = x509_parser::parse_x509_certificate(der)?;
    if !rest.is_empty() {
        bail!("{} bytes follow the certificate", rest.len());
    }
    let known = [
        OID_X509_EXT_BASIC_CONSTRAINTS,
        OID_X509_EXT_KEY_USAGE,
        OID_X509_EXT_EXTENDED_KEY_USAGE,
        OID_X509_EXT_SUBJECT_ALT_NAME,
    ];
    if let Some(ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.critical && !known.contains(&ext.oid))
    {
        bail!("unknown critical extension {}", ext.oid);
    }
    Ok(cert)
}

/// The DER of a text that is exactly one PEM certificate block.
fn pem_certificate(text: &str) -> Result<Vec<u8>> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(text.as_bytes())?;
    if pem.label != "CERTIFICATE" || !rest.iter().all(u8::is_ascii_whitespace) {
        bail!("not a single PEM certificate");
    }
    Ok(pem.contents)
}

fn print_hints(
    manifest: &Manifest,
    results: &BTreeMap<String, open_pact_core::ControlValue>,
    os: Os,
) {
    for c in &manifest.body().controls {
        let (Some(required), Some(value)) = (c.required.get(&os), results.get(&c.id)) else {
            continue;
        };
        if required.contains(value) {
            continue;
        }
        if let Some(hint) = checks::fix_hint(&c.id, &value.to_string(), os) {
            println!("  fix {}: {hint}", c.id);
        }
    }
}

async fn check(home: &Home, insecure_dev: bool) -> Result<ExitCode> {
    let mut enrolment = home.enrolment()?;
    check_scheme(&enrolment.gateway, insecure_dev)?;
    home.recover_vpn()?;
    if home.has_legacy_log_head() {
        print_log_upgrade(home);
        return Ok(ExitCode::FAILURE);
    }
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    checks::check_supported(&manifest)
        .map_err(|e| anyhow::anyhow!("{e}; nothing was run or sent"))?;
    let device = DeviceKey::load(&home.0)?;
    let os = current_os()?;

    let http = http_client()?;
    let (mut verified, own) = match sync_log(&http, home, &manifest, &mut enrolment).await? {
        LogSync::Verified(cp, own) => (cp, own),
        alarm => {
            report_log(alarm, home);
            return Ok(ExitCode::from(2));
        }
    };
    let results = collect_results(&manifest, os);
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
    let (csr_pem, csr_der) = vpn_csr(home)?;
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
        virtualized: disclosable_virtualized(&manifest, virtualized),
        results,
        csr_sha256: Some(CsrHash::of(&csr_der)),
        log_checkpoint,
    };
    let sent =
        serde_json::to_vec(&json!({ "jws": device.sign_claim(&claim)?, "csr_pem": csr_pem }))?;
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
            log_checkpoint,
        } => {
            let checked = match log_checkpoint {
                None => Ok(Err(
                    "the accepted claim response has no log checkpoint".into()
                )),
                Some(text) => {
                    let key = Pins::load(home)?.log;
                    let policy = manifest.body().log.as_ref();
                    verify_checkpoint(&http, home, gateway, &key, policy, Some(&verified), &text)
                        .await
                }
            };
            match checked? {
                Ok(cp) => verified = cp,
                Err(e) => {
                    println!("ACCEPTED, but the response failed log verification");
                    report_log(
                        alarm(format!(
                            "the checkpoint in the accepted claim response: {e}; no certificate was installed"
                        )),
                        home,
                    );
                    return Ok(ExitCode::from(2));
                }
            }
            println!("ACCEPTED");
            for w in &warnings {
                println!("  warning: {w}");
            }
            print_hints(&manifest, &claim.results, os);
            let vpn_key = KeyPair::from_pem(&std::fs::read_to_string(home.file("vpn-key.pem"))?)?;
            let certificate_pem = certificate_pem.context(
                "the accepted response carries no VPN certificate for the request this check sent; the installed ones are kept",
            )?;
            let described = check_vpn_pair(&ca_pem, &certificate_pem, &vpn_key)
                .context("the accepted response carries an unusable VPN certificate or CA; the installed ones are kept")?;
            home.install_vpn_pair(ca_pem.as_bytes(), certificate_pem.as_bytes())?;
            println!(
                "VPN certificate {} ({described})",
                home.file("vpn-cert.pem").display(),
            );
            println!("VPN CA          {}", home.file("ca.pem").display());
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
    report_log(LogSync::Verified(verified, own), home);
    Ok(if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
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
    let manifest = Manifest::parse(&std::fs::read(home.file("manifest.toml"))?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let http = http_client()?;
    let sync = sync_log(&http, home, &manifest, &mut enrolment).await?;
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
    // Rust ignores SIGPIPE, so `open-pact-client log show | head` would panic on a closed pipe.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
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
    fn sends_declared_results_even_without_an_os_requirement() {
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
            .map(|(k, v)| (k.to_string(), v.into())),
        );
        let ids = |os| -> Vec<String> {
            disclosable(&manifest, os, all.clone())
                .into_keys()
                .collect()
        };
        assert_eq!(
            ids(Os::Macos),
            [
                "antimalware_active",
                "disk_encryption",
                "firewall",
                "screen_lock"
            ]
        );
        assert_eq!(
            ids(Os::Linux),
            [
                "antimalware_active",
                "disk_encryption",
                "firewall",
                "screen_lock"
            ]
        );
    }

    #[test]
    fn sends_numeric_results_only_within_declared_bounds() {
        use open_pact_core::ControlValue;
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        for (value, expected) in [
            (ControlValue::Integer(0), true),
            (ControlValue::Integer(3650), true),
            (ControlValue::Integer(-1), false),
            (ControlValue::Integer(3651), false),
            ("unknown".into(), true),
            ("30".into(), false),
        ] {
            let all = BTreeMap::from([("os_patch_age_days".into(), value.clone())]);
            let sent = disclosable(&manifest, Os::Linux, all);
            assert_eq!(sent.get("os_patch_age_days"), expected.then_some(&value));
        }
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

    use fake_gateway::{
        Company, DEMO_MANIFEST, FakeGateway, Witness, checkpoint_of, not_found, serve_log, snapshot,
    };

    /// A device enrolled at `gateway` under the demo manifest, with a certificate from an earlier check.
    fn enrolled_home(dir: &Path, gateway: &str, company: &Company) -> Home {
        enrolled_home_with(dir, gateway, company, DEMO_MANIFEST)
    }

    fn enrolled_home_with(dir: &Path, gateway: &str, company: &Company, toml: &str) -> Home {
        let home = Home(dir.to_path_buf());
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let device = DeviceKey::load_or_create(dir, true).unwrap();
        let enrolment = Enrolment {
            gateway: gateway.into(),
            manifest: manifest.hash().clone(),
            device: Pseudonym::of(&device.public_key()),
            salt: "00".repeat(32),
            log_entries: None,
        };
        home.write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
            .unwrap();
        home.write("manifest.toml", toml.as_bytes()).unwrap();
        Pins {
            company: company.fingerprint(),
            log: company.log.clone(),
        }
        .save(&home)
        .unwrap();
        home.write("ca.pem", b"earlier CA").unwrap();
        home.write("vpn-cert.pem", b"earlier certificate").unwrap();
        home
    }

    #[tokio::test]
    async fn check_after_a_log_alarm_sends_nothing_and_writes_no_file() {
        let company = Company::new();
        let attacker = dev_key::generate();
        let log = company.log.vkey();
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, Company::published(DEMO_MANIFEST, &attacker)),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "POST /v1/nonce" => (200, r#"{"nonce":"n"}"#.into()),
            "POST /v1/claim" => (
                200,
                r#"{"status":"accepted","warnings":[],"certificate_pem":null,"ca_pem":"attacker CA"}"#
                    .into(),
            ),
            _ => not_found(),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path(), &gateway.url, &company);
        let before = snapshot(dir.path());

        let code = check(&home, false).await;

        assert_eq!(gateway.posts(), Vec::<String>::new(), "no nonce, no claim");
        assert_eq!(
            snapshot(dir.path()),
            before,
            "no CA, certificate, key or log written"
        );
        assert_eq!(code.unwrap(), ExitCode::from(2));
    }

    /// The demo manifest with only the cheap `os_supported` check and `witness` as its one witness.
    fn witnessed_manifest(witness: &Witness) -> String {
        let first = DEMO_MANIFEST.find("[[control]]").unwrap();
        let kept = DEMO_MANIFEST
            .find("[[control]]\nid = \"os_supported\"")
            .unwrap();
        let log = DEMO_MANIFEST.find("[log]").unwrap();
        let end = DEMO_MANIFEST[kept + 1..log]
            .find("[[control]]")
            .map_or(log, |next| kept + 1 + next);
        let toml = format!(
            "{}{}{}",
            &DEMO_MANIFEST[..first],
            &DEMO_MANIFEST[kept..end],
            &DEMO_MANIFEST[log..]
        );
        let demo = toml
            .lines()
            .find(|l| l.starts_with("witnesses = "))
            .unwrap();
        toml.replace(
            demo,
            &format!(
                r#"witnesses = [{{ name = "witness.example.org/test", key = "{}" }}]"#,
                witness.key.vkey()
            ),
        )
    }

    /// Runs `check` against a gateway with an honest, witnessed log of the device's manifest and
    /// enrolment that grows by one entry while the claim is processed. `response` gives the
    /// `log_checkpoint` of the accepted claim response from the log's entries.
    /// Returns the exit code, the files before the check, the files after it and the certificate
    /// the response carried.
    async fn check_with_response_checkpoint(
        response: impl FnOnce(&Company, &Witness, &[Entry], u64) -> Option<String>,
        pair: impl FnOnce(&KeyPair) -> VpnPair,
    ) -> (
        Result<ExitCode>,
        BTreeMap<String, Vec<u8>>,
        BTreeMap<String, Vec<u8>>,
        VpnPair,
    ) {
        let (company, witness) = (Company::new(), Witness::new());
        let toml = witnessed_manifest(&witness);
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceKey::load_or_create(dir.path(), true).unwrap();
        let mine = commitment(&Enrolment {
            gateway: String::new(),
            manifest: manifest.hash().clone(),
            device: Pseudonym::of(&device.public_key()),
            salt: "00".repeat(32),
            log_entries: None,
        })
        .unwrap();
        let entries = vec![
            Entry {
                index: 0,
                kind: EntryKind::ManifestPublished,
                data: json!({ "manifest": manifest.hash().as_str() }),
            },
            Entry {
                index: 1,
                kind: EntryKind::DeviceEnrolled,
                data: json!({ "commitment": mine }),
            },
            Entry {
                index: 2,
                kind: EntryKind::DeviceApproved,
                data: json!({ "device": "another" }),
            },
        ];
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
        let mut before_claim = company.sign(&checkpoint_of(company.log.origin(), &entries, 2));
        witness.cosign(&mut before_claim, now);
        let before_claim = before_claim.to_string();
        let vpn_key = KeyPair::generate().unwrap();
        std::fs::write(dir.path().join("vpn-key.pem"), vpn_key.serialize_pem()).unwrap();
        let pair = pair(&vpn_key);
        let mut claim = json!({
            "status": "accepted",
            "warnings": [],
            "certificate_pem": pair.cert,
            "ca_pem": pair.ca,
        });
        if let Some(text) = response(&company, &witness, &entries, now) {
            claim["log_checkpoint"] = text.into();
        }
        let (published, log) = (Company::published(&toml, &company.key), company.log.vkey());
        let (claim, stored) = (claim.to_string(), before_claim.clone());
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, stored.clone()),
            "POST /v1/nonce" => (200, r#"{"nonce":"n"}"#.into()),
            "POST /v1/claim" => (200, claim.clone()),
            _ => serve_log(&entries, line).unwrap_or_else(not_found),
        })
        .await;
        let home = enrolled_home_with(dir.path(), &gateway.url, &company, &toml);
        home.write(LOG_CHECKPOINT, before_claim.as_bytes()).unwrap();
        let before = snapshot(dir.path());

        let code = check(&home, false).await;

        let posts = gateway.posts();
        assert_eq!(
            posts,
            ["POST /v1/nonce", "POST /v1/claim"],
            "the claim was sent"
        );
        (code, before, snapshot(dir.path()), pair)
    }

    /// A VPN certificate and the CA a claim response carries.
    struct VpnPair {
        cert: Option<String>,
        ca: String,
    }

    /// A fictional VPN CA as the gateway makes it: a CA that signs certificates, unless `is_ca`
    /// is false.
    fn test_ca(is_ca: bool) -> (CertificateParams, KeyPair) {
        test_ca_with(is_ca, |_| {})
    }

    fn test_ca_with(
        is_ca: bool,
        edit: impl FnOnce(&mut CertificateParams),
    ) -> (CertificateParams, KeyPair) {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fictional VPN CA");
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
        }
        edit(&mut params);
        (params, KeyPair::generate().unwrap())
    }

    fn ca_pem((params, key): &(CertificateParams, KeyPair)) -> String {
        params.self_signed(key).unwrap().pem()
    }

    /// A client certificate for `key` issued by `ca` as the gateway issues it, expired since 2020
    /// if `expired`.
    fn issue_to(key: &KeyPair, ca: &(CertificateParams, KeyPair), expired: bool) -> String {
        issue_with(key, ca, |leaf| {
            if expired {
                leaf.not_before = rcgen::date_time_ymd(2020, 1, 1);
                leaf.not_after = rcgen::date_time_ymd(2020, 2, 1);
            }
        })
    }

    fn issue_with(
        key: &KeyPair,
        (params, ca_key): &(CertificateParams, KeyPair),
        edit: impl FnOnce(&mut CertificateParams),
    ) -> String {
        let mut leaf = CertificateParams::new(vec![]).unwrap();
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        leaf.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        edit(&mut leaf);
        leaf.signed_by(key, &rcgen::Issuer::from_params(params, ca_key))
            .unwrap()
            .pem()
    }

    /// A certificate for the device's VPN key, issued by the CA that comes with it.
    fn valid_pair(vpn: &KeyPair) -> VpnPair {
        let ca = test_ca(true);
        VpnPair {
            cert: Some(issue_to(vpn, &ca, false)),
            ca: ca_pem(&ca),
        }
    }

    /// A valid pair whose certificate gets the extra leaf settings of `edit`.
    fn pair_with(vpn: &KeyPair, edit: impl FnOnce(&mut CertificateParams)) -> VpnPair {
        let ca = test_ca(true);
        VpnPair {
            cert: Some(issue_with(vpn, &ca, edit)),
            ca: ca_pem(&ca),
        }
    }

    /// A PEM certificate block around `der`.
    fn pem_of(der: &[u8]) -> String {
        use base64::Engine as _;
        let text = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = text
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    fn grown_checkpoint(
        company: &Company,
        witness: &Witness,
        entries: &[Entry],
        now: u64,
    ) -> Option<String> {
        let mut grown = company.sign(&checkpoint_of(company.log.origin(), entries, 3));
        witness.cosign(&mut grown, now);
        Some(grown.to_string())
    }

    /// R6-L1: a replacement certificate and CA are checked before either installed file
    /// changes, so a bad pair in an accepted response leaves the working pair in place.
    #[tokio::test]
    async fn check_keeps_the_installed_pair_if_the_new_one_is_invalid() {
        type Pair = fn(&KeyPair) -> VpnPair;
        let cases: [(&str, Pair); 14] = [
            ("malformed certificate", |vpn| VpnPair {
                cert: Some("FICTIONAL NOT A CERTIFICATE".into()),
                ..valid_pair(vpn)
            }),
            ("malformed CA", |vpn| VpnPair {
                ca: "FICTIONAL NOT A CA".into(),
                ..valid_pair(vpn)
            }),
            ("certificate for another key", |_| {
                valid_pair(&KeyPair::generate().unwrap())
            }),
            ("certificate from another CA", |vpn| VpnPair {
                ca: ca_pem(&test_ca(true)),
                ..valid_pair(vpn)
            }),
            ("expired certificate", |vpn| {
                let ca = test_ca(true);
                VpnPair {
                    cert: Some(issue_to(vpn, &ca, true)),
                    ca: ca_pem(&ca),
                }
            }),
            ("CA that is not a CA", |vpn| {
                let ca = test_ca(false);
                VpnPair {
                    cert: Some(issue_to(vpn, &ca, false)),
                    ca: ca_pem(&ca),
                }
            }),
            ("certificate and CA swapped", |vpn| {
                let pair = valid_pair(vpn);
                VpnPair {
                    cert: Some(pair.ca),
                    ca: pair.cert.unwrap(),
                }
            }),
            // R7-L1: each pair below is unusable for a VPN client, though the old checks pass it.
            ("no certificate for the request sent", |vpn| VpnPair {
                cert: None,
                ..valid_pair(vpn)
            }),
            ("server-only certificate", |vpn| {
                pair_with(vpn, |leaf| {
                    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                })
            }),
            ("certificate that may not sign", |vpn| {
                pair_with(vpn, |leaf| {
                    leaf.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
                })
            }),
            ("certificate with an unknown critical extension", |vpn| {
                pair_with(vpn, |leaf| {
                    let mut ext =
                        rcgen::CustomExtension::from_oid_content(&[2, 25, 7, 7], vec![5, 0]);
                    ext.set_criticality(true);
                    leaf.custom_extensions = vec![ext];
                })
            }),
            ("issuer name that is not the CA's", |vpn| {
                let ca = test_ca(true);
                let renamed = test_ca_with(true, |p| {
                    p.distinguished_name = rcgen::DistinguishedName::new();
                    p.distinguished_name
                        .push(rcgen::DnType::CommonName, "fictional other CA");
                });
                VpnPair {
                    cert: Some(issue_to(
                        vpn,
                        &(renamed.0, KeyPair::from_pem(&ca.1.serialize_pem()).unwrap()),
                        false,
                    )),
                    ca: ca_pem(&ca),
                }
            }),
            ("CA that may not sign certificates", |vpn| {
                let ca = test_ca_with(true, |p| {
                    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                });
                VpnPair {
                    cert: Some(issue_to(vpn, &ca, false)),
                    ca: ca_pem(&ca),
                }
            }),
            ("certificate with bytes after its DER", |vpn| {
                let pair = valid_pair(vpn);
                let mut der = pem_certificate(pair.cert.as_deref().unwrap()).unwrap();
                der.extend([0, 0]);
                VpnPair {
                    cert: Some(pem_of(&der)),
                    ..pair
                }
            }),
        ];
        let mut accepted = Vec::new();
        for (case, pair) in cases {
            let (code, before, after, _) =
                check_with_response_checkpoint(grown_checkpoint, pair).await;
            let failed = code.as_ref().is_err() || code.as_ref().unwrap() != &ExitCode::SUCCESS;
            let kept = ["ca.pem", "vpn-cert.pem", "vpn-key.pem"]
                .iter()
                .all(|file| after[*file] == before[*file]);
            if !failed || !kept {
                accepted.push(case);
            }
        }
        assert_eq!(accepted, [""; 0], "cases that replaced the installed pair");
    }

    #[tokio::test]
    async fn check_installs_the_certificate_of_a_verified_response_checkpoint() {
        let (code, before, after, pair) =
            check_with_response_checkpoint(grown_checkpoint, valid_pair).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(after["ca.pem"], pair.ca.as_bytes());
        assert_eq!(after["vpn-cert.pem"], pair.cert.unwrap().as_bytes());
        let stored = Note::parse(std::str::from_utf8(&after[LOG_CHECKPOINT]).unwrap()).unwrap();
        assert_eq!(Checkpoint::parse(&stored.text).unwrap().size, 3);
        assert_ne!(after[LOG_CHECKPOINT], before[LOG_CHECKPOINT]);
    }

    #[tokio::test]
    async fn check_installs_nothing_if_the_response_checkpoint_fails_verification() {
        type Respond = fn(&Company, &Witness, &[Entry], u64) -> Option<String>;
        fn signed(company: &Company, witness: &Witness, cp: Checkpoint, at: u64) -> Option<String> {
            let mut note = company.sign(&cp);
            witness.cosign(&mut note, at);
            Some(note.to_string())
        }
        let cases: [(&str, Respond); 8] = [
            ("not a checkpoint", |_, _, _, _| {
                Some("NOT A CHECKPOINT".into())
            }),
            ("no checkpoint", |_, _, _, _| None),
            ("a fork at the stored size", |c, w, e, now| {
                let fork = Checkpoint {
                    root: LogHash([7; 32]),
                    ..checkpoint_of(c.log.origin(), e, 2)
                };
                signed(c, w, fork, now)
            }),
            ("a grown fork", |c, w, e, now| {
                let fork = Checkpoint {
                    root: LogHash([7; 32]),
                    ..checkpoint_of(c.log.origin(), e, 3)
                };
                signed(c, w, fork, now)
            }),
            ("a rollback", |c, w, e, now| {
                signed(c, w, checkpoint_of(c.log.origin(), e, 1), now)
            }),
            ("no witness cosignature", |c, _, e, _| {
                Some(c.sign(&checkpoint_of(c.log.origin(), e, 3)).to_string())
            }),
            ("a stale cosignature", |c, w, e, now| {
                signed(c, w, checkpoint_of(c.log.origin(), e, 3), now - 2 * 3600)
            }),
            ("another log key", |c, w, e, now| {
                signed(&Company::new(), w, checkpoint_of(c.log.origin(), e, 3), now)
            }),
        ];
        for (case, response) in cases {
            let (code, before, after, _) =
                check_with_response_checkpoint(response, valid_pair).await;
            assert_eq!(code.unwrap(), ExitCode::from(2), "{case}: log alarm");
            for file in ["ca.pem", "vpn-cert.pem", LOG_CHECKPOINT] {
                assert_eq!(after[file], before[file], "{case}: {file} unchanged");
            }
        }
    }

    #[tokio::test]
    async fn join_pins_the_manifest_response_it_shows_and_signs() {
        let company = Company::new();
        let attacker = dev_key::generate();
        let forged = DEMO_MANIFEST.replace(
            r#"data_controller = "Company Ltd., dpo@company.example""#,
            r#"data_controller = "Someone else""#,
        );
        assert_ne!(forged, DEMO_MANIFEST);
        let real = Company::published(DEMO_MANIFEST, &company.key);
        let (log, checkpoint) = (company.log.vkey(), company.empty_checkpoint());
        let gateway = FakeGateway::start(move |line, nth| match line {
            "GET /v1/manifest" if nth == 0 => (200, Company::published(&forged, &attacker)),
            "GET /v1/manifest" => (200, real.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, checkpoint.clone()),
            _ => not_found(),
        })
        .await;
        let invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([7; 32]),
        )
        .encode();
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());

        let joined = join(&home, &invitation, true, true, false).await;

        assert_eq!(gateway.posts(), Vec::<String>::new(), "no enrolment sent");
        assert!(!home.file(COMPANY_KEY).exists(), "nothing pinned");
        let error = format!("{:#}", joined.expect_err("join must fail"));
        assert!(error.contains("company key differs"), "{error}");
    }

    async fn join_with_manifest(toml: String) -> (FakeGateway, anyhow::Result<ExitCode>) {
        let company = Company::new();
        let published = Company::published(&toml, &company.key);
        let (log, checkpoint) = (company.log.vkey(), company.empty_checkpoint());
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, checkpoint.clone()),
            _ => not_found(),
        })
        .await;
        let invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([7; 32]),
        )
        .encode();
        let dir = tempfile::tempdir().unwrap();
        let joined = join(
            &Home(dir.path().to_path_buf()),
            &invitation,
            true,
            true,
            false,
        )
        .await;
        (gateway, joined)
    }

    #[tokio::test]
    async fn join_refuses_a_builtin_this_client_does_not_implement() {
        for (from, to) in [
            (
                r#"check = "builtin:disk_encryption@1""#,
                r#"check = "builtin:nonexistent@999""#,
            ),
            (
                r#"check = "builtin:disk_encryption@1""#,
                r#"check = "builtin:disk_encryption@2""#,
            ),
            (r#"id = "firewall""#, r#"id = "installed_apps""#),
        ] {
            assert!(DEMO_MANIFEST.contains(from));
            let (gateway, joined) = join_with_manifest(DEMO_MANIFEST.replace(from, to)).await;
            assert_eq!(
                gateway.posts(),
                Vec::<String>::new(),
                "{to}: nothing signed or sent"
            );
            let error = format!("{:#}", joined.expect_err(to));
            assert!(error.contains("does not implement"), "{error}");
        }
    }

    /// R7-L2: wherever an install of a new VPN pair is interrupted, the recovery at the next
    /// start shows one whole pair, the earlier or the new, through the documented paths.
    #[cfg(unix)]
    #[test]
    fn an_interrupted_vpn_install_leaves_one_whole_pair() {
        let read = |home: &Home| {
            ["ca.pem", "vpn-cert.pem"].map(|name| std::fs::read(home.file(name)).unwrap())
        };
        let earlier = [b"earlier CA".to_vec(), b"earlier certificate".to_vec()];
        let new = [b"new CA".to_vec(), b"new certificate".to_vec()];
        type Setup = fn(&Home);
        let layouts: [(&str, Setup); 2] = [
            ("plain files", |home| {
                home.write("ca.pem", b"earlier CA").unwrap();
                home.write("vpn-cert.pem", b"earlier certificate").unwrap();
            }),
            ("an installed pair", |home| {
                home.install_vpn_pair(b"earlier CA", b"earlier certificate")
                    .unwrap();
            }),
        ];
        let mut mixed = Vec::new();
        for (layout, setup) in layouts {
            for step in 1.. {
                let dir = tempfile::tempdir().unwrap();
                let home = Home(dir.path().to_path_buf());
                setup(&home);
                INTERRUPT_AFTER.with(|left| left.set(Some(step)));
                let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    home.install_vpn_pair(b"new CA", b"new certificate")
                }))
                .is_ok();
                INTERRUPT_AFTER.with(|left| left.set(None));
                home.recover_vpn().unwrap();
                let pair = read(&home);
                if pair != earlier && pair != new {
                    mixed.push(format!("{layout}, step {step}"));
                }
                if finished {
                    assert_eq!(pair, new, "{layout}: installed");
                    break;
                }
            }
        }
        assert_eq!(
            mixed,
            [""; 0].map(String::from),
            "interruptions that left a mixed pair"
        );
    }

    #[test]
    fn the_vpn_certificate_request_carries_only_the_public_key() {
        use x509_parser::certification_request::X509CertificationRequest;
        use x509_parser::prelude::FromDer;
        let dir = tempfile::tempdir().unwrap();
        let (pem, der) = vpn_csr(&Home(dir.path().to_path_buf())).unwrap();
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        assert_eq!(parsed.contents, der);
        let (rest, csr) = X509CertificationRequest::from_der(&der).unwrap();
        assert!(rest.is_empty());
        let info = &csr.certification_request_info;
        assert_eq!(info.subject.iter().count(), 0, "empty subject");
        assert!(info.attributes().is_empty(), "no attributes or extensions");
    }

    #[test]
    fn probes_and_sends_virtualized_only_if_the_manifest_discloses_it() {
        let listed = Manifest::parse(DEMO_MANIFEST.as_bytes()).unwrap();
        assert_eq!(
            disclosable_virtualized(&listed, || Virtualized::Yes),
            Some(Virtualized::Yes)
        );
        let unlisted = DEMO_MANIFEST.replace(r#""virtualized", "#, "");
        assert_ne!(unlisted, DEMO_MANIFEST);
        let unlisted = Manifest::parse(unlisted.as_bytes()).unwrap();
        assert_eq!(
            disclosable_virtualized(&unlisted, || panic!("probed")),
            None
        );
    }
}
