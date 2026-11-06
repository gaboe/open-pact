mod checks;
mod device_config;
mod device_key;
#[cfg(test)]
mod fake_gateway;
mod locallog;
mod report;
mod schedule;
#[cfg(target_os = "macos")]
mod secure_enclave;
mod ui;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::Future;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand};
use device_key::DeviceKey;
use open_pact_core::{
    Checkpoint, Claim, CsrHash, Endorsement, EnrolRequest, Entry, EntryKind, Invitation,
    LogCheckpoint, LogHash, LogKey, LogPolicy, Manifest, ManifestHash, Metadata, Note, Os,
    Pseudonym, PublicKey, SignedManifest, Virtualized, dev_key, verify_claim, verify_consistency,
    verify_cosignatures, verify_inclusion,
};
use open_pact_core::{
    DeviceAuthPurpose, DeviceStatus, MyEntries, MyEntriesRequest, device_auth_statement,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(
    name = "open-pact-client",
    version,
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
        invitation: Option<String>,
        /// Sign without asking
        #[arg(long)]
        yes: bool,
        /// Keep a new device key in a file (trust level L0) even when a Secure Enclave is available
        #[arg(long)]
        software_key: bool,
        /// Print the device code and exit without waiting for IT
        #[arg(long)]
        no_wait: bool,
    },
    /// Run the manifest's checks, send a signed claim and fetch a VPN certificate
    Check,
    /// Prepare open-pact.toml from the signed manifest, then run the checks
    Finish {
        /// Write without asking for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Send a signed status report to an HTTPS collector
    Report {
        #[arg(long)]
        dry_run: bool,
    },
    /// Reconcile the scheduled report job with open-pact.toml
    Apply {
        #[arg(long)]
        dry_run: bool,
    },
    /// Print a device configuration template
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Internal scheduled report commands
    Schedule {
        #[command(subcommand)]
        command: schedule::Command,
    },
    /// Transparency log and local claim log
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Show how to stop scheduled reports and remove the client
    Stop,
    /// Destroy the device key before full uninstall or rotation
    DeleteDeviceKey,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print a commented open-pact.toml template for the enrolled manifest
    Example,
}

#[derive(Subcommand)]
enum LogCommand {
    /// Print the last verified, gateway-signed log checkpoint held on this device
    Head,
    /// Fetch and verify the inclusion proof of one log entry [default: this device's enrolment]
    Prove { index: Option<u64> },
    /// Print every claim this device sent and the gateway's response
    Show,
    /// Print report requests and collector responses
    Reports,
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
struct Proof {
    proof: Vec<LogHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Approval {
    Pending,
    Approved,
    Revoked,
}

#[derive(Deserialize)]
struct DeviceStatusResponse {
    state: Approval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalWait {
    Approved,
    Revoked,
    Interrupted,
}

#[derive(Clone, Copy)]
enum ClaimResult {
    Accepted,
    Denied,
    ResponseUnverified,
}

#[derive(Clone, Copy)]
struct JoinOptions {
    insecure_dev: bool,
    no_wait: bool,
    poll_interval: Duration,
}

#[derive(Debug)]
enum WaitError {
    Network,
    Alarm(String),
    Fatal(anyhow::Error),
}

#[derive(Debug)]
enum CheckpointVerifyError {
    Network(anyhow::Error),
    Alarm(String),
}

impl CheckpointVerifyError {
    fn alarm_text(self) -> String {
        match self {
            Self::Network(error) => {
                format!("no consistency proof from the gateway: {error:#}")
            }
            Self::Alarm(message) => message,
        }
    }
}

impl WaitError {
    fn from_error(error: anyhow::Error) -> Self {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(is_retryable_http_error)
        }) {
            Self::Network
        } else {
            Self::Fatal(error)
        }
    }

    fn body_error(_error: reqwest::Error) -> Self {
        Self::Network
    }
}

const APPROVAL_POLL_INTERVAL: Duration = Duration::from_secs(10);

fn is_retryable_http_error(error: &reqwest::Error) -> bool {
    !error.is_decode()
        && (error.is_connect()
            || error.is_timeout()
            || error.is_request()
            || error.is_body()
            || error
                .status()
                .is_some_and(|status| status.is_server_error()))
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

tokio::task_local! {
    static WIZARD_STEP: Cell<u8>;
}

fn wizard_step(step: u8, title: &str) {
    let _ = WIZARD_STEP.try_with(|current| current.set(step));
    ui::step(step, 6, title);
}

async fn run_wizard<F>(
    home: &Home,
    invitation: Option<&str>,
    no_wait: bool,
    operation: F,
) -> Result<ExitCode>
where
    F: Future<Output = Result<ExitCode>>,
{
    if !wizard_enabled(no_wait) {
        return operation.await;
    }

    let initial_step = if home.file("enrolment.json").exists() {
        4
    } else {
        1
    };
    WIZARD_STEP
        .scope(Cell::new(initial_step), async {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => match signal {
                    Ok(()) => {
                        print_stopped(home, invitation);
                        let _ = std::io::stdout().flush();
                        std::process::exit(130);
                    }
                    Err(error) => Err(error.into()),
                },
                result = operation => {
                    if !matches!(&result, Ok(code) if *code == ExitCode::SUCCESS) {
                        print_stopped(home, invitation);
                    }
                    result
                },
            }
        })
        .await
}

fn print_stopped(home: &Home, invitation: Option<&str>) {
    let step = WIZARD_STEP.try_with(Cell::get).unwrap_or(1);
    let command = client_command(&home.0);
    let enrolled = home
        .read_json::<Enrolment>("enrolment.json")
        .ok()
        .flatten()
        .is_some();
    let continuation = if enrolled {
        format!("{command} join")
    } else if let Some(invitation) = invitation {
        format!("{command} join {}", shell_quote_arg(invitation))
    } else {
        format!("{command} join {}", shell_quote_arg("<invitation from IT>"))
    };
    println!("{}", stopped_message(step, &continuation));
}

fn stopped_message(step: u8, continuation: &str) -> String {
    format!("Stopped at [{step}/6]. Continue with: {continuation}")
}

/// The directory of VPN credential generations, the selected generation, and its files,
/// CA first.
const VPN_DIR: &str = "vpn";
const VPN_CURRENT: &str = "current";
#[cfg(windows)]
const VPN_FLAT_STALE: &str = "flat-copies-stale";
const VPN_FILES: [&str; 2] = ["ca.pem", "vpn-cert.pem"];

#[cfg(test)]
thread_local! {
    /// The number of install steps left before a test interrupts the process, if it does.
    static INTERRUPT_AFTER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(test, windows))]
thread_local! {
    static VPN_RENAME_ERROR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
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

fn read_home_file(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        use std::io::Read;
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x00200000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(path)?;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "home file is a reparse point",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    #[cfg(not(windows))]
    std::fs::read(path)
}

#[cfg(windows)]
struct VpnLock(std::fs::File);

#[cfg(windows)]
impl Drop for VpnLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
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
        match read_home_file(&path) {
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

    /// Installs a VPN CA and certificate as one generation (R7-L2).
    /// Unix selects it through a symlink, with flat paths linked into that generation.
    /// Windows selects it through a pointer file, then copies the flat files one at a time.
    /// Windows flat copies may lag after a failed replacement; recovery retries them.
    fn install_vpn_pair(&self, ca: &[u8], cert: &[u8]) -> Result<()> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (ca, cert);
            bail!("installing the VPN pair is not supported on this OS yet");
        }
        #[cfg(windows)]
        {
            let _lock = self.lock_vpn()?;
            self.recover_vpn_locked()?;
            let vpn = self.file(VPN_DIR);
            if self.vpn_generation(VPN_CURRENT)?.is_none()
                && let (Ok(old_ca), Ok(old_cert)) = (
                    read_home_file(&self.file(VPN_FILES[0])),
                    read_home_file(&self.file(VPN_FILES[1])),
                )
            {
                let baseline = self.write_windows_vpn_generation(&old_ca, &old_cert)?;
                Self::replace_vpn_file(&vpn.join(VPN_CURRENT), baseline.as_bytes())?;
            }
            let generation = self.write_windows_vpn_generation(ca, cert)?;
            if let Some(current) = self.vpn_generation(VPN_CURRENT)? {
                Self::replace_vpn_file(&vpn.join("previous"), current.as_bytes())?;
            }
            Self::replace_vpn_file(&vpn.join(VPN_CURRENT), generation.as_bytes())?;
            self.recover_vpn_locked()
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

    #[cfg(windows)]
    fn write_windows_vpn_generation(&self, ca: &[u8], cert: &[u8]) -> Result<String> {
        let vpn = self.file(VPN_DIR);
        let generation = format!(
            "{}-{}",
            chrono::Utc::now().timestamp_nanos_opt().context("clock")?,
            std::process::id()
        );
        let dir = vpn.join(&generation);
        std::fs::create_dir(&dir)?;
        for (name, bytes) in VPN_FILES.iter().zip([ca, cert]) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            interruption_point();
        }
        Ok(generation)
    }

    #[cfg(windows)]
    fn replace_vpn_file(path: &Path, bytes: &[u8]) -> Result<()> {
        let temp = path.with_file_name(format!(
            ".{}.{}-{}.tmp",
            path.file_name().context("VPN file name")?.to_string_lossy(),
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().context("clock")?
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        interruption_point();
        // Rust uses MoveFileExW with MOVEFILE_REPLACE_EXISTING on Windows.
        #[cfg(test)]
        VPN_RENAME_ERROR.with(|target| -> Result<()> {
            if target.borrow().as_deref() == Some(path) {
                target.replace(None);
                return Err(std::io::Error::from_raw_os_error(32).into());
            }
            Ok(())
        })?;
        std::fs::rename(&temp, path).with_context(|| path.display().to_string())?;
        interruption_point();
        Ok(())
    }

    #[cfg(windows)]
    fn lock_vpn(&self) -> Result<VpnLock> {
        let file = self.open_vpn_lock()?;
        file.lock().context("lock VPN files")?;
        Ok(VpnLock(file))
    }

    #[cfg(windows)]
    fn try_lock_vpn(&self) -> Result<Option<VpnLock>> {
        let file = self.open_vpn_lock()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(VpnLock(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(error).context("lock VPN files"),
        }
    }

    #[cfg(windows)]
    fn open_vpn_lock(&self) -> Result<std::fs::File> {
        let vpn = self.file(VPN_DIR);
        std::fs::create_dir_all(&vpn)?;
        Ok(std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(vpn.join("write.lock"))?)
    }

    #[cfg(windows)]
    fn recover_vpn_at_startup(&self) -> Result<bool> {
        if !self.file(VPN_DIR).exists() {
            return Ok(true);
        }
        let Some(_lock) = self.try_lock_vpn()? else {
            return Ok(false);
        };
        self.recover_vpn_locked()?;
        Ok(true)
    }

    #[cfg(windows)]
    fn recover_vpn(&self) -> Result<()> {
        // A command such as uninstall must not recreate a missing home.
        if !self.file(VPN_DIR).exists() {
            return Ok(());
        }
        let _lock = self.lock_vpn()?;
        self.recover_vpn_locked()
    }

    #[cfg(windows)]
    fn vpn_generation(&self, pointer: &str) -> Result<Option<String>> {
        match read_home_file(&self.file(VPN_DIR).join(pointer)) {
            Ok(bytes) => {
                let name = String::from_utf8(bytes).context("VPN generation is not UTF-8")?;
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                    bail!("invalid VPN generation name");
                }
                Ok(Some(name))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("read VPN generation"),
        }
    }

    #[cfg(windows)]
    fn recover_vpn_locked(&self) -> Result<()> {
        let vpn = self.file(VPN_DIR);
        let current = self.vpn_generation(VPN_CURRENT)?;
        let previous = self.vpn_generation("previous")?;
        // Read the complete selected pair before changing either documented file.
        let pair = current
            .as_ref()
            .map(|name| -> Result<_> {
                let dir = vpn.join(name);
                Ok([
                    read_home_file(&dir.join(VPN_FILES[0]))?,
                    read_home_file(&dir.join(VPN_FILES[1]))?,
                ])
            })
            .transpose()?;
        if let Some(pair) = pair {
            for (name, bytes) in VPN_FILES.iter().zip(pair) {
                let path = self.file(name);
                let refresh = (|| -> Result<()> {
                    match read_home_file(&path) {
                        Ok(existing) if existing == bytes => return Ok(()),
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e).with_context(|| path.display().to_string()),
                    }
                    Self::replace_vpn_file(&path, &bytes)
                })();
                if let Err(error) = refresh {
                    let marker = vpn.join(VPN_FLAT_STALE);
                    let marker_error = std::fs::write(&marker, b"stale").err();
                    return Err(error).with_context(|| {
                        let message = format!(
                            "cannot replace {}; close the program that holds it and run check again",
                            path.display()
                        );
                        match marker_error {
                            Some(marker_error) => format!(
                                "{message}; could not record stale flat copies at {}: {marker_error}",
                                marker.display()
                            ),
                            None => message,
                        }
                    });
                }
            }
            std::fs::remove_file(vpn.join(VPN_FLAT_STALE)).or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        }
        for parent in [&self.0, &vpn] {
            let entries = match std::fs::read_dir(parent) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| parent.display().to_string()),
            };
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let temporary = if parent == &vpn {
                    (name.starts_with(".current.") || name.starts_with(".previous."))
                        && name.ends_with(".tmp")
                } else {
                    VPN_FILES
                        .iter()
                        .any(|file| name.starts_with(&format!(".{file}.")))
                        && name.ends_with(".tmp")
                };
                let old_generation = parent == &vpn
                    && entry.file_type()?.is_dir()
                    && current.as_deref() != Some(name.as_ref())
                    && previous.as_deref() != Some(name.as_ref());
                if old_generation {
                    std::fs::remove_dir_all(entry.path())?;
                } else if temporary {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
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

fn collect_results(
    manifest: &Manifest,
    os: Os,
    device_config: Option<&device_config::DeviceConfig>,
    repo_scan: Option<&checks::repos::RepoScan>,
) -> BTreeMap<String, open_pact_core::ControlValue> {
    disclosable(
        manifest,
        os,
        checks::run(os, &manifest.body().controls, device_config, repo_scan),
    )
}

async fn scan_repositories(
    home: &Home,
    manifest: &Manifest,
    config: Option<&device_config::DeviceConfig>,
) -> Result<checks::repos::RepoScan> {
    let root = repository_scan_root(home)?;
    let folders = config
        .and_then(|config| config.managed_repos.as_ref())
        .map_or_else(Vec::new, |repos| repos.folders.clone());
    let patterns = manifest
        .body()
        .controls
        .iter()
        .flat_map(|control| control.remotes.iter().map(ToString::to_string))
        .collect::<Vec<_>>();
    let state = home.0.clone();
    let scan_root = root.clone();
    let scan =
        tokio::task::spawn_blocking(move || checks::repos::scan(&scan_root, &folders, &patterns))
            .await
            .context("repository scan task stopped")??;
    checks::repos::store(&state, &scan)?;
    Ok(scan)
}

fn repository_scan_root(_home: &Home) -> Result<PathBuf> {
    #[cfg(test)]
    {
        Ok(_home.0.clone())
    }
    #[cfg(not(test))]
    {
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .context("user home is not set")
    }
}

fn stored_repo_scan(home: &Home) -> Result<Option<checks::repos::RepoScan>> {
    checks::repos::load(&home.0, chrono::Utc::now().timestamp())
}

fn proposal_repo_scan(home: &Home) -> Result<Option<checks::repos::RepoScan>> {
    let now = chrono::Utc::now().timestamp();
    Ok(checks::repos::load_attempt(&home.0)?
        .filter(|scan| scan.partial || checks::repos::fresh(scan, now)))
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
            if c.output.contains(&value) {
                return Some((c.id.clone(), value));
            }
            if value == "n/a" {
                let unknown = open_pact_core::ControlValue::from("unknown");
                if c.output.contains(&unknown) {
                    return Some((c.id.clone(), unknown));
                }
            }
            None
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
    println!("  Issuer       {}, valid from {}", b.issuer, b.valid_from);
    println!("  Controller   {}", b.data_controller);
    println!(
        "  Recipients   {}",
        list(&mut b.claim_recipients.iter().cloned())
    );
    println!("  Retention    claims kept {}", b.claim_retention);
    println!(
        "  Metadata     {}",
        list(&mut b.disclosed_metadata.iter().map(ToString::to_string))
    );
    println!(
        "  Claims       valid {}, unknown results tolerated for {}, minimum trust {:?}",
        b.claim_max_age, b.unknown_grace, b.min_trust_level
    );
    println!("  Manifest     {}", manifest.hash());
    println!(
        "  Company key  {}  (matches your invitation)",
        company.fingerprint()
    );
    if let Some(policy) = &b.log {
        let witnesses = list(&mut policy.witnesses.iter().map(|w| w.name.clone()));
        println!(
            "  Witnesses    {}",
            if witnesses.is_empty() {
                "none"
            } else {
                &witnesses
            }
        );
        println!("  Quorum       {}", policy.witness_quorum);
        println!(
            "  Split views  {}",
            if policy.allow_split_views {
                "allowed"
            } else {
                "not allowed"
            }
        );
    }
    let required = |c: &&open_pact_core::Control| c.required.get(&os).map(ToString::to_string);
    let (not_applicable, applicable): (Vec<_>, Vec<_>) = b
        .controls
        .iter()
        .partition(|c| required(c).as_deref() == Some("n/a"));
    let (enforced, reported): (Vec<_>, Vec<_>) =
        applicable.into_iter().partition(|c| required(c).is_some());
    let width = b.controls.iter().map(|c| c.id.len()).max().unwrap_or(0);
    let ui = ui::styled();
    let show = |title: String, controls: &[&open_pact_core::Control]| {
        if controls.is_empty() {
            return;
        }
        println!("\n  {}", ui::bold(&title, ui));
        for c in controls {
            let rule = required(c).map_or(String::new(), |r| format!("must be {r}, "));
            println!("    {:<width$}  {rule}grace {}", c.id, c.grace);
            for pattern in &c.remotes {
                println!("    {:<width$}  counts repositories from {pattern}", "");
            }
            if let Some(why) = &c.rationale {
                println!("    {:<width$}  why: {why}", "");
            }
            println!("    {:<width$}  reports: {}", "", c.output);
        }
    };
    show(
        format!("Required on this {os} device ({})", enforced.len()),
        &enforced,
    );
    show(
        format!("Reported, not required ({})", reported.len()),
        &reported,
    );
    if !not_applicable.is_empty() {
        println!(
            "\n  {}\n    {}",
            ui::bold(
                &format!("Not checked on {os}, always n/a ({})", not_applicable.len()),
                ui
            ),
            list(&mut not_applicable.iter().map(|c| c.id.clone()))
        );
    }
    println!();
}

async fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result: std::io::Result<bool> = (|| {
            let mut answer = String::new();
            std::io::stdin().lock().read_line(&mut answer)?;
            Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
        })();
        let _ = send.send(result);
    });
    Ok(receive.await.context("confirmation input stopped")??)
}

enum LogSync {
    Verified(Checkpoint, OwnEntries),
    Alarm(String),
}

fn alarm(e: impl std::fmt::Display) -> LogSync {
    LogSync::Alarm(e.to_string())
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match read_home_file(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn unified_diff(old: Option<&str>, new: &str) -> String {
    let old_lines: Vec<_> = old.unwrap_or_default().lines().collect();
    let new_lines: Vec<_> = new.lines().collect();
    let mut diff = format!(
        "--- open-pact.toml\n+++ open-pact.toml (proposal)\n@@ -1,{} +1,{} @@\n",
        old_lines.len(),
        new_lines.len()
    );
    diff.push_str(
        &old_lines
            .iter()
            .map(|line| format!("-{line}\n"))
            .collect::<String>(),
    );
    diff.push_str(
        &new_lines
            .iter()
            .map(|line| format!("+{line}\n"))
            .collect::<String>(),
    );
    diff
}

fn write_temporary(
    path: &Path,
    bytes: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> Result<PathBuf> {
    use std::fs::OpenOptions;

    let parent = path.parent().context("file has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .context("file has no name")?
        .to_string_lossy();
    let temporary = parent.join(format!("{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<PathBuf> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        Ok(temporary.clone())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn reject_config_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "open-pact.toml is a symbolic link. finish does not change it. Edit the target file by hand."
            );
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn create_backup(
    path: &Path,
    bytes: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> Result<PathBuf> {
    create_backup_at(
        path,
        bytes,
        permissions,
        &chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

fn create_backup_at(
    path: &Path,
    bytes: &[u8],
    permissions: Option<std::fs::Permissions>,
    timestamp: &str,
) -> Result<PathBuf> {
    use std::fs::OpenOptions;

    let name = path
        .file_name()
        .context("file has no name")?
        .to_string_lossy();
    let prefix = format!("{name}.bak-{timestamp}");
    let mut attempt = 1u32;
    loop {
        let candidate = if attempt == 1 {
            prefix.clone()
        } else {
            format!("{prefix}-{attempt}")
        };
        let backup = path.with_file_name(candidate);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&backup) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt
                    .checked_add(1)
                    .context("backup name suffix overflow")?;
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", backup.display()));
            }
        };
        let result = (|| -> Result<()> {
            if let Some(permissions) = permissions {
                file.set_permissions(permissions)?;
            }
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&backup);
        }
        result?;
        return Ok(backup);
    }
}

#[cfg(test)]
thread_local! {
    static FINISH_WRITE_HOOK: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) };
}

fn before_finish_rename(path: &Path) {
    #[cfg(test)]
    FINISH_WRITE_HOOK.with(|hook| {
        if let Some(hook) = hook.take() {
            hook(path);
        }
    });
    #[cfg(not(test))]
    let _ = path;
}

fn write_proposal(home: &Home, expected: Option<&[u8]>, proposal: &str) -> Result<Option<PathBuf>> {
    let path = home.file(device_config::FILE);
    reject_config_symlink(&path)?;
    let current = read_optional_file(&path)?;
    if current.as_deref() != expected {
        bail!("open-pact.toml changed while finish ran. Run finish again.");
    }
    if current.as_deref() == Some(proposal.as_bytes()) {
        return Ok(None);
    }
    let permissions = match std::fs::metadata(&path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("read permissions for {}", path.display()));
        }
    };
    let temporary = write_temporary(&path, proposal.as_bytes(), permissions.clone())?;
    let backup = match &current {
        Some(bytes) => match create_backup(&path, bytes, permissions) {
            Ok(backup) => Some(backup),
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error);
            }
        },
        None => None,
    };
    before_finish_rename(&path);
    let check = reject_config_symlink(&path).and_then(|()| read_optional_file(&path));
    let unchanged = matches!(check.as_ref(), Ok(bytes) if bytes.as_deref() == expected);
    if !unchanged {
        let _ = std::fs::remove_file(&temporary);
        if let Some(backup) = &backup {
            let _ = std::fs::remove_file(backup);
        }
        check?;
        bail!("open-pact.toml changed while finish ran. Run finish again.");
    }
    let result = std::fs::rename(&temporary, &path)
        .with_context(|| format!("rename {} to {}", temporary.display(), path.display()));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
        if let Some(backup) = &backup {
            let _ = std::fs::remove_file(backup);
        }
    }
    result?;
    #[cfg(unix)]
    std::fs::File::open(path.parent().context("file has no parent directory")?)?.sync_all()?;
    Ok(backup)
}

async fn finish(home: &Home, insecure_dev: bool, yes: bool, wizard: bool) -> Result<ExitCode> {
    if wizard {
        wizard_step(5, "Set up this device");
    }
    let path = home.file(device_config::FILE);
    reject_config_symlink(&path)?;
    let enrolment = home.enrolment()?;
    let manifest_path = home.file("manifest.toml");
    let manifest = Manifest::parse(&read_home_file(&manifest_path)?)?;
    if manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let existing_bytes = read_optional_file(&path)?;
    let existing_text = existing_bytes
        .as_deref()
        .map(|bytes| String::from_utf8(bytes.to_vec()))
        .transpose()
        .with_context(|| format!("{} must be UTF-8", path.display()))?;
    let os = current_os()?;
    let repo_scan = proposal_repo_scan(home)?;
    let user_home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    let proposal = existing_text.clone().unwrap_or_else(|| {
        device_config::example(&manifest, os, repo_scan.as_ref(), user_home.as_deref())
    });
    let unchanged = existing_text.as_deref() == Some(proposal.as_str());
    if unchanged {
        println!("No changes to {}.", path.display());
    } else {
        print!("{}", unified_diff(existing_text.as_deref(), &proposal));
    }
    if !unchanged && !yes {
        match confirm("Write open-pact.toml?").await {
            Ok(true) => {}
            Ok(false) => {
                if wizard {
                    print_stopped(home, None);
                }
                return Ok(ExitCode::SUCCESS);
            }
            Err(error) => return Err(error),
        }
    }
    if !unchanged && let Some(backup) = write_proposal(home, existing_bytes.as_deref(), &proposal)?
    {
        println!("Backup written to {}", backup.display());
    }
    if wizard {
        wizard_step(6, "First check and claim");
    }
    match check_impl(home, insecure_dev, !wizard).await {
        Ok(code) => Ok(code),
        Err(error) => Err(error),
    }
}

async fn after_approval(home: &Home, insecure_dev: bool, wizard: bool) -> Result<ExitCode> {
    if !wizard {
        print_approved_next_step(&client_command(&home.0));
        return Ok(ExitCode::SUCCESS);
    }
    match wizard_resume(home)? {
        WizardResume::Finish => return finish(home, insecure_dev, false, true).await,
        WizardResume::Complete => {
            println!("This device setup is complete.");
            return Ok(ExitCode::SUCCESS);
        }
        WizardResume::FirstCheck => {}
    }
    wizard_step(6, "First check and claim");
    match check_impl(home, insecure_dev, false).await {
        Ok(code) => Ok(code),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WizardResume {
    Finish,
    FirstCheck,
    Complete,
}

fn wizard_resume(home: &Home) -> Result<WizardResume> {
    let configured = home.file(device_config::FILE).exists();
    let (records, damaged) = match locallog::read_lenient(&home.file("claims.jsonl")) {
        Ok(history) => history,
        Err(error) => {
            println!(
                "warning: could not read claim history; wizard completion cannot be confirmed ({error})"
            );
            return Ok(if configured {
                WizardResume::FirstCheck
            } else {
                WizardResume::Finish
            });
        }
    };
    if damaged > 0 {
        println!(
            "warning: skipped {damaged} damaged claim history record(s); checked valid records for wizard completion"
        );
    }
    if !configured {
        return Ok(WizardResume::Finish);
    }
    let Some(record) = records.last() else {
        return Ok(WizardResume::FirstCheck);
    };
    if !record
        .status
        .is_some_and(|status| (200..300).contains(&status))
    {
        return Ok(WizardResume::FirstCheck);
    }
    let response = record.response()?;
    let Ok(Response::Accepted {
        certificate_pem: Some(certificate),
        ca_pem,
        ..
    }) = serde_json::from_slice::<Response>(&response)
    else {
        return Ok(WizardResume::FirstCheck);
    };
    let installed_certificate = read_optional_file(&home.file("vpn-cert.pem"))
        .ok()
        .flatten();
    let installed_ca = read_optional_file(&home.file("ca.pem")).ok().flatten();
    if installed_certificate.as_deref() == Some(certificate.as_bytes())
        && installed_ca.as_deref() == Some(ca_pem.as_bytes())
    {
        Ok(WizardResume::Complete)
    } else {
        Ok(WizardResume::FirstCheck)
    }
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
        Err(e) => return Ok(Err(e.alarm_text())),
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
/// and that it extends `prev`, the last checkpoint this device verified. The first checkpoint
/// trusts the same signature and witness policy. Stores the note only if all hold.
async fn verify_checkpoint(
    http: &reqwest::Client,
    home: &Home,
    gateway: &str,
    key: &LogKey,
    policy: Option<&LogPolicy>,
    prev: Option<&Checkpoint>,
    text: &str,
) -> Result<Result<Checkpoint, CheckpointVerifyError>> {
    let now = u64::try_from(chrono::Utc::now().timestamp()).context("clock")?;
    let new = match Note::parse(text).and_then(|note| {
        let checkpoint = key.verify(&note)?;
        verify_cosignatures(policy, &checkpoint, &note, now)?;
        Ok(checkpoint)
    }) {
        Ok(checkpoint) => checkpoint,
        Err(e) => return Ok(Err(CheckpointVerifyError::Alarm(e.to_string()))),
    };
    let checked = match prev {
        None => Ok(()),
        Some(old) if old.size == new.size => {
            verify_consistency(old.size, new.size, &old.root, &new.root, &[])
                .map_err(|e| CheckpointVerifyError::Alarm(e.to_string()))
        }
        Some(old) => {
            let url = format!(
                "{}/v1/log/proof/consistency?from={}&to={}",
                base(gateway),
                old.size,
                new.size
            );
            let proof = async {
                let response = http.get(&url).send().await.map_err(|error| {
                    let error = anyhow::Error::from(error);
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<reqwest::Error>()
                            .is_some_and(is_retryable_http_error)
                    }) {
                        CheckpointVerifyError::Network(error)
                    } else {
                        CheckpointVerifyError::Alarm(error.to_string())
                    }
                })?;
                let response = response.error_for_status().map_err(|error| {
                    let error = anyhow::Error::from(error);
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<reqwest::Error>()
                            .is_some_and(is_retryable_http_error)
                    }) {
                        CheckpointVerifyError::Network(error)
                    } else {
                        CheckpointVerifyError::Alarm(error.to_string())
                    }
                })?;
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| CheckpointVerifyError::Network(error.into()))?;
                serde_json::from_slice::<Proof>(&bytes).map_err(|error| {
                    CheckpointVerifyError::Alarm(format!(
                        "GET {url}: error decoding response body: {error}"
                    ))
                })
            }
            .await;
            match proof {
                Ok(p) => verify_consistency(old.size, new.size, &old.root, &new.root, &p.proof)
                    .map_err(|e| CheckpointVerifyError::Alarm(e.to_string())),
                Err(CheckpointVerifyError::Network(error)) => {
                    Err(CheckpointVerifyError::Network(error))
                }
                Err(CheckpointVerifyError::Alarm(message)) => Err(CheckpointVerifyError::Alarm(
                    format!("no consistency proof from the gateway: {message}"),
                )),
            }
        }
    };
    if let Err(e) = checked {
        return Ok(Err(e));
    }
    home.write(LOG_CHECKPOINT, text.as_bytes())?;
    Ok(Ok(new))
}

fn signed_manifest_entry(enrolment: &Enrolment) -> impl Fn(&Entry) -> bool + '_ {
    |e: &Entry| {
        e.kind == EntryKind::ManifestPublished && e.data["manifest"] == enrolment.manifest.as_str()
    }
}

fn own_enrolment_entry(commitment: &str) -> impl Fn(&Entry) -> bool + '_ {
    move |e: &Entry| e.kind == EntryKind::DeviceEnrolled && e.data["commitment"] == commitment
}

async fn fetch_my_entries(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
) -> Result<MyEntries> {
    let device = DeviceKey::load(&home.0)?;
    let gateway = base(&enrolment.gateway);
    let nonce: Nonce = http
        .post(format!("{gateway}/v1/nonce"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let statement =
        device_auth_statement(DeviceAuthPurpose::LogMine, &enrolment.device, &nonce.nonce);
    let request = MyEntriesRequest {
        pseudonym: enrolment.device.clone(),
        nonce: nonce.nonce,
        device_key: device.public_key(),
        signature: device.sign(&statement)?,
    };
    let response = http
        .post(format!("{gateway}/v1/log/mine"))
        .json(&request)
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow::anyhow!(
            "The gateway does not support this client version. Ask IT to update the gateway to 0.4.0 or later."
        ));
    }
    Ok(response.error_for_status()?.json().await?)
}

async fn status_after_log_denial(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
) -> Result<DeviceStatus> {
    let device = DeviceKey::load(&home.0)?;
    let gateway = base(&enrolment.gateway);
    let nonce: Nonce = http
        .post(format!("{gateway}/v1/nonce"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let statement = device_auth_statement(
        DeviceAuthPurpose::DeviceStatus,
        &enrolment.device,
        &nonce.nonce,
    );
    let request = MyEntriesRequest {
        pseudonym: enrolment.device.clone(),
        nonce: nonce.nonce,
        device_key: device.public_key(),
        signature: device.sign(&statement)?,
    };
    #[derive(Deserialize)]
    struct Status {
        state: DeviceStatus,
    }
    let status: Status = http
        .post(format!("{gateway}/v1/device/status"))
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(status.state)
}

async fn fetch_my_entries_for_wait(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
) -> std::result::Result<MyEntries, WaitError> {
    let device = DeviceKey::load(&home.0).map_err(WaitError::Fatal)?;
    let gateway = base(&enrolment.gateway);
    let nonce_bytes = http
        .post(format!("{gateway}/v1/nonce"))
        .send()
        .await
        .map_err(|error| WaitError::from_error(error.into()))?
        .error_for_status()
        .map_err(|error| WaitError::from_error(error.into()))?
        .bytes()
        .await
        .map_err(WaitError::body_error)?;
    let nonce: Nonce =
        serde_json::from_slice(&nonce_bytes).map_err(|error| WaitError::Fatal(error.into()))?;
    let statement =
        device_auth_statement(DeviceAuthPurpose::LogMine, &enrolment.device, &nonce.nonce);
    let request = MyEntriesRequest {
        pseudonym: enrolment.device.clone(),
        nonce: nonce.nonce,
        device_key: device.public_key(),
        signature: device.sign(&statement).map_err(WaitError::Fatal)?,
    };
    let response = http
        .post(format!("{gateway}/v1/log/mine"))
        .json(&request)
        .send()
        .await
        .map_err(|error| WaitError::from_error(error.into()))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(WaitError::Fatal(anyhow::anyhow!(
            "The gateway does not support this client version. Ask IT to update the gateway to 0.4.0 or later."
        )));
    }
    let bytes = response
        .error_for_status()
        .map_err(|error| WaitError::from_error(error.into()))?
        .bytes()
        .await
        .map_err(WaitError::body_error)?;
    serde_json::from_slice(&bytes).map_err(|error| WaitError::Fatal(error.into()))
}

fn verify_my_entries(
    response: &MyEntries,
    enrolment: &Enrolment,
    commitment: &str,
    cp: &Checkpoint,
) -> Result<OwnEntries, String> {
    if !signed_manifest_entry(enrolment)(&response.manifest.entry) {
        return Err("the gateway returned a different manifest entry".into());
    }
    for item in std::iter::once(&response.manifest).chain(&response.device) {
        if item.entry.index >= cp.size {
            return Err("own entry is outside the checkpoint".into());
        }
        verify_inclusion(
            &item.entry.leaf_hash(),
            item.entry.index,
            cp.size,
            &item.proof,
            &cp.root,
        )
        .map_err(|e| e.to_string())?;
    }
    if response.device.iter().any(|item| {
        !matches!(
            item.entry.kind,
            EntryKind::DeviceEnrolled | EntryKind::DeviceApproved | EntryKind::DeviceRevoked
        ) || item.entry.data["commitment"] != commitment
    }) {
        return Err("the gateway returned another device's entry".into());
    }
    let enrolled = response
        .device
        .iter()
        .find(|item| own_enrolment_entry(commitment)(&item.entry))
        .ok_or_else(|| "the log has no entry for this device's enrolment".to_string())?;
    Ok(OwnEntries {
        manifest: response.manifest.entry.index,
        enrolment: enrolled.entry.index,
    })
}

/// Verifies this device's entries against an authenticated checkpoint.
async fn check_own_entries(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &mut Enrolment,
    cp: &mut Checkpoint,
) -> Result<Result<OwnEntries, String>> {
    let response = fetch_my_entries(http, home, enrolment).await?;
    let pins = Pins::load(home)?;
    let manifest = Manifest::parse(&read_home_file(&home.file("manifest.toml"))?)?;
    let next = match verify_checkpoint(
        http,
        home,
        &enrolment.gateway,
        &pins.log,
        manifest.body().log.as_ref(),
        Some(cp),
        &response.checkpoint,
    )
    .await?
    {
        Ok(next) => next,
        Err(error) => return Ok(Err(error.alarm_text())),
    };
    let own = match verify_my_entries(&response, enrolment, &commitment(enrolment)?, &next) {
        Ok(own) => own,
        Err(error) => return Ok(Err(error)),
    };
    if enrolment
        .log_entries
        .is_some_and(|stored| stored.manifest != own.manifest || stored.enrolment != own.enrolment)
    {
        return Ok(Err(
            "the gateway changed this device's log entry indexes".into()
        ));
    }
    *cp = next;
    enrolment.log_entries = Some(own);
    home.write("enrolment.json", &serde_json::to_vec_pretty(&enrolment)?)?;
    Ok(Ok(own))
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
    let mut cp = match sync_checkpoint(http, home, &gateway, policy).await? {
        Ok(cp) => cp,
        Err(e) => return Ok(alarm(e)),
    };
    Ok(
        match check_own_entries(http, home, enrolment, &mut cp).await? {
            Ok(own) => LogSync::Verified(cp, own),
            Err(e) => alarm(e),
        },
    )
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

async fn fetch_device_status(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
) -> std::result::Result<Approval, WaitError> {
    let device = DeviceKey::load(&home.0).map_err(WaitError::Fatal)?;
    let nonce_bytes = http
        .post(format!("{}/v1/nonce", base(&enrolment.gateway)))
        .send()
        .await
        .map_err(|e| WaitError::from_error(e.into()))?
        .error_for_status()
        .map_err(|e| WaitError::from_error(e.into()))?
        .bytes()
        .await
        .map_err(WaitError::body_error)?;
    let nonce: Nonce =
        serde_json::from_slice(&nonce_bytes).map_err(|e| WaitError::Fatal(e.into()))?;
    let statement = device_auth_statement(
        DeviceAuthPurpose::DeviceStatus,
        &enrolment.device,
        &nonce.nonce,
    );
    let request = MyEntriesRequest {
        pseudonym: enrolment.device.clone(),
        nonce: nonce.nonce,
        device_key: device.public_key(),
        signature: device.sign(&statement).map_err(WaitError::Fatal)?,
    };
    let bytes = http
        .post(format!("{}/v1/device/status", base(&enrolment.gateway)))
        .json(&request)
        .send()
        .await
        .map_err(|e| WaitError::from_error(e.into()))?
        .error_for_status()
        .map_err(|e| WaitError::from_error(e.into()))?
        .bytes()
        .await
        .map_err(WaitError::body_error)?;
    let response: DeviceStatusResponse =
        serde_json::from_slice(&bytes).map_err(|e| WaitError::Fatal(e.into()))?;
    Ok(response.state)
}

/// Verifies the gateway checkpoint and every private entry before trusting an approval entry.
async fn verify_approval_entry(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
) -> std::result::Result<bool, WaitError> {
    let response = fetch_my_entries_for_wait(http, home, enrolment).await?;
    let pins = Pins::load(home).map_err(WaitError::Fatal)?;
    let prev = home.checkpoint().map_err(WaitError::Fatal)?;
    let checkpoint = match verify_checkpoint(
        http,
        home,
        &enrolment.gateway,
        &pins.log,
        manifest.body().log.as_ref(),
        prev.as_ref(),
        &response.checkpoint,
    )
    .await
    .map_err(WaitError::Fatal)?
    {
        Ok(checkpoint) => checkpoint,
        Err(CheckpointVerifyError::Network(_)) => return Err(WaitError::Network),
        Err(CheckpointVerifyError::Alarm(error)) => return Err(WaitError::Alarm(error)),
    };
    let commitment = commitment(enrolment).map_err(WaitError::Fatal)?;
    if let Err(error) = verify_my_entries(&response, enrolment, &commitment, &checkpoint) {
        return Err(WaitError::Alarm(error));
    }
    Ok(response.device.iter().any(|item| {
        item.entry.kind == EntryKind::DeviceApproved && item.entry.data["commitment"] == commitment
    }))
}

fn print_waiting_line(message: &str) {
    let mut stdout = std::io::stdout().lock();
    if stdout.is_terminal() {
        let _ = write!(stdout, "\r\x1b[2K  {message}");
        let _ = stdout.flush();
    } else {
        println!("  {message}");
    }
}

#[cfg(test)]
async fn wait_for_approval(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
    poll_interval: Duration,
    interruptible: bool,
) -> Result<Result<ApprovalWait, String>> {
    wait_for_approval_with_status(
        http,
        home,
        enrolment,
        manifest,
        poll_interval,
        interruptible,
        true,
    )
    .await
}

async fn wait_for_approval_with_status(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
    poll_interval: Duration,
    interruptible: bool,
    show_waiting: bool,
) -> Result<Result<ApprovalWait, String>> {
    if show_waiting {
        print_waiting_line("Waiting for IT approval...");
    }
    let mut warning_printed = false;
    let mut first_poll = true;
    loop {
        if !first_poll {
            if interruptible {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(Ok(ApprovalWait::Interrupted)),
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            } else {
                tokio::time::sleep(poll_interval).await;
            }
        }
        let first = first_poll;
        first_poll = false;
        let status_result = if interruptible {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(Ok(ApprovalWait::Interrupted)),
                result = fetch_device_status(http, home, enrolment) => result,
            }
        } else {
            fetch_device_status(http, home, enrolment).await
        };
        let status = match status_result {
            Ok(status) => status,
            Err(WaitError::Network) => {
                if !warning_printed {
                    eprintln!("warning: could not reach the gateway for IT approval; retrying");
                    warning_printed = true;
                }
                continue;
            }
            Err(WaitError::Alarm(error)) => return Ok(Err(error)),
            Err(WaitError::Fatal(error)) => return Err(error),
        };
        match status {
            Approval::Revoked => return Ok(Ok(ApprovalWait::Revoked)),
            Approval::Pending if !first && show_waiting => {
                print_waiting_line("Waiting for IT approval...")
            }
            Approval::Pending => {}
            Approval::Approved => {
                let proof_result = if interruptible {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            return Ok(Ok(ApprovalWait::Interrupted));
                        }
                        result = verify_approval_entry(http, home, enrolment, manifest) => result,
                    }
                } else {
                    verify_approval_entry(http, home, enrolment, manifest).await
                };
                match proof_result {
                    Err(WaitError::Network) => {
                        if !warning_printed {
                            eprintln!(
                                "warning: could not reach the gateway for IT approval; retrying"
                            );
                            warning_printed = true;
                        }
                    }
                    Err(WaitError::Alarm(error)) => return Ok(Err(error)),
                    Err(WaitError::Fatal(error)) => return Err(error),
                    Ok(true) => return Ok(Ok(ApprovalWait::Approved)),
                    Ok(false) if show_waiting => print_waiting_line(
                        "IT approved the device. Waiting for the signed log proof...",
                    ),
                    Ok(false) => {}
                }
            }
        }
    }
}

fn print_approved_next_step(command: &str) {
    println!("\n  {}", ui::bold(approval_confirmation(), ui::styled()));
    println!("\n{}", approved_next_hint(command));
}

fn approved_next_hint(command: &str) -> String {
    format!("Next: {command} finish")
}

fn approval_confirmation() -> &'static str {
    "This device is approved."
}

fn approval_scan_output(
    scan: &checks::repos::RepoScan,
    user_home: &Path,
    still_waiting: bool,
) -> String {
    let mut output = device_config::managed_repo_summary(scan, user_home);
    if still_waiting {
        output.push_str("  The client is still waiting for IT approval. Keep this window open.\n");
    }
    output
}

fn approval_exit(wait: ApprovalWait, command: &str) -> ExitCode {
    match wait {
        ApprovalWait::Approved => {
            print_approved_next_step(command);
            ExitCode::SUCCESS
        }
        ApprovalWait::Revoked => {
            println!("\nThis device was revoked. Contact IT before you continue.");
            ExitCode::FAILURE
        }
        ApprovalWait::Interrupted => {
            println!("\n{}", stopped_message(4, &format!("{command} join")));
            ExitCode::from(130)
        }
    }
}

async fn wait_after_join(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
    options: JoinOptions,
    wizard: bool,
) -> Result<ExitCode> {
    wizard_step(4, "Wait for IT approval");
    println!(
        "  {}\n",
        ui::device_code_line(&device_code(&enrolment.device), ui::styled())
    );
    println!("  Read this code to IT. IT approves the device with it.");
    let command = client_command(&home.0);
    let wizard = wizard && !options.no_wait;
    println!(
        "  The client now looks for managed repositories in your home folder to prepare the `managed_repos` setup proposal for open-pact.toml."
    );
    if current_os()? == Os::Macos
        && manifest
            .body()
            .controls
            .iter()
            .any(|control| !control.remotes.is_empty())
    {
        println!("  If macOS asks for access to a folder, you can deny it.");
    }
    let config = device_config::DeviceConfig::load(home)?;
    if options.no_wait {
        let scan = scan_repositories(home, manifest, config.as_ref()).await?;
        print!(
            "{}",
            device_config::managed_repo_summary(&scan, &repository_scan_root(home)?)
        );
        println!("\nNext, after IT approves:");
        println!("  1. {command} config example");
        println!(
            "  2. Save the sections you need as {}",
            home.file("open-pact.toml").display()
        );
        println!("  3. {command} check");
        print_claim_log_status(home, None, Some("IT has not approved this device yet"));
        return Ok(ExitCode::SUCCESS);
    }

    let scan = scan_repositories(home, manifest, config.as_ref());
    let approval = wait_for_approval_with_status(
        http,
        home,
        enrolment,
        manifest,
        options.poll_interval,
        false,
        !wizard,
    );
    tokio::pin!(scan);
    tokio::pin!(approval);
    let mut early_approval = None;
    let scan = tokio::select! {
        result = &mut approval => {
            if matches!(&result, Ok(Ok(ApprovalWait::Approved))) {
                Some(scan.await?)
            } else {
                early_approval = Some(result);
                None
            }
        }
        result = &mut scan => Some(result?),
    };
    let approval = if let Some(approval) = early_approval {
        if let Some(scan) = &scan {
            print!(
                "{}",
                approval_scan_output(scan, &repository_scan_root(home)?, wizard)
            );
        }
        approval?
    } else {
        tokio::select! {
            biased;
            result = &mut approval => {
                if let Some(scan) = &scan {
                    print!(
                        "{}",
                        approval_scan_output(scan, &repository_scan_root(home)?, wizard)
                    );
                }
                result?
            },
            _ = std::future::ready(()) => {
                if let Some(scan) = &scan {
                    print!(
                        "{}",
                        approval_scan_output(scan, &repository_scan_root(home)?, wizard)
                    );
                }
                approval.await?
            }
        }
    };
    match approval {
        Ok(ApprovalWait::Approved) if wizard => {
            println!("\n  {}", ui::bold(approval_confirmation(), ui::styled()));
            after_approval(home, options.insecure_dev, true).await
        }
        Ok(wait) => {
            let code = approval_exit(wait, &command);
            match wait {
                ApprovalWait::Approved => {
                    print_claim_log_status(home, None, Some("finish and check have not run yet"))
                }
                ApprovalWait::Revoked => {
                    print_claim_log_status(home, None, Some("IT revoked this device"));
                }
                ApprovalWait::Interrupted => {}
            }
            Ok(code)
        }
        Err(error) => {
            eprintln!(
                "\nTRANSPARENCY LOG ALARM: the gateway's signed history or proof does not match.\n!! {error}"
            );
            print_claim_log_status(home, None, Some("the approval proof did not verify"));
            Ok(ExitCode::from(2))
        }
    }
}

fn wizard_enabled(no_wait: bool) -> bool {
    !no_wait && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

async fn continue_saved_join(
    http: &reqwest::Client,
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
    options: JoinOptions,
) -> Result<ExitCode> {
    let wizard = wizard_enabled(options.no_wait);
    wait_after_join(http, home, enrolment, manifest, options, wizard).await
}

async fn resume_join(
    home: &Home,
    insecure_dev: bool,
    no_wait: bool,
    poll_interval: Duration,
) -> Result<ExitCode> {
    let enrolment: Enrolment = home
        .read_json("enrolment.json")?
        .context("join needs the invitation until this device is enrolled")?;
    check_scheme(&enrolment.gateway, insecure_dev)?;
    Pins::load(home)
        .context("this device has no pinned gateway keys; run join with the invitation")?;
    let http = http_client()?;
    let published: PublishedManifest =
        match get_json(&http, format!("{}/v1/manifest", base(&enrolment.gateway))).await {
            Ok(published) => published,
            Err(error) => return Err(error),
        };
    let manifest = Manifest::parse(published.toml.as_bytes())?;
    if !published.company.verify(manifest.hash()) {
        bail!("the company signature does not match this manifest; refusing to resume");
    }
    if manifest.hash() != &enrolment.manifest {
        bail!("the gateway manifest no longer matches this device's enrolment");
    }
    let stored_manifest = Manifest::parse(&read_home_file(&home.file("manifest.toml"))?)?;
    if stored_manifest.hash() != &enrolment.manifest {
        bail!("manifest.toml no longer matches the hash you signed");
    }
    let checkpoint = match sync_checkpoint(
        &http,
        home,
        &enrolment.gateway,
        manifest.body().log.as_ref(),
    )
    .await
    {
        Ok(checkpoint) => checkpoint,
        Err(error) => return Err(error),
    };
    if let Err(error) = checkpoint {
        report_log(alarm(error), home);
        print_claim_log_status(home, None, Some("the log checkpoint did not verify"));
        return Ok(ExitCode::from(2));
    }
    continue_saved_join(
        &http,
        home,
        &enrolment,
        &manifest,
        JoinOptions {
            insecure_dev,
            no_wait,
            poll_interval,
        },
    )
    .await
}

async fn join(
    home: &Home,
    invitation: &str,
    yes: bool,
    software_key: bool,
    insecure_dev: bool,
    no_wait: bool,
    poll_interval: Duration,
) -> Result<ExitCode> {
    let invitation = Invitation::decode(invitation)?;
    let gateway = invitation.gateway.as_str();
    check_scheme(gateway, insecure_dev)?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        println!(
            "You are running join as root, for example with sudo. The client would then check \
             root's settings instead of yours and keep its keys in root's home. Run join without \
             sudo, as the account that uses this device."
        );
        if !yes && !confirm("Continue as root anyway?").await? {
            if !wizard_enabled(no_wait) {
                println!("Stopped. Nothing was sent.");
            }
            return Ok(ExitCode::FAILURE);
        }
    }
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
    let saved_enrolment = home.read_json::<Enrolment>("enrolment.json")?;
    let same_gateway_enrolment = saved_enrolment
        .as_ref()
        .is_some_and(|saved| saved.gateway == gateway);
    let invitation_step_shown = !same_gateway_enrolment;
    if invitation_step_shown {
        wizard_step(1, "Check the invitation");
    }
    let http = http_client()?;
    let published: PublishedManifest =
        match get_json(&http, format!("{}/v1/manifest", base(gateway))).await {
            Ok(published) => published,
            Err(error) => return Err(error),
        };
    let manifest = Manifest::parse(published.toml.as_bytes())?;
    if !published.company.verify(manifest.hash()) {
        bail!("the company signature does not match this manifest; refusing to show it");
    }
    let log = match get_text(&http, format!("{}/v1/log/key", base(gateway))).await {
        Ok(log) => log,
        Err(error) => return Err(error),
    };
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
    let saved_enrolment_matches = saved_enrolment
        .as_ref()
        .is_some_and(|saved| saved.gateway == gateway && saved.manifest == *manifest.hash());
    if !saved_enrolment_matches && !invitation_step_shown {
        wizard_step(1, "Check the invitation");
    }
    wanted.save(home)?;
    if !saved_enrolment_matches {
        println!("  The gateway keys match your invitation.");
        for line in invitation.describe().lines() {
            println!("  {line}");
        }
    }
    if home.has_legacy_log_head() {
        std::fs::remove_file(home.file(LEGACY_LOG_HEAD))?;
        println!("Removed the old hash-chain log head; this device now pins the Merkle log.");
    }
    let checkpoint = match sync_checkpoint(&http, home, gateway, manifest.body().log.as_ref()).await
    {
        Ok(checkpoint) => checkpoint,
        Err(error) => return Err(error),
    };
    if let Err(e) = checkpoint {
        report_log(alarm(e), home);
        print_claim_log_status(home, None, Some("the log checkpoint did not verify"));
        return Ok(ExitCode::from(2));
    }
    if let Some(existing) = saved_enrolment
        .filter(|existing| existing.gateway == gateway && existing.manifest == *manifest.hash())
    {
        match DeviceKey::load(&home.0) {
            Ok(device) if Pseudonym::of(&device.public_key()) == existing.device => {
                return continue_saved_join(
                    &http,
                    home,
                    &existing,
                    &manifest,
                    JoinOptions {
                        insecure_dev,
                        no_wait,
                        poll_interval,
                    },
                )
                .await;
            }
            Ok(_) => bail!(
                "This home has an enrolment for a different device key. Run open-pact-client join with a new invitation after removing the old enrolment. Recovery command: `{}` delete-device-key",
                client_command(&home.0)
            ),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                }) => {}
            Err(error) => return Err(error),
        }
    }
    let os = current_os()?;
    wizard_step(2, "Review and sign the manifest");
    print_summary(&manifest, &published.company.key, os);
    if !yes && !confirm("Sign this manifest as the device owner?").await? {
        if !wizard_enabled(no_wait) {
            println!("Not signed. Nothing was sent. Run join again when you want to enrol.");
        }
        return Ok(ExitCode::FAILURE);
    }
    wizard_step(3, "Enrol this device");
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
    let resp = match http
        .post(format!("{}/v1/enroll", base(gateway)))
        .json(&request)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return Err(error.into()),
    };
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
    let enrolment = Enrolment {
        gateway: gateway.to_string(),
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device.public_key()),
        salt: body["salt"].as_str().context("salt")?.to_string(),
        log_entries,
    };
    home.write("enrolment.json", &serde_json::to_vec_pretty(&enrolment)?)?;
    let client_home = std::path::absolute(&home.0).unwrap_or_else(|_| home.0.clone());
    println!("  Signed       {}  (the manifest above)", manifest.hash());
    println!("  Enrolled as  {}", enrolment.device);
    println!(
        "  Device key   {}, trust level {:?} (asserted by this client; without attestation the gateway counts it as L0)",
        device.describe(),
        device.trust_level()
    );
    if let Some(index) = body["log_index"].as_u64() {
        println!(
            "  Public log   enrolment is entry #{index}. Prove it with: open-pact-client log prove"
        );
    }
    println!(
        "               The log records only sha256(salt || pseudonym). The salt stays in enrolment.json."
    );
    println!("  Client home  {}", client_home.display());
    let state = body["state"].as_str();
    if state == Some("revoked") {
        println!("This device was revoked. Contact IT before you continue.");
        return Ok(ExitCode::FAILURE);
    }
    if matches!(state, Some("pending" | "approved")) {
        return continue_saved_join(
            &http,
            home,
            &enrolment,
            &manifest,
            JoinOptions {
                insecure_dev,
                no_wait,
                poll_interval,
            },
        )
        .await;
    }
    Ok(ExitCode::SUCCESS)
}

fn device_code(device: &Pseudonym) -> String {
    device.as_str().trim_start_matches("pseudonym:")[..12].to_string()
}

/// The command prefix the owner types next: with `--home` only when join used another home.
fn client_command(home: &Path) -> String {
    match Home::new(None) {
        Ok(default) if default.0 == home => "open-pact-client".to_string(),
        _ => format!(
            "open-pact-client --home {}",
            shell_quote_arg(&home.display().to_string())
        ),
    }
}

#[cfg(windows)]
fn shell_quote_arg(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "''"))
}

#[cfg(not(windows))]
fn shell_quote_arg(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''"))
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
    check_impl(home, insecure_dev, true).await
}

async fn check_impl(home: &Home, insecure_dev: bool, show_resume_hint: bool) -> Result<ExitCode> {
    let migrating = schedule::migration_example(home)?;
    let mut can_scan_repositories = true;
    let device_config = match device_config::DeviceConfig::load(home) {
        Ok(Some(config)) => Some(config),
        Ok(None) => None,
        Err(error) => {
            can_scan_repositories = false;
            eprintln!(
                "{error:#}\nCorrect this section and key in open-pact.toml. Other controls will still run."
            );
            None
        }
    };
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
    let scan = if can_scan_repositories {
        Some(scan_repositories(home, &manifest, device_config.as_ref()).await?)
    } else {
        None
    };
    let device = DeviceKey::load(&home.0)?;
    let os = current_os()?;

    if device_config.is_none() && !migrating {
        let user_home =
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
        print!(
            "{}",
            device_config::example(&manifest, os, scan.as_ref(), user_home.as_deref())
        );
    }
    let check_manifest = manifest.clone();
    let check_config = device_config.clone();
    let check_scan = scan.clone();
    let virtualization_manifest = manifest.clone();
    let (results, virtualized) = tokio::task::spawn_blocking(move || {
        let results = collect_results(
            &check_manifest,
            os,
            check_config.as_ref(),
            check_scan.as_ref(),
        );
        let virtualized = disclosable_virtualized(&virtualization_manifest, virtualized);
        (results, virtualized)
    })
    .await
    .context("control collection task stopped")?;
    device_config::print_table(&manifest, os, device_config.as_ref(), &results);
    if let Some(scan) = &scan {
        if scan.partial {
            println!("Repository scan is partial; repository counts are unknown.");
            for cause in &scan.causes {
                println!("  could not read {} ({})", cause.path.display(), cause.kind);
            }
            if scan.causes.is_empty() {
                println!("  Fix access to unreadable folders or retry after they are available.");
            } else {
                println!("  Fix access to these locations, then run check again.");
            }
        }
        if scan.partial && scan.access_denied {
            let binary = std::env::current_exe().unwrap_or_default();
            println!(
                "Repository values are unknown because the client lacks access to some folders. On macOS, grant Full Disk Access to this client binary: {}",
                binary.display()
            );
        }
        for path in &scan.outside_paths {
            println!(
                "  outside repository: {}. Move it into a registered folder.",
                path.display()
            );
        }
    }
    let command = client_command(&home.0);
    if show_resume_hint {
        match wizard_resume(home)? {
            WizardResume::Finish => {
                println!("Wizard step [5/6] is unfinished. Continue with: {command} join");
            }
            WizardResume::FirstCheck => {
                println!("Wizard step [6/6] is unfinished. Continue with: {command} join");
            }
            WizardResume::Complete => {}
        }
    }
    let http = http_client()?;
    let sync = match sync_log(&http, home, &manifest, &mut enrolment).await {
        Err(error)
            if error.downcast_ref::<reqwest::Error>().is_some_and(|error| {
                error.status() == Some(reqwest::StatusCode::FORBIDDEN)
                    && error
                        .url()
                        .is_some_and(|url| url.path().ends_with("/v1/log/mine"))
            }) =>
        {
            match status_after_log_denial(&http, home, &enrolment).await? {
                DeviceStatus::Pending => {
                    println!("This device waits for IT approval.");
                    println!(
                        "Wizard step [4/6] is unfinished. Continue with: {} join",
                        client_command(&home.0)
                    );
                    print_claim_log_status(
                        home,
                        None,
                        Some("the device is waiting for IT approval"),
                    );
                }
                DeviceStatus::Revoked => {
                    println!("IT revoked this device.");
                    print_claim_log_status(home, None, Some("IT revoked this device"));
                }
                DeviceStatus::Approved => {
                    print_claim_log_status(
                        home,
                        None,
                        Some("the gateway denied log access after approval"),
                    );
                    return Err(error);
                }
            }
            return Ok(ExitCode::FAILURE);
        }
        result => result?,
    };
    let (mut verified, own) = match sync {
        LogSync::Verified(cp, own) => (cp, own),
        alarm => {
            report_log(alarm, home);
            print_claim_log_status(home, None, Some("log verification did not complete"));
            return Ok(ExitCode::from(2));
        }
    };
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
        virtualized,
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
    let status = resp.status();
    let received = resp.bytes().await?;
    locallog::append_with_status(
        &home.file("claims.jsonl"),
        &sent,
        &received,
        Some(status.as_u16()),
    )?;

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
            if !status.is_success() {
                bail!("claim request failed with HTTP {status}");
            }
            let checked = match log_checkpoint {
                None => Ok(Err(CheckpointVerifyError::Alarm(
                    "the accepted claim response has no log checkpoint".into(),
                ))),
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
                            "the checkpoint in the accepted claim response: {}; no certificate was installed",
                            e.alarm_text()
                        )),
                        home,
                    );
                    print_claim_log_status(
                        home,
                        Some((
                            claim
                                .time
                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            ClaimResult::ResponseUnverified,
                            claim.results.len(),
                        )),
                        None,
                    );
                    return Ok(ExitCode::from(2));
                }
            }
            println!("{}", ui::bold("ACCEPTED", ui::styled()));
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
            println!("{}", ui::bold("DENIED", ui::styled()));
            for r in &reasons {
                println!("  {r}");
            }
            print_hints(&manifest, &claim.results, os);
            false
        }
    };
    report_log(LogSync::Verified(verified, own), home);
    print_claim_log_status(
        home,
        Some((
            claim
                .time
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            if accepted {
                ClaimResult::Accepted
            } else {
                ClaimResult::Denied
            },
            claim.results.len(),
        )),
        None,
    );
    if !accepted {
        println!("\nNext: fix the items above, then run {command} check again.");
    }
    Ok(if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn print_claim_log_status(
    home: &Home,
    claim: Option<(String, ClaimResult, usize)>,
    reason: Option<&str>,
) {
    println!("{}", claim_log_status_text(home, claim, reason));
}

fn claim_log_status_text(
    home: &Home,
    claim: Option<(String, ClaimResult, usize)>,
    reason: Option<&str>,
) -> String {
    let path = home.file("claims.jsonl");
    let command = client_command(&home.0);
    let summary = match claim {
        Some((time, result, controls)) => {
            let outcome = match result {
                ClaimResult::Accepted => "accepted",
                ClaimResult::Denied => "denied",
                ClaimResult::ResponseUnverified => "accepted response not verified",
            };
            format!("  Last claim: {time}, {outcome}, {controls} controls.")
        }
        None => format!(
            "  No claim was sent because {}.",
            reason.unwrap_or("the check stopped before it sent a claim")
        ),
    };
    format!(
        "\nLocal claim log: {}\n  It holds every claim this device sent and each response, byte for byte.\n  Show it with: {command} log show\n{summary}",
        path.display()
    )
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
    let response = fetch_my_entries(&http, home, &enrolment).await?;
    let pins = Pins::load(home)?;
    let cp = match verify_checkpoint(
        &http,
        home,
        &enrolment.gateway,
        &pins.log,
        manifest.body().log.as_ref(),
        Some(&cp),
        &response.checkpoint,
    )
    .await?
    {
        Ok(cp) => cp,
        Err(error) => {
            report_log(alarm(error.alarm_text()), home);
            return Ok(ExitCode::from(2));
        }
    };
    if let Err(error) = verify_my_entries(&response, &enrolment, &commitment(&enrolment)?, &cp) {
        report_log(alarm(error), home);
        return Ok(ExitCode::from(2));
    }
    let item = std::iter::once(&response.manifest)
        .chain(response.device.iter())
        .find(|item| item.entry.index == index)
        .context("that entry is not available to this device")?;
    let (entry, proof) = (&item.entry, &item.proof);
    println!("Entry #{} {}", entry.index, serde_json::to_string(&entry)?);
    println!(
        "Leaf hash  {}  (sha256 of 0x00 || JCS({{kind, data}}))",
        entry.leaf_hash()
    );
    println!("Proof      {} hashes", proof.len());
    for h in proof {
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

#[derive(Clone, Copy)]
struct ReportLogFile<'a> {
    path: &'a Path,
    source: &'static str,
    system_state: bool,
}

fn system_history_warning(reason: &str, warnings: &mut impl Write) -> Result<()> {
    writeln!(
        warnings,
        "SYSTEM history was not included: {reason}; run from an elevated prompt to include it."
    )?;
    Ok(())
}

fn system_discovery_reason(error: &anyhow::Error) -> &'static str {
    let detail = format!("{error:#}").to_ascii_lowercase();
    if [
        "acl",
        "reparse point",
        "non-admin owner",
        "permissions are unsafe",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
    {
        "protected directory permissions are unsafe"
    } else if [
        "access denied",
        "access is denied",
        "permission denied",
        "unauthorizedaccess",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
    {
        "access denied"
    } else {
        "protected SYSTEM history could not be discovered"
    }
}

fn log_reports(
    files: &[ReportLogFile<'_>],
    output: &mut impl Write,
    warnings: &mut impl Write,
) -> Result<()> {
    let mut records = Vec::new();
    let mut system_unreadable = None;
    for file in files {
        match locallog::read_with_lines(file.path) {
            Ok(file_records) => records.extend(
                file_records
                    .into_iter()
                    .map(|(line, record)| (*file, line, record)),
            ),
            Err(error) if file.system_state && error.kind() != std::io::ErrorKind::InvalidData => {
                system_unreadable = Some(if error.kind() == std::io::ErrorKind::PermissionDenied {
                    "access denied"
                } else {
                    "protected history could not be read"
                });
            }
            Err(error) => {
                return Err(
                    anyhow::Error::new(error).context(format!("{} report history", file.source))
                );
            }
        }
    }
    records.sort_by(|(_, _, left), (_, _, right)| left.time.cmp(&right.time));
    if let Some(reason) = system_unreadable {
        system_history_warning(reason, warnings)?;
    }
    if records.is_empty() {
        writeln!(output, "No reports sent yet.")?;
    }
    for (file, line, record) in &records {
        let location = format!("{} line {line}", file.source);
        let sent = record
            .sent()
            .with_context(|| format!("{location}: invalid sent report"))?;
        let jws = std::str::from_utf8(&sent)
            .with_context(|| format!("{location}: report JWS is not UTF-8"))?;
        let mut parts = jws.split('.');
        let _header = parts.next();
        let payload = parts
            .next()
            .context("report JWS payload is missing")
            .with_context(|| location.clone())?;
        if parts.next().is_none() || parts.next().is_some() {
            bail!("{location}: report JWS must have three segments");
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .with_context(|| format!("{location}: invalid report JWS payload"))?;
        let value: Value = serde_json::from_slice(&payload)
            .with_context(|| format!("{location}: report payload is not JSON"))?;
        let report_id = value["report_id"].as_str().unwrap_or("unknown");
        let report_type = value["report_type"].as_str().unwrap_or("unknown");
        writeln!(
            output,
            "== {}  source:{}  status:{}  report_id:{}  report_type:{}",
            record.time,
            file.source,
            record
                .status
                .map_or_else(|| "unknown".into(), |status| status.to_string()),
            report_id,
            report_type
        )?;
        writeln!(output, "{}", serde_json::to_string_pretty(&value)?)?;
        if record.response_incomplete {
            writeln!(output, "-- response (response incomplete)")?;
        } else {
            writeln!(output, "-- response")?;
        }
        let response = record.response()?;
        match String::from_utf8(response) {
            Ok(response) => writeln!(output, "{response}\n")?,
            Err(error) => writeln!(
                output,
                "{} response bytes (not UTF-8)\n",
                error.as_bytes().len()
            )?,
        }
    }
    Ok(())
}

fn log_reports_with_discovery(
    home: &Home,
    discover: impl FnOnce(&Home) -> Result<Vec<(PathBuf, bool)>>,
    output: &mut impl Write,
    warnings: &mut impl Write,
) -> Result<()> {
    let canonical_home = Home(schedule::report_log_home_path(home)?);
    let paths = match discover(&canonical_home) {
        Ok(paths) => paths,
        Err(error) => {
            system_history_warning(system_discovery_reason(&error), warnings)?;
            vec![(canonical_home.file("reports.jsonl"), false)]
        }
    };
    let files = paths
        .iter()
        .map(|(path, system_state)| ReportLogFile {
            path,
            source: if *system_state { "system" } else { "home" },
            system_state: *system_state,
        })
        .collect::<Vec<_>>();
    log_reports(&files, output, warnings)
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Command::Schedule {
        command: schedule::Command::Probe { address },
    } = &cli.command
    {
        schedule::probe_blocking(address)?;
        return Ok(ExitCode::SUCCESS);
    }
    let home = Home::new(cli.home)?;
    #[cfg(windows)]
    match home.recover_vpn_at_startup() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("warning: VPN recovery skipped because another process holds the VPN lock")
        }
        Err(error) => eprintln!("warning: VPN recovery failed: {error:#}"),
    }
    match cli.command {
        Command::Join {
            invitation,
            yes,
            software_key,
            no_wait,
        } => match invitation {
            Some(invitation) => {
                run_wizard(
                    &home,
                    Some(&invitation),
                    no_wait,
                    join(
                        &home,
                        &invitation,
                        yes,
                        software_key,
                        cli.insecure_dev,
                        no_wait,
                        APPROVAL_POLL_INTERVAL,
                    ),
                )
                .await
            }
            None => {
                run_wizard(
                    &home,
                    None,
                    no_wait,
                    resume_join(&home, cli.insecure_dev, no_wait, APPROVAL_POLL_INTERVAL),
                )
                .await
            }
        },
        Command::Check => check(&home, cli.insecure_dev).await,
        Command::Finish { yes } => finish(&home, cli.insecure_dev, yes, false).await,
        Command::Report { dry_run } => {
            let config = device_config::DeviceConfig::load(&home)?
                .context("open-pact.toml is missing; run `config example`")?;
            let report = config
                .report
                .context("open-pact.toml [report].collector is required")?;
            report::run(&home, &report.collector, dry_run).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Config {
            command: ConfigCommand::Example,
        } => {
            let enrolment = home.enrolment()?;
            let manifest = Manifest::parse(&read_home_file(&home.file("manifest.toml"))?)?;
            if manifest.hash() != &enrolment.manifest {
                bail!("manifest.toml no longer matches the hash you signed");
            }
            let repo_scan = proposal_repo_scan(&home)?;
            let user_home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from);
            print!(
                "{}",
                device_config::example(
                    &manifest,
                    current_os()?,
                    repo_scan.as_ref(),
                    user_home.as_deref()
                )
            );
            eprintln!(
                "Next: save the sections you need as {}, then run {} check",
                std::path::absolute(home.file("open-pact.toml"))?.display(),
                client_command(&home.0)
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Apply { dry_run } => {
            schedule::apply(&home, dry_run).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Schedule { command } => {
            schedule::run(&home, command).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Log {
            command: LogCommand::Head,
        } => log_head(&home).map(|()| ExitCode::SUCCESS),
        Command::Log {
            command: LogCommand::Prove { index },
        } => log_prove(&home, index, cli.insecure_dev).await,
        Command::Log {
            command: LogCommand::Show,
        } => log_show(&home.file("claims.jsonl")).map(|()| ExitCode::SUCCESS),
        Command::Log {
            command: LogCommand::Reports,
        } => log_reports_with_discovery(
            &home,
            schedule::report_log_paths,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )
        .map(|()| ExitCode::SUCCESS),
        Command::DeleteDeviceKey => {
            DeviceKey::delete(&home.0)?;
            println!("Device key deleted.");
            Ok(ExitCode::SUCCESS)
        }
        Command::Stop => {
            println!(
                "Set [schedule].enabled = false in open-pact.toml, then run `{}` to stop scheduled reports.",
                schedule::apply_command(&home.0)
            );
            println!(
                "Before deleting the home or binary, run `open-pact-client delete-device-key` with the same --home."
            );
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
    fn local_claim_log_summary_explains_the_file_and_last_claim() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let text = claim_log_status_text(
            &home,
            Some(("2026-11-05T12:00:00Z".into(), ClaimResult::Accepted, 21)),
            None,
        );
        assert!(text.contains(&home.file("claims.jsonl").display().to_string()));
        assert!(text.contains("every claim this device sent"));
        assert!(text.contains("log show"));
        assert!(text.contains("2026-11-05T12:00:00Z, accepted, 21 controls"));
        let unverified = claim_log_status_text(
            &home,
            Some((
                "2026-11-05T12:00:00Z".into(),
                ClaimResult::ResponseUnverified,
                21,
            )),
            None,
        );
        assert!(unverified.contains("Local claim log:"));
        assert!(unverified.contains("Show it with:"));
        assert!(unverified.contains("accepted response not verified"));
        assert!(!unverified.contains("No claim was sent"));
        let empty =
            claim_log_status_text(&home, None, Some("the device is waiting for IT approval"));
        assert!(empty.contains("No claim was sent because the device is waiting for IT approval."));
    }

    #[test]
    fn approval_interruption_uses_the_interrupt_exit_status() {
        assert_eq!(
            approval_exit(ApprovalWait::Interrupted, "open-pact-client"),
            ExitCode::from(130)
        );
    }

    #[test]
    fn approval_interruption_names_step_four_and_its_continuation() {
        assert_eq!(
            stopped_message(4, "open-pact-client join"),
            "Stopped at [4/6]. Continue with: open-pact-client join"
        );
    }

    #[test]
    fn step_four_prints_scan_summary_before_the_waiting_message() {
        let home = Path::new("/home/example");
        let scan = checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 2,
            managed_repos_total: 2,
            outside_paths: Vec::new(),
            managed_paths: Some(vec![home.join("work/one"), home.join("work/two")]),
            partial: true,
            access_denied: false,
            causes: Vec::new(),
        };
        let output = approval_scan_output(&scan, home, true);
        let found = output.find("Found 2 managed repositories:").unwrap();
        let locations = output.find("~/work (2)").unwrap();
        let partial = output.find("scan was partial").unwrap();
        let waiting = output.find("still waiting for IT approval").unwrap();
        assert!(
            found < locations && locations < partial && partial < waiting,
            "{output}"
        );
        assert!(!approval_scan_output(&scan, home, false).contains("still waiting"));
    }

    #[test]
    fn wizard_resume_requires_a_verified_first_check() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::Finish);
        fs::write(
            home.file(device_config::FILE),
            "[report]\ncollector = \"https://collector.example.org/status\"\n",
        )
        .unwrap();
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::FirstCheck);
        locallog::append(&home.file("claims.jsonl"), b"sent", b"upstream unavailable").unwrap();
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::FirstCheck);

        let certificate = "fictional certificate";
        let ca = "fictional certificate authority";
        let response = serde_json::to_vec(&json!({
            "status": "accepted",
            "warnings": [],
            "certificate_pem": certificate,
            "ca_pem": ca,
            "log_checkpoint": "fictional verified checkpoint"
        }))
        .unwrap();
        locallog::append_with_status(
            &home.file("claims.jsonl"),
            b"failed HTTP exchange",
            &response,
            Some(502),
        )
        .unwrap();
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::FirstCheck);
        locallog::append_with_status(
            &home.file("claims.jsonl"),
            b"verified claim",
            &response,
            Some(200),
        )
        .unwrap();
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::FirstCheck);
        fs::write(home.file("vpn-cert.pem"), certificate).unwrap();
        fs::write(home.file("ca.pem"), ca).unwrap();
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::Complete);

        let valid = fs::read_to_string(home.file("claims.jsonl"))
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut bad_hash: Value = serde_json::from_slice(&valid).unwrap();
        bad_hash["sent_sha256"] = json!("00".repeat(32));
        let mut history = serde_json::to_vec(&bad_hash).unwrap();
        history.push(b'\n');
        history.extend_from_slice(&valid);
        history.push(b'\n');
        history.extend_from_slice(b"{\"time\":\n");
        fs::write(home.file("claims.jsonl"), &history).unwrap();
        let (valid_records, damaged) = locallog::read_lenient(&home.file("claims.jsonl")).unwrap();
        assert_eq!(valid_records.len(), 1);
        assert_eq!(damaged, 2);
        assert_eq!(wizard_resume(&home).unwrap(), WizardResume::Complete);
        assert_eq!(fs::read(home.file("claims.jsonl")).unwrap(), history);
    }

    #[cfg(unix)]
    #[test]
    fn printed_home_argument_survives_posix_shell_parsing() {
        let path = Path::new("/tmp/client home's;$(fictional)");
        let quoted = shell_quote_arg(&path.display().to_string());
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("printf %s {quoted}")])
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected = path.to_string_lossy();
        assert_eq!(output.stdout, expected.as_bytes());
    }

    #[cfg(windows)]
    #[test]
    fn printed_home_argument_uses_powershell_quoting() {
        assert_eq!(shell_quote_arg("C:\\client home's"), "'C:\\client home''s'");
    }
    use std::fs;

    #[test]
    fn log_reports_keeps_home_history_when_system_discovery_fails() {
        use base64::Engine;

        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let payload = serde_json::json!({
            "report_id": "home-row",
            "report_type": "periodic",
        });
        let jws = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        locallog::append_report_retained(
            &home.file("reports.jsonl"),
            &home.file("report-state.json"),
            jws.as_bytes(),
            b"ok",
            200,
            false,
        )
        .unwrap();

        let mut output = Vec::new();
        let mut warnings = Vec::new();
        log_reports_with_discovery(
            &home,
            |_| Err(anyhow::anyhow!("access denied")),
            &mut output,
            &mut warnings,
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("report_id:home-row"));
        assert!(!output.contains("SYSTEM history was not included"));
        let warnings = String::from_utf8(warnings).unwrap();
        assert_eq!(warnings.lines().count(), 1);
        assert!(warnings.contains("SYSTEM history was not included"));
        assert!(warnings.contains("access denied"));
        assert!(warnings.contains("elevated prompt"));

        let mut unsafe_warning = Vec::new();
        log_reports_with_discovery(
            &home,
            |_| {
                Err(anyhow::anyhow!(
                    "Protected path ACL grants write to a non-admin principal"
                ))
            },
            &mut Vec::new(),
            &mut unsafe_warning,
        )
        .unwrap();
        let unsafe_warning = String::from_utf8(unsafe_warning).unwrap();
        assert_eq!(unsafe_warning.lines().count(), 1);
        assert!(unsafe_warning.contains("protected directory permissions are unsafe"));
    }

    #[test]
    fn finish_writer_does_not_rewrite_an_unchanged_owner_config() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let path = home.file(device_config::FILE);
        let original =
            b"# owner note\n[report]\ncollector = \"https://owner.example.org/status\"\n";
        let old_backup = home.file("open-pact.toml.bak");
        fs::write(&old_backup, b"older owner config").unwrap();
        fs::write(&path, original).unwrap();
        let proposal = std::str::from_utf8(original).unwrap();
        assert!(
            write_proposal(&home, Some(original), proposal)
                .unwrap()
                .is_none()
        );
        let written = fs::read(&path).unwrap();
        assert_eq!(written, original);
        assert_eq!(fs::read(&old_backup).unwrap(), b"older owner config");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn finish_creates_the_config_example_once_when_no_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let path = home.file(device_config::FILE);
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let proposal = device_config::example(&manifest, Os::Macos, None, None);

        assert!(write_proposal(&home, None, &proposal).unwrap().is_none());
        assert_eq!(fs::read(&path).unwrap(), proposal.as_bytes());
        let written = fs::read(&path).unwrap();
        assert!(
            write_proposal(&home, Some(&written), &proposal)
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read(&path).unwrap(), written);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn finish_write_creates_a_timestamped_backup_without_replacing_old_backups() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let path = home.file(device_config::FILE);
        let original = b"owner config\n";
        fs::write(&path, original).unwrap();
        let old_backup = home.file("open-pact.toml.bak");
        fs::write(&old_backup, b"older owner config").unwrap();

        let backup = write_proposal(&home, Some(original), "updated config\n")
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"updated config\n");
        assert_eq!(fs::read(&backup).unwrap(), original);
        assert_eq!(fs::read(&old_backup).unwrap(), b"older owner config");
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("open-pact.toml.bak-")
        );
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn finish_write_uses_a_suffix_when_the_timestamped_backup_exists() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("open-pact.toml");
        let first = create_backup_at(&config, b"older", None, "20261102T120000Z").unwrap();
        let second = create_backup_at(&config, b"current", None, "20261102T120000Z").unwrap();
        assert_eq!(
            first.file_name().unwrap(),
            "open-pact.toml.bak-20261102T120000Z"
        );
        assert_eq!(
            second.file_name().unwrap(),
            "open-pact.toml.bak-20261102T120000Z-2"
        );
        assert_eq!(fs::read(first).unwrap(), b"older");
        assert_eq!(fs::read(second).unwrap(), b"current");
    }

    #[test]
    fn finish_write_rejects_a_concurrent_owner_edit_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let path = home.file(device_config::FILE);
        let original = b"[report]\ncollector = 'https://owner.example.org/status'\n";
        fs::write(&path, original).unwrap();
        FINISH_WRITE_HOOK.with(|hook| hook.set(Some(simulate_concurrent_owner_edit)));
        let error = write_proposal(
            &home,
            Some(original),
            "[report]\ncollector = 'https://company.example.org/status'\n",
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "open-pact.toml changed while finish ran. Run finish again."
        );
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("# concurrent edit")
        );
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            !name.ends_with(".tmp") && !name.starts_with("open-pact.toml.bak-")
        }));
    }

    fn simulate_concurrent_owner_edit(path: &Path) {
        fs::write(
            path,
            b"[report]\ncollector = 'https://owner.example.org/status'\n# concurrent edit\n",
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn finish_refuses_a_dangling_config_symlink_before_writing() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let path = home.file(device_config::FILE);
        symlink("missing-target", &path).unwrap();
        let error = write_proposal(&home, None, "[report]\n")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "open-pact.toml is a symbolic link. finish does not change it. Edit the target file by hand."
        );
        assert!(fs::read_link(&path).unwrap().ends_with("missing-target"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn log_reports_prints_records_oldest_first_with_payload_and_response() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let state = dir.path().join("report-state.json");
        for (id, kind, response, status) in [
            ("first", "periodic", b"ok".as_slice(), 200),
            ("second", "event", b"\xff".as_slice(), 503),
        ] {
            let payload = serde_json::json!({
                "report_id": id,
                "report_type": kind,
                "results": {"firewall": "on"},
            });
            let jws = format!(
                "e30.{}.signature",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
            );
            locallog::append_report_retained(
                &path,
                &state,
                jws.as_bytes(),
                response,
                status,
                false,
            )
            .unwrap();
        }
        let mut records = locallog::read(&path).unwrap();
        records[0].time = "2026-01-01T00:00:00Z".into();
        records[1].time = "2026-01-02T00:00:00Z".into();
        records[1].response_incomplete = true;
        fs::write(
            &path,
            records
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
                .join("\n")
                + "\n",
        )
        .unwrap();
        let mut output = Vec::new();
        log_reports(
            &[ReportLogFile {
                path: &path,
                source: "home",
                system_state: false,
            }],
            &mut output,
            &mut Vec::new(),
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.find("report_id:first").unwrap() < output.find("report_id:second").unwrap());
        assert!(output.contains("status:200"));
        assert!(output.contains("report_type:periodic"));
        assert!(output.contains("\"firewall\": \"on\""));
        assert!(output.contains("ok"));
        assert!(output.contains("1 response bytes (not UTF-8)"));
        assert!(output.contains("response incomplete"));
    }

    #[test]
    fn log_reports_reads_home_and_system_history() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home-reports.jsonl");
        let system = dir.path().join("system-reports.jsonl");
        let state = dir.path().join("report-state.json");
        for (path, id, time) in [
            (&system, "system-row", "2026-01-01T00:00:00Z"),
            (&home, "home-row", "2026-01-02T00:00:00Z"),
        ] {
            let payload = serde_json::json!({
                "report_id": id,
                "report_type": "periodic",
            });
            let jws = format!(
                "e30.{}.signature",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
            );
            locallog::append_report_retained(path, &state, jws.as_bytes(), b"ok", 200, false)
                .unwrap();
            let mut record = locallog::read(path).unwrap().remove(0);
            record.time = time.into();
            fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        let files = [
            ReportLogFile {
                path: &home,
                source: "home",
                system_state: false,
            },
            ReportLogFile {
                path: &system,
                source: "system",
                system_state: true,
            },
        ];
        let mut output = Vec::new();
        let mut warnings = Vec::new();

        log_reports(&files, &mut output, &mut warnings).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("source:home"));
        assert!(output.contains("source:system"));
        assert!(
            output.find("report_id:system-row").unwrap()
                < output.find("report_id:home-row").unwrap()
        );

        let unreadable_system = dir.path().join("unreadable-system");
        fs::create_dir(&unreadable_system).unwrap();
        let unreadable_files = [
            ReportLogFile {
                path: &home,
                source: "home",
                system_state: false,
            },
            ReportLogFile {
                path: &unreadable_system,
                source: "system",
                system_state: true,
            },
        ];
        let mut fallback = Vec::new();
        let mut warnings = Vec::new();
        log_reports(&unreadable_files, &mut fallback, &mut warnings).unwrap();
        let fallback = String::from_utf8(fallback).unwrap();
        assert!(fallback.contains("report_id:home-row"));
        let warnings = String::from_utf8(warnings).unwrap();
        assert_eq!(warnings.lines().count(), 1);
        assert!(warnings.contains("SYSTEM history was not included"));
        assert!(warnings.contains("elevated prompt"));
    }

    #[test]
    fn report_errors_name_physical_file_lines() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("report-state.json");
        let hash_path = dir.path().join("hash-reports.jsonl");
        locallog::append_report_retained(&hash_path, &state, b"first", b"ok", 200, false).unwrap();
        locallog::append_report_retained(&hash_path, &state, b"second", b"ok", 200, false).unwrap();
        let mut lines = fs::read_to_string(&hash_path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut bad_hash: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        bad_hash["sent_sha256"] = serde_json::Value::String("0".repeat(64));
        lines[1] = serde_json::to_string(&bad_hash).unwrap();
        fs::write(&hash_path, format!("{}\n\n{}\n", lines[0], lines[1])).unwrap();
        let hash_error = log_reports(
            &[ReportLogFile {
                path: &hash_path,
                source: "home",
                system_state: false,
            }],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            format!("{hash_error:#}").contains("line 3"),
            "{hash_error:#}"
        );

        let sorted_path = dir.path().join("sorted-reports.jsonl");
        let valid_payload = serde_json::json!({
            "report_id": "newer",
            "report_type": "periodic",
        });
        let valid_jws = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_payload).unwrap())
        );
        locallog::append_report_retained(
            &sorted_path,
            &state,
            valid_jws.as_bytes(),
            b"ok",
            200,
            false,
        )
        .unwrap();
        locallog::append_report_retained(
            &sorted_path,
            &state,
            b"e30.*.signature",
            b"ok",
            200,
            false,
        )
        .unwrap();
        let mut records = locallog::read(&sorted_path).unwrap();
        records[0].time = "2026-01-02T00:00:00Z".into();
        records[1].time = "2026-01-01T00:00:00Z".into();
        fs::write(
            &sorted_path,
            records
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
                .join("\n")
                + "\n",
        )
        .unwrap();
        let jws_error = log_reports(
            &[ReportLogFile {
                path: &sorted_path,
                source: "home",
                system_state: false,
            }],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(jws_error.to_string().contains("line 2"), "{jws_error:#}");
    }

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
                "os_supported",
                "screen_lock"
            ]
        );
        assert_eq!(
            ids(Os::Linux),
            [
                "antimalware_active",
                "disk_encryption",
                "firewall",
                "os_supported",
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
    fn substitutes_unknown_when_na_is_not_disclosed_but_unknown_is() {
        let template = include_str!("../../../examples/manifest.toml");
        let (body, log) = template.split_once("[log]").unwrap();
        let mut fixture = body.split("[[control]]").next().unwrap().to_string();
        for id in [
            "antimalware_active_threats",
            "antimalware_full_scan_age_days",
        ] {
            fixture.push_str(&format!("\n[[control]]\nid = \"{id}\"\nsource = \"company_policy\"\ncheck = \"builtin:{id}@1\"\noutput = {{ integer = {{ min = 0, max = 3650 }} }}\nrequired = {{ macos = {{ max = 0 }} }}\ngrace = \"1d\"\n"));
        }
        fixture.push_str("\n[[control]]\nid = \"web_protection\"\nsource = \"company_policy\"\ncheck = \"builtin:web_protection@1\"\noutput = [\"on\", \"off\", \"unknown\"]\nrequired = {}\ngrace = \"1d\"\n");
        fixture.push_str(&format!("\n[log]{log}"));
        let manifest = Manifest::parse(fixture.as_bytes()).unwrap();
        let all = BTreeMap::from([
            ("antimalware_active_threats".into(), "n/a".into()),
            ("antimalware_full_scan_age_days".into(), "n/a".into()),
            ("web_protection".into(), "n/a".into()),
        ]);

        let sent = disclosable(&manifest, Os::Macos, all);

        assert_eq!(sent["antimalware_active_threats"], "unknown");
        assert_eq!(sent["antimalware_full_scan_age_days"], "unknown");
        assert_eq!(sent["web_protection"], "unknown");

        let key = PublicKey::from(&dev_key::generate());
        let time = "2026-10-20T12:00:00Z".parse().unwrap();
        let claim = Claim {
            manifest: manifest.hash().clone(),
            device: Pseudonym::of(&key),
            device_key: key,
            nonce: "n".into(),
            time,
            client: "open-pact-client 0.0.1".into(),
            os: Os::Macos,
            trust_level: open_pact_core::TrustLevel::L0,
            virtualized: Some(Virtualized::No),
            results: sent,
            csr_sha256: None,
            log_checkpoint: None,
        };
        let decision = open_pact_core::evaluate(
            &manifest,
            &claim,
            time,
            &open_pact_core::FirstFailures::new(),
        )
        .decision;
        let open_pact_core::Decision::Allow { warnings } = decision else {
            panic!("unknown detection results should receive unknown_grace");
        };
        let warnings = warnings.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 2);
        assert!(warnings.iter().any(|warning| {
            warning.starts_with("antimalware_active_threats = unknown")
                && warning.ends_with("access ends in 7d")
        }));
        assert!(warnings.iter().any(|warning| {
            warning.starts_with("antimalware_full_scan_age_days = unknown")
                && warning.ends_with("access ends in 7d")
        }));
    }

    #[test]
    fn keeps_na_when_declared_and_omits_na_when_unknown_is_not_declared() {
        let template = include_str!("../../../examples/manifest.toml").replace("\r\n", "\n");
        let manifest = Manifest::parse(template.as_bytes()).unwrap();
        let all = BTreeMap::from([
            ("antimalware_active_threats".into(), "n/a".into()),
            ("antimalware_full_scan_age_days".into(), "n/a".into()),
        ]);
        let sent = disclosable(&manifest, Os::Macos, all);
        assert_eq!(sent["antimalware_active_threats"], "n/a");
        assert_eq!(sent["antimalware_full_scan_age_days"], "n/a");

        let no_fallback = template
            .split("[[control]]")
            .map(|block| {
                if block.starts_with("\nid = \"antimalware_active_threats\"")
                    || block.starts_with("\nid = \"antimalware_full_scan_age_days\"")
                {
                    block
                        .lines()
                        .map(|line| {
                            if line.starts_with("output = ") {
                                "output = [\"0\", \"1\"]"
                            } else if line.starts_with("required = ") {
                                "required = {}"
                            } else {
                                line
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                } else {
                    block.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("[[control]]");
        let manifest = Manifest::parse(no_fallback.as_bytes()).unwrap();
        let all = BTreeMap::from([
            ("antimalware_active_threats".into(), "n/a".into()),
            ("antimalware_full_scan_age_days".into(), "n/a".into()),
        ]);
        assert!(disclosable(&manifest, Os::Macos, all).is_empty());
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

    fn approval_fixture(
        home: &Home,
        company: &Company,
        witness: &Witness,
    ) -> (Manifest, Enrolment, Vec<Entry>, String, String) {
        let manifest = Manifest::parse(&fs::read(home.file("manifest.toml")).unwrap()).unwrap();
        let enrolment = home.enrolment().unwrap();
        let entries = vec![
            Entry {
                index: 0,
                kind: EntryKind::ManifestPublished,
                data: json!({"manifest": enrolment.manifest.as_str()}),
            },
            Entry {
                index: 1,
                kind: EntryKind::DeviceEnrolled,
                data: json!({"commitment": commitment(&enrolment).unwrap()}),
            },
            Entry {
                index: 2,
                kind: EntryKind::DeviceApproved,
                data: json!({"commitment": commitment(&enrolment).unwrap()}),
            },
        ];
        let mut before_approval = company.sign(&checkpoint_of(company.log.origin(), &entries, 2));
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
        witness.cosign(&mut before_approval, now);
        let before_approval = before_approval.to_string();
        home.write(LOG_CHECKPOINT, before_approval.as_bytes())
            .unwrap();
        let mut approved = company.sign(&checkpoint_of(company.log.origin(), &entries, 3));
        witness.cosign(&mut approved, now);
        let approved = approved.to_string();
        (manifest, enrolment, entries, before_approval, approved)
    }

    fn my_entries_response(checkpoint: &str, entries: &[Entry], size: usize) -> String {
        let leaves: Vec<_> = entries.iter().map(Entry::leaf_hash).collect();
        serde_json::to_string(&MyEntries {
            checkpoint: checkpoint.into(),
            manifest: open_pact_core::EntryWithProof {
                entry: entries[0].clone(),
                proof: open_pact_core::inclusion_proof(&leaves[..size], 0).unwrap(),
            },
            device: entries[1..size]
                .iter()
                .map(|entry| open_pact_core::EntryWithProof {
                    entry: entry.clone(),
                    proof: open_pact_core::inclusion_proof(&leaves[..size], entry.index).unwrap(),
                })
                .collect(),
        })
        .unwrap()
    }

    fn put_gateway_in_enrolment(home: &Home, enrolment: &mut Enrolment, url: &str) {
        enrolment.gateway = url.to_string();
        home.write("enrolment.json", &serde_json::to_vec(enrolment).unwrap())
            .unwrap();
    }

    #[test]
    fn home_reader_returns_file_bytes_and_missing_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        std::fs::write(&path, b"fixture").unwrap();
        assert_eq!(read_home_file(&path).unwrap(), b"fixture");
        assert_eq!(
            read_home_file(&dir.path().join("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(windows)]
    #[test]
    fn home_reader_refuses_reparse_point_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        let link = dir.path().join("link");
        std::fs::write(&file, b"fixture").unwrap();
        std::os::windows::fs::symlink_file(&file, &link).unwrap();
        assert_eq!(
            read_home_file(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

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
    async fn check_reports_device_state_after_private_log_denial_under_path_prefix() {
        for state in ["pending", "revoked"] {
            let company = Company::new();
            let witness = Witness::new();
            let toml = witnessed_manifest(&witness);
            let published = Company::published(&toml, &company.key);
            let log = company.log.vkey();
            let mut checkpoint = Note::parse(&company.empty_checkpoint()).unwrap();
            witness.cosign(
                &mut checkpoint,
                u64::try_from(chrono::Utc::now().timestamp()).unwrap(),
            );
            let checkpoint = checkpoint.to_string();
            let gateway = FakeGateway::start(move |line, _| match line {
                "GET /api/v1/manifest" => (200, published.clone()),
                "GET /api/v1/log/key" => (200, log.clone()),
                "GET /api/v1/log/checkpoint" => (200, checkpoint.clone()),
                "POST /api/v1/nonce" => (200, json!({"nonce":"state-nonce"}).to_string()),
                "POST /api/v1/log/mine" => (403, json!({"status":"denied"}).to_string()),
                "POST /api/v1/device/status" => (200, json!({"state":state}).to_string()),
                _ => not_found(),
            })
            .await;
            let dir = tempfile::tempdir().unwrap();
            let gateway_url = format!("{}/api", gateway.url);
            let home = enrolled_home_with(dir.path(), &gateway_url, &company, &toml);
            fs::write(home.file("claims.jsonl"), b"{\"time\":\n").unwrap();
            assert_eq!(
                check(&home, true).await.unwrap(),
                ExitCode::FAILURE,
                "{state}"
            );
            assert_eq!(
                gateway.posts(),
                [
                    "POST /api/v1/nonce",
                    "POST /api/v1/log/mine",
                    "POST /api/v1/nonce",
                    "POST /api/v1/device/status"
                ]
            );
            assert!(!home.file("vpn-key.pem").exists());
        }
    }

    #[tokio::test]
    async fn first_checkpoint_requires_gateway_and_witness_signatures_without_public_entries() {
        for case in ["valid", "wrong gateway", "missing witness", "wrong witness"] {
            let company = Company::new();
            let witness = Witness::new();
            let toml = witnessed_manifest(&witness);
            let manifest = Manifest::parse(toml.as_bytes()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let home = enrolled_home_with(dir.path(), "", &company, &toml);
            let cp = checkpoint_of(
                company.log.origin(),
                &[Entry {
                    index: 0,
                    kind: EntryKind::ManifestPublished,
                    data: json!({"manifest": manifest.hash()}),
                }],
                1,
            );
            let mut note = if case == "wrong gateway" {
                Company::new().sign(&cp)
            } else {
                company.sign(&cp)
            };
            let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
            if case != "missing witness" {
                witness.cosign(&mut note, now);
            }
            if case == "wrong witness" {
                note.signatures.last_mut().unwrap().payload[12] ^= 1;
            }
            let published = Company::published(&toml, &company.key);
            let log = company.log.vkey();
            let note = note.to_string();
            let gateway = FakeGateway::start(move |line, _| match line {
                "GET /v1/manifest" => (200, published.clone()),
                "GET /v1/log/key" => (200, log.clone()),
                "GET /v1/log/checkpoint" => (200, note.clone()),
                _ => not_found(),
            })
            .await;
            let result = sync_checkpoint(
                &http_client().unwrap(),
                &home,
                &gateway.url,
                manifest.body().log.as_ref(),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), case == "valid", "{case}: {result:?}");
            assert_eq!(home.checkpoint().unwrap().is_some(), case == "valid");
            assert_eq!(
                gateway.requests(),
                [
                    "GET /v1/manifest",
                    "GET /v1/log/key",
                    "GET /v1/log/checkpoint"
                ]
            );
        }
    }

    #[tokio::test]
    async fn own_entries_use_private_endpoint_and_reject_bad_proofs() {
        for (corrupt, stored) in [(false, false), (false, true), (true, false)] {
            let company = Company::new();
            let witness = Witness::new();
            let toml = witnessed_manifest(&witness);
            let dir = tempfile::tempdir().unwrap();
            let home = enrolled_home_with(dir.path(), "", &company, &toml);
            let mut enrolment = home.enrolment().unwrap();
            if stored {
                enrolment.log_entries = Some(OwnEntries {
                    manifest: 0,
                    enrolment: 1,
                });
            }
            let mine = commitment(&enrolment).unwrap();
            let entries = vec![
                Entry {
                    index: 0,
                    kind: EntryKind::ManifestPublished,
                    data: json!({"manifest": enrolment.manifest}),
                },
                Entry {
                    index: 1,
                    kind: EntryKind::DeviceEnrolled,
                    data: json!({"commitment": mine}),
                },
                Entry {
                    index: 2,
                    kind: EntryKind::DeviceApproved,
                    data: json!({"commitment": mine}),
                },
            ];
            let mut cp = checkpoint_of(company.log.origin(), &entries, 3);
            let leaves: Vec<_> = entries.iter().map(Entry::leaf_hash).collect();
            let mut note = company.sign(&cp);
            witness.cosign(
                &mut note,
                u64::try_from(chrono::Utc::now().timestamp()).unwrap(),
            );
            let mut response = MyEntries {
                checkpoint: note.to_string(),
                manifest: open_pact_core::EntryWithProof {
                    entry: entries[0].clone(),
                    proof: open_pact_core::inclusion_proof(&leaves, 0).unwrap(),
                },
                device: entries[1..]
                    .iter()
                    .map(|entry| open_pact_core::EntryWithProof {
                        entry: entry.clone(),
                        proof: open_pact_core::inclusion_proof(&leaves, entry.index).unwrap(),
                    })
                    .collect(),
            };
            if corrupt {
                response.device[1].proof[0] = LogHash([0; 32]);
            }
            let response = serde_json::to_string(&response).unwrap();
            let gateway = FakeGateway::start(move |line, _| match line {
                "POST /v1/nonce" => (200, json!({"nonce":"own-entry-nonce"}).to_string()),
                "POST /v1/log/mine" => (200, response.clone()),
                _ => not_found(),
            })
            .await;
            enrolment.gateway = gateway.url.clone();
            let result = check_own_entries(&http_client().unwrap(), &home, &mut enrolment, &mut cp)
                .await
                .unwrap();
            assert_eq!(result.is_ok(), !corrupt, "{result:?}");
            assert_eq!(gateway.requests(), ["POST /v1/nonce", "POST /v1/log/mine"]);
            assert_eq!(enrolment.log_entries.is_some(), !corrupt);
        }
    }

    #[tokio::test]
    async fn join_retries_a_dropped_or_truncated_status_response() {
        for (first_status, first_body) in
            [(0, String::new()), (598, r#"{"state":"pending""#.into())]
        {
            let company = Company::new();
            let dir = tempfile::tempdir().unwrap();
            let home = enrolled_home(dir.path(), "", &company);
            let enrolment = home.enrolment().unwrap();
            let manifest = Manifest::parse(DEMO_MANIFEST.as_bytes()).unwrap();
            let gateway = FakeGateway::start(move |line, nth| match line {
                "POST /v1/nonce" => (200, json!({"nonce":format!("network-{nth}")}).to_string()),
                "POST /v1/device/status" if nth == 0 => (first_status, first_body.clone()),
                "POST /v1/device/status" => (200, r#"{"state":"revoked"}"#.into()),
                _ => not_found(),
            })
            .await;
            let mut enrolment = enrolment;
            put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

            let waited = wait_for_approval(
                &http_client().unwrap(),
                &home,
                &enrolment,
                &manifest,
                Duration::from_millis(1),
                false,
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(waited, ApprovalWait::Revoked);
            assert_eq!(
                gateway
                    .requests()
                    .iter()
                    .filter(|request| request.as_str() == "POST /v1/device/status")
                    .count(),
                2
            );
            assert!(
                !gateway
                    .requests()
                    .iter()
                    .any(|request| request == "POST /v1/log/mine")
            );
        }
    }

    #[tokio::test]
    async fn join_stops_on_a_complete_malformed_status_response() {
        let company = Company::new();
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path(), "", &company);
        let mut enrolment = home.enrolment().unwrap();
        let manifest = Manifest::parse(DEMO_MANIFEST.as_bytes()).unwrap();
        let gateway = FakeGateway::start(|line, nth| match line {
            "POST /v1/nonce" => (200, json!({"nonce":format!("malformed-{nth}")}).to_string()),
            "POST /v1/device/status" => (200, "not json".into()),
            _ => not_found(),
        })
        .await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

        let error = wait_for_approval(
            &http_client().unwrap(),
            &home,
            &enrolment,
            &manifest,
            Duration::from_millis(1),
            false,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(error.contains("expected ident"), "{error}");
        assert_eq!(
            gateway
                .requests()
                .iter()
                .filter(|request| request.as_str() == "POST /v1/device/status")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn join_retries_a_transient_consistency_proof_fetch_failure() {
        let company = Company::new();
        let witness = Witness::new();
        let toml = witnessed_manifest(&witness);
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), "", &company, &toml);
        let (manifest, mut enrolment, entries, _, approved_checkpoint) =
            approval_fixture(&home, &company, &witness);
        let response = my_entries_response(&approved_checkpoint, &entries, 3);
        let gateway = FakeGateway::start(move |line, nth| match line {
            "POST /v1/nonce" => (200, json!({"nonce":format!("proof-{nth}")}).to_string()),
            "POST /v1/device/status" => (200, r#"{"state":"approved"}"#.into()),
            "POST /v1/log/mine" => (200, response.clone()),
            line if line.starts_with("GET /v1/log/proof/consistency?") && nth == 0 => {
                (503, "{}".into())
            }
            line => serve_log(&entries, line).unwrap_or_else(not_found),
        })
        .await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

        let waited = wait_for_approval(
            &http_client().unwrap(),
            &home,
            &enrolment,
            &manifest,
            Duration::from_millis(1),
            false,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(waited, ApprovalWait::Approved);
        assert_eq!(
            gateway
                .requests()
                .iter()
                .filter(|request| request.as_str() == "POST /v1/device/status")
                .count(),
            2
        );
        assert_eq!(
            gateway
                .requests()
                .iter()
                .filter(|request| request.starts_with("GET /v1/log/proof/consistency?"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn join_refuses_to_resume_an_enrolment_with_another_device_key() {
        let company = Company::new();
        let witness = Witness::new();
        let manifest = witnessed_manifest(&witness);
        let published = Company::published(&manifest, &company.key);
        let log = company.log.vkey();
        let mut checkpoint = Note::parse(&company.empty_checkpoint()).unwrap();
        witness.cosign(
            &mut checkpoint,
            u64::try_from(chrono::Utc::now().timestamp()).unwrap(),
        );
        let checkpoint = checkpoint.to_string();
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, checkpoint.clone()),
            _ => not_found(),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), &gateway.url, &company, &manifest);
        DeviceKey::delete(dir.path()).unwrap();
        DeviceKey::load_or_create(dir.path(), true).unwrap();
        let invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([7; 32]),
        )
        .encode();

        let error = join(
            &home,
            &invitation,
            true,
            true,
            false,
            true,
            APPROVAL_POLL_INTERVAL,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(error.contains("This home has an enrolment for a different device key."));
        assert!(error.contains("delete-device-key"));
        assert!(
            !gateway
                .requests()
                .iter()
                .any(|request| request == "POST /v1/enroll" || request == "POST /v1/device/status")
        );
    }

    #[tokio::test]
    async fn join_reenrols_after_the_saved_device_key_is_deleted() {
        let witness = Witness::new();
        let toml = witnessed_manifest(&witness);
        let company = Company::new();
        let published = Company::published(&toml, &company.key);
        let log = company.log.vkey();
        let mut checkpoint = company.sign(&Checkpoint {
            origin: company.log.origin().into(),
            size: 1,
            root: LogHash([3; 32]),
        });
        witness.cosign(
            &mut checkpoint,
            u64::try_from(chrono::Utc::now().timestamp()).unwrap(),
        );
        let checkpoint = checkpoint.to_string();
        let checkpoint_for_gateway = checkpoint.clone();
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, checkpoint_for_gateway.clone()),
            "POST /v1/enroll" => (
                200,
                json!({"salt":"11".repeat(32),"state":"pending"}).to_string(),
            ),
            _ => not_found(),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), &gateway.url, &company, &toml);
        home.write(LOG_CHECKPOINT, checkpoint.as_bytes()).unwrap();
        let original = home.enrolment().unwrap();
        let old_invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([7; 32]),
        )
        .encode();

        DeviceKey::delete(dir.path()).unwrap();
        DeviceKey::load_or_create(dir.path(), true).unwrap();
        let mismatch = join(
            &home,
            &old_invitation,
            true,
            true,
            false,
            true,
            APPROVAL_POLL_INTERVAL,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(mismatch.contains("This home has an enrolment for a different device key."));
        assert!(gateway.posts().is_empty(), "mismatch must not enrol");

        DeviceKey::delete(dir.path()).unwrap();
        let new_invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([8; 32]),
        )
        .encode();
        let exit = join(
            &home,
            &new_invitation,
            true,
            true,
            false,
            true,
            APPROVAL_POLL_INTERVAL,
        )
        .await
        .unwrap();

        assert_eq!(exit, ExitCode::SUCCESS);
        assert_eq!(gateway.posts(), vec!["POST /v1/enroll"]);
        let replacement = home.enrolment().unwrap();
        assert_ne!(replacement.device, original.device);
        assert!(dir.path().join("device-dev.pem").exists());
    }

    #[tokio::test]
    async fn check_reports_consistency_proof_url_and_json_error() {
        let company = Company::new();
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path(), "", &company);
        let new = Checkpoint {
            origin: company.log.origin().into(),
            size: 2,
            root: LogHash([1; 32]),
        };
        let new_note = company.sign(&new).to_string();
        let old = Checkpoint {
            origin: company.log.origin().into(),
            size: 1,
            root: LogHash([2; 32]),
        };
        let gateway = FakeGateway::start(|line, _| {
            if line.starts_with("GET /v1/log/proof/consistency?") {
                (200, "not json".into())
            } else {
                not_found()
            }
        })
        .await;
        let error = verify_checkpoint(
            &http_client().unwrap(),
            &home,
            &gateway.url,
            &company.log,
            None,
            Some(&old),
            &new_note,
        )
        .await
        .unwrap()
        .unwrap_err()
        .alarm_text();

        assert!(error.contains(&format!(
            "GET {}/v1/log/proof/consistency?from=1&to=2",
            gateway.url
        )));
        assert!(
            error.contains("expected ident at line 1 column 2"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn join_waits_for_approval_and_verifies_its_log_entry() {
        let company = Company::new();
        let witness = Witness::new();
        let toml = witnessed_manifest(&witness);
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), "", &company, &toml);
        let (_manifest, mut enrolment, entries, before_approval, approved_checkpoint) =
            approval_fixture(&home, &company, &witness);
        let response = my_entries_response(&approved_checkpoint, &entries, 3);
        let entries_for_log = entries.clone();
        let published = Company::published(&toml, &company.key);
        let log_key = company.log.vkey();
        let gateway = FakeGateway::start(move |line, nth| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log_key}\n")),
            "GET /v1/log/checkpoint" => (
                200,
                if nth == 0 {
                    before_approval.clone()
                } else {
                    approved_checkpoint.clone()
                },
            ),
            "POST /v1/nonce" => (200, json!({"nonce":format!("approval-{nth}")}).to_string()),
            "POST /v1/device/status" => (
                200,
                json!({"state": if nth == 0 { "pending" } else { "approved" }}).to_string(),
            ),
            "POST /v1/log/mine" => (200, response.clone()),
            _ => serve_log(&entries_for_log, line).unwrap_or_else(not_found),
        })
        .await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);
        let invitation = Invitation::new(
            &gateway.url,
            &PublicKey::from(&company.key),
            &company.log,
            open_pact_core::InvitationCode::from_bytes([7; 32]),
        )
        .encode();

        let code = join(
            &home,
            &invitation,
            true,
            true,
            false,
            false,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(approval_confirmation(), "This device is approved.");
        assert_eq!(
            approved_next_hint("open-pact-client"),
            "Next: open-pact-client finish"
        );
        let requests = gateway.requests();
        assert!(!requests.iter().any(|request| request == "POST /v1/enroll"));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.as_str() == "POST /v1/device/status")
                .count(),
            2
        );
        let second_status = requests
            .iter()
            .rposition(|request| request == "POST /v1/device/status")
            .unwrap();
        let log_read = requests
            .iter()
            .position(|request| request == "POST /v1/log/mine")
            .unwrap();
        assert!(
            second_status < log_read,
            "approval status precedes private log read"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.as_str() == "POST /v1/log/mine")
                .count(),
            1
        );
        assert!(
            !requests.iter().any(|request| request == "POST /v1/claim"),
            "a non-terminal join stops before finish and check"
        );
        let resumed = resume_join(&home, false, false, Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(resumed, ExitCode::SUCCESS);
        let resumed_requests = gateway.requests();
        assert!(
            !resumed_requests
                .iter()
                .any(|request| request == "POST /v1/enroll")
        );
        assert!(
            !resumed_requests
                .iter()
                .any(|request| request == "POST /v1/claim")
        );
    }

    #[test]
    fn join_invitation_argument_is_optional_for_a_saved_enrolment() {
        let cli = Cli::try_parse_from(["open-pact-client", "join"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Join {
                invitation: None,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn join_waits_until_the_approval_entry_reaches_the_signed_checkpoint() {
        let company = Company::new();
        let witness = Witness::new();
        let toml = witnessed_manifest(&witness);
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), "", &company, &toml);
        let (manifest, mut enrolment, entries, before_approval, approved_checkpoint) =
            approval_fixture(&home, &company, &witness);
        let lagging_response = my_entries_response(&before_approval, &entries, 2);
        let approved_response = my_entries_response(&approved_checkpoint, &entries, 3);
        let entries_for_log = entries.clone();
        let gateway = FakeGateway::start(move |line, nth| match line {
            "POST /v1/nonce" => (200, json!({"nonce":format!("lag-{nth}")}).to_string()),
            "POST /v1/device/status" => (200, r#"{"state":"approved"}"#.into()),
            "POST /v1/log/mine" if nth == 0 => (200, lagging_response.clone()),
            "POST /v1/log/mine" => (200, approved_response.clone()),
            _ => serve_log(&entries_for_log, line).unwrap_or_else(not_found),
        })
        .await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

        let waited = wait_for_approval(
            &http_client().unwrap(),
            &home,
            &enrolment,
            &manifest,
            Duration::from_millis(1),
            false,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(waited, ApprovalWait::Approved);
        assert_eq!(
            gateway
                .requests()
                .iter()
                .filter(|request| request.as_str() == "POST /v1/log/mine")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn join_stops_when_it_revokes_a_waiting_device() {
        let company = Company::new();
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path(), "", &company);
        let manifest = Manifest::parse(DEMO_MANIFEST.as_bytes()).unwrap();
        let mut enrolment = home.enrolment().unwrap();
        let gateway = FakeGateway::start(|line, nth| match line {
            "POST /v1/nonce" => (200, json!({"nonce":format!("revoked-{nth}")}).to_string()),
            "POST /v1/device/status" => (
                200,
                json!({"state": if nth == 0 { "pending" } else { "revoked" }}).to_string(),
            ),
            _ => not_found(),
        })
        .await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

        let waited = wait_for_approval(
            &http_client().unwrap(),
            &home,
            &enrolment,
            &manifest,
            Duration::from_millis(1),
            false,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(waited, ApprovalWait::Revoked);
        assert_eq!(approval_exit(waited, "open-pact-client"), ExitCode::FAILURE);
        assert!(
            !gateway
                .requests()
                .iter()
                .any(|request| request == "POST /v1/log/mine")
        );
    }

    #[tokio::test]
    async fn join_no_wait_does_not_poll_status() {
        let company = Company::new();
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path(), "", &company);
        let mut enrolment = home.enrolment().unwrap();
        let manifest = Manifest::parse(DEMO_MANIFEST.as_bytes()).unwrap();
        let gateway = FakeGateway::start(|_, _| not_found()).await;
        put_gateway_in_enrolment(&home, &mut enrolment, &gateway.url);

        let code = wait_after_join(
            &http_client().unwrap(),
            &home,
            &enrolment,
            &manifest,
            JoinOptions {
                insecure_dev: true,
                no_wait: true,
                poll_interval: APPROVAL_POLL_INTERVAL,
            },
            false,
        )
        .await
        .unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
        assert!(gateway.posts().is_empty());
    }

    #[tokio::test]
    async fn old_gateway_returns_a_clear_version_error_without_fetching_the_full_log() {
        let company = Company::new();
        let toml = witnessed_manifest(&Witness::new());
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with(dir.path(), "", &company, &toml);
        let mut enrolment = home.enrolment().unwrap();
        let mut cp = Checkpoint {
            origin: company.log.origin().into(),
            size: 1,
            root: LogHash([0; 32]),
        };
        let gateway = FakeGateway::start(|line, _| match line {
            "POST /v1/nonce" => (200, json!({"nonce":"old-gateway-nonce"}).to_string()),
            "POST /v1/log/mine" => not_found(),
            _ => not_found(),
        })
        .await;
        enrolment.gateway = gateway.url.clone();

        let error = check_own_entries(&http_client().unwrap(), &home, &mut enrolment, &mut cp)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "The gateway does not support this client version. Ask IT to update the gateway to 0.4.0 or later."
        );
        assert_eq!(gateway.requests(), ["POST /v1/nonce", "POST /v1/log/mine"]);
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
        let mut after = snapshot(dir.path());
        after.remove("repo-scan.json");
        assert_eq!(after, before, "no CA, certificate, key or log written");
        assert!(home.file("repo-scan.json").is_file());
        assert_eq!(code.unwrap(), ExitCode::from(2));
    }

    /// The demo manifest with only the cheap `os_supported` check and `witness` as its one witness.
    fn witnessed_manifest(witness: &Witness) -> String {
        let manifest = DEMO_MANIFEST.replace("\r\n", "\n");
        let first = manifest.find("[[control]]").unwrap();
        let kept = manifest.find("[[control]]\nid = \"os_supported\"").unwrap();
        let log = manifest.find("[log]").unwrap();
        let end = manifest[kept + 1..log]
            .find("[[control]]")
            .map_or(log, |next| kept + 1 + next);
        let toml = format!(
            "{}{}{}",
            &manifest[..first],
            &manifest[kept..end],
            &manifest[log..]
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
        device_config: Option<&str>,
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
        let leaves: Vec<_> = entries[..2].iter().map(Entry::leaf_hash).collect();
        let mine_response = serde_json::to_string(&MyEntries {
            checkpoint: before_claim.clone(),
            manifest: open_pact_core::EntryWithProof {
                entry: entries[0].clone(),
                proof: open_pact_core::inclusion_proof(&leaves, 0).unwrap(),
            },
            device: vec![open_pact_core::EntryWithProof {
                entry: entries[1].clone(),
                proof: open_pact_core::inclusion_proof(&leaves, 1).unwrap(),
            }],
        })
        .unwrap();
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, format!("{log}\n")),
            "GET /v1/log/checkpoint" => (200, stored.clone()),
            "POST /v1/nonce" => (200, r#"{"nonce":"n"}"#.into()),
            "POST /v1/claim" => (200, claim.clone()),
            "POST /v1/log/mine" => (200, mine_response.clone()),
            _ => serve_log(&entries, line).unwrap_or_else(not_found),
        })
        .await;
        let home = enrolled_home_with(dir.path(), &gateway.url, &company, &toml);
        home.write(LOG_CHECKPOINT, before_claim.as_bytes()).unwrap();
        if let Some(config) = device_config {
            home.write(crate::device_config::FILE, config.as_bytes())
                .unwrap();
        }
        let before = snapshot(dir.path());

        let code = check(&home, false).await;
        #[cfg(windows)]
        if code.as_ref().is_err() || code.as_ref().is_ok_and(|code| *code != ExitCode::SUCCESS) {
            assert!(
                !home.file(VPN_DIR).exists(),
                "rejected response wrote VPN state"
            );
        }

        let posts = gateway.posts();
        assert_eq!(
            posts,
            [
                "POST /v1/nonce",
                "POST /v1/log/mine",
                "POST /v1/nonce",
                "POST /v1/claim"
            ],
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
                check_with_response_checkpoint(grown_checkpoint, pair, None).await;
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

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn invalid_device_config_still_sends_all_manifest_controls() {
        use base64::Engine;
        let (code, _, after, _) = check_with_response_checkpoint(
            grown_checkpoint,
            valid_pair,
            Some("[managed_repos]\nfolders = ['relative-private-folder']"),
        )
        .await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        let record: locallog::Record = serde_json::from_slice(&after["claims.jsonl"]).unwrap();
        let sent: Value = serde_json::from_slice(&record.sent().unwrap()).unwrap();
        let payload = sent["jws"].as_str().unwrap().split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let claim: Value = serde_json::from_slice(&bytes).unwrap();
        let manifest = Manifest::parse(&after["manifest.toml"]).unwrap();
        assert_eq!(
            claim["results"].as_object().unwrap().len(),
            manifest.body().controls.len()
        );
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("relative-private-folder")
        );
    }

    #[tokio::test]
    async fn check_installs_the_certificate_of_a_verified_response_checkpoint() {
        let (code, before, after, pair) =
            check_with_response_checkpoint(grown_checkpoint, valid_pair, None).await;
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
                check_with_response_checkpoint(response, valid_pair, None).await;
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

        let joined = join(
            &home,
            &invitation,
            true,
            true,
            false,
            true,
            APPROVAL_POLL_INTERVAL,
        )
        .await;

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
            true,
            APPROVAL_POLL_INTERVAL,
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

    #[cfg(windows)]
    fn selected_windows_vpn_pair(home: &Home) -> Option<[Vec<u8>; 2]> {
        let vpn = home.file(VPN_DIR);
        let generation = match std::fs::read_to_string(vpn.join(VPN_CURRENT)) {
            Ok(generation) => generation,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("{error}"),
        };
        Some(VPN_FILES.map(|name| std::fs::read(vpn.join(&generation).join(name)).unwrap()))
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_install_and_recovery_survive_every_interruption() {
        let earlier = [b"earlier CA".to_vec(), b"earlier certificate".to_vec()];
        let new = [b"new CA".to_vec(), b"new certificate".to_vec()];
        for layout in ["empty", "plain files", "installed"] {
            let mut completed = false;
            for step in 1..=32 {
                let dir = tempfile::tempdir().unwrap();
                let home = Home(dir.path().join("fictional-home"));
                if layout == "installed" {
                    home.install_vpn_pair(&earlier[0], &earlier[1]).unwrap();
                } else if layout == "plain files" {
                    for (name, bytes) in VPN_FILES.iter().zip(&earlier) {
                        home.write(name, bytes).unwrap();
                    }
                }
                INTERRUPT_AFTER.with(|left| left.set(Some(step)));
                let result = std::panic::catch_unwind(|| home.install_vpn_pair(&new[0], &new[1]));
                INTERRUPT_AFTER.with(|left| left.set(None));
                let finished = match result {
                    Ok(result) => {
                        result.unwrap();
                        true
                    }
                    Err(_) => false,
                };
                let selected = selected_windows_vpn_pair(&home);
                assert!(
                    selected.is_none()
                        || selected.as_ref() == Some(&earlier)
                        || selected.as_ref() == Some(&new)
                );
                if layout == "installed" {
                    assert!(selected.is_some());
                }
                // Recovery can itself stop while repairing either documented file.
                for recovery_step in 1..=5 {
                    INTERRUPT_AFTER.with(|left| left.set(Some(recovery_step)));
                    let result = std::panic::catch_unwind(|| home.recover_vpn());
                    INTERRUPT_AFTER.with(|left| left.set(None));
                    if let Ok(result) = result {
                        result.unwrap();
                    }
                    assert_eq!(selected_windows_vpn_pair(&home), selected);
                }
                home.recover_vpn().unwrap();
                home.recover_vpn().unwrap();
                if let Some(selected) = &selected {
                    assert_eq!(
                        VPN_FILES.map(|name| std::fs::read(home.file(name)).unwrap()),
                        *selected
                    );
                } else if layout == "plain files" {
                    assert_eq!(
                        VPN_FILES.map(|name| std::fs::read(home.file(name)).unwrap()),
                        earlier
                    );
                } else {
                    assert!(VPN_FILES.iter().all(|name| !home.file(name).exists()));
                }
                let generations: Vec<_> = std::fs::read_dir(home.file(VPN_DIR))
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .filter(|entry| entry.file_type().unwrap().is_dir())
                    .collect();
                for entry in &generations {
                    let name = entry.file_name().into_string().unwrap();
                    assert!(
                        Some(&name) == home.vpn_generation(VPN_CURRENT).unwrap().as_ref()
                            || Some(&name) == home.vpn_generation("previous").unwrap().as_ref()
                    );
                }
                assert!(generations.len() <= 2);
                assert!(!std::fs::read_dir(&home.0).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                }));
                if finished {
                    assert_eq!(selected, Some(new.clone()));
                    completed = true;
                    break;
                }
            }
            assert!(completed, "{layout}: did not reach a complete installation");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_recovery_repairs_flat_files_and_removes_stale_generations() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        home.install_vpn_pair(b"fictional CA", b"fictional certificate")
            .unwrap();
        let selected = selected_windows_vpn_pair(&home).unwrap();
        std::fs::write(home.file(VPN_FILES[0]), b"stale CA").unwrap();
        std::fs::remove_file(home.file(VPN_FILES[1])).unwrap();
        let vpn = home.file(VPN_DIR);
        std::fs::create_dir(vpn.join("123-456")).unwrap();
        std::fs::write(vpn.join("123-456/ca.pem"), b"unfinished").unwrap();
        std::fs::write(vpn.join(".current.123.tmp"), b"unfinished").unwrap();
        std::fs::write(home.file(".ca.pem.123.tmp"), b"unfinished").unwrap();
        home.recover_vpn().unwrap();
        assert_eq!(
            VPN_FILES.map(|name| std::fs::read(home.file(name)).unwrap()),
            selected
        );
        assert_eq!(std::fs::read_dir(vpn).unwrap().count(), 3);
        assert!(!home.file(".ca.pem.123.tmp").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_reader_retries_after_two_switches() {
        for switches in [1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let home = Home(dir.path().to_path_buf());
            home.install_vpn_pair(b"CA one", b"certificate one")
                .unwrap();
            let vpn = home.file(VPN_DIR);
            let first = home.vpn_generation(VPN_CURRENT).unwrap().unwrap();
            let mut attempts = 0;
            let pair = loop {
                attempts += 1;
                let before = home.vpn_generation(VPN_CURRENT).unwrap().unwrap();
                let ca = std::fs::read(vpn.join(&before).join(VPN_FILES[0]));
                if attempts == 1 {
                    home.install_vpn_pair(b"CA two", b"certificate two")
                        .unwrap();
                    assert!(vpn.join(&first).join(VPN_FILES[1]).exists());
                    if switches == 2 {
                        home.install_vpn_pair(b"CA three", b"certificate three")
                            .unwrap();
                        assert!(!vpn.join(&first).exists());
                    }
                }
                let cert = std::fs::read(vpn.join(&before).join(VPN_FILES[1]));
                let after = home.vpn_generation(VPN_CURRENT).unwrap().unwrap();
                if before == after
                    && let (Ok(ca), Ok(cert)) = (ca, cert)
                {
                    break [ca, cert];
                }
                assert!(attempts < 10);
            };
            assert_eq!(attempts, 2);
            assert_eq!(Some(pair), selected_windows_vpn_pair(&home));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_sharing_violation_keeps_new_generation_and_retries_flat_copies() {
        use std::os::windows::fs::OpenOptionsExt;
        for native in [false, true] {
            for baseline in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let home = Home(dir.path().to_path_buf());
                let old = [b"old CA".to_vec(), b"old certificate".to_vec()];
                if baseline {
                    for (name, bytes) in VPN_FILES.iter().zip(&old) {
                        home.write(name, bytes).unwrap();
                    }
                } else {
                    home.install_vpn_pair(&old[0], &old[1]).unwrap();
                }
                let held = if native {
                    Some(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .share_mode(1 | 2)
                            .open(home.file(VPN_FILES[1]))
                            .unwrap(),
                    )
                } else {
                    VPN_RENAME_ERROR.with(|target| target.replace(Some(home.file(VPN_FILES[1]))));
                    None
                };
                let error = home
                    .install_vpn_pair(b"new CA", b"new certificate")
                    .unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains("vpn-cert.pem"), "{message}");
                assert!(
                    message.contains("close the program that holds it and run check again"),
                    "{message}"
                );
                assert!(
                    error
                        .chain()
                        .any(
                            |cause| cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                                match error.raw_os_error() {
                                    Some(32) => true,
                                    Some(5) => native,
                                    _ => false,
                                }
                            })
                        ),
                    "{message}"
                );
                let new = [b"new CA".to_vec(), b"new certificate".to_vec()];
                assert_eq!(selected_windows_vpn_pair(&home), Some(new.clone()));
                assert_eq!(std::fs::read(home.file(VPN_FILES[0])).unwrap(), new[0]);
                assert_eq!(std::fs::read(home.file(VPN_FILES[1])).unwrap(), old[1]);
                assert!(home.file(VPN_DIR).join(VPN_FLAT_STALE).exists());
                drop(held);
                home.recover_vpn().unwrap();
                assert_eq!(
                    VPN_FILES.map(|name| std::fs::read(home.file(name)).unwrap()),
                    new
                );
                assert!(!home.file(VPN_DIR).join(VPN_FLAT_STALE).exists());
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_lock_serializes_install_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        home.install_vpn_pair(b"CA one", b"certificate one")
            .unwrap();
        let guard = home.lock_vpn().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for recover in [false, true] {
                let home = &home;
                let started = started_tx.clone();
                let done = done_tx.clone();
                scope.spawn(move || {
                    started.send(()).unwrap();
                    if recover {
                        home.recover_vpn().unwrap();
                    } else {
                        home.install_vpn_pair(b"CA two", b"certificate two")
                            .unwrap();
                    }
                    done.send(()).unwrap();
                });
            }
            started_rx.recv().unwrap();
            started_rx.recv().unwrap();
            assert!(
                done_rx
                    .recv_timeout(std::time::Duration::from_millis(100))
                    .is_err()
            );
            assert_eq!(selected_windows_vpn_pair(&home).unwrap()[0], b"CA one");
            drop(guard);
            done_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            done_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        });
        assert_eq!(selected_windows_vpn_pair(&home).unwrap()[0], b"CA two");
        home.recover_vpn().unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_vpn_startup_recovers_for_log_and_warns_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        home.install_vpn_pair(b"CA one", b"certificate one")
            .unwrap();
        home.write(LOG_CHECKPOINT, b"fictional checkpoint").unwrap();
        home.write(VPN_FILES[0], b"interrupted flat copy").unwrap();
        let home_path = dir.path().to_path_buf();
        let cli = move || {
            Cli::parse_from([
                "open-pact-client",
                "--home",
                home_path.to_str().unwrap(),
                "log",
                "head",
            ])
        };
        let lock = home.lock_vpn().unwrap();
        assert!(!home.recover_vpn_at_startup().unwrap());
        let handle = tokio::runtime::Handle::current();
        let cli_for_task = cli.clone();
        let run_while_locked =
            tokio::task::spawn_blocking(move || handle.block_on(run(cli_for_task())));
        let timely =
            tokio::time::timeout(std::time::Duration::from_secs(1), run_while_locked).await;
        drop(lock);
        assert!(timely.is_ok(), "log command must not wait for the VPN lock");
        assert_eq!(timely.unwrap().unwrap().unwrap(), ExitCode::SUCCESS);
        assert_eq!(
            std::fs::read(home.file(VPN_FILES[0])).unwrap(),
            b"interrupted flat copy"
        );
        assert_eq!(run(cli()).await.unwrap(), ExitCode::SUCCESS);
        assert_eq!(std::fs::read(home.file(VPN_FILES[0])).unwrap(), b"CA one");
        std::fs::write(home.file(VPN_DIR).join(VPN_CURRENT), b"../invalid").unwrap();
        assert_eq!(run(cli()).await.unwrap(), ExitCode::SUCCESS);
    }

    #[cfg(windows)]
    #[test]
    fn windows_vpn_recovery_rejects_an_invalid_or_incomplete_selection_before_copying() {
        for pointer in ["../outside", "", "123-456"] {
            let dir = tempfile::tempdir().unwrap();
            let home = Home(dir.path().to_path_buf());
            let vpn = home.file(VPN_DIR);
            std::fs::create_dir_all(vpn.join("123-456")).unwrap();
            std::fs::write(vpn.join("123-456/ca.pem"), b"fictional new CA").unwrap();
            std::fs::write(vpn.join(VPN_CURRENT), pointer).unwrap();
            home.write(VPN_FILES[0], b"fictional old CA").unwrap();
            home.write(VPN_FILES[1], b"fictional old certificate")
                .unwrap();
            assert!(home.recover_vpn().is_err());
            assert_eq!(
                std::fs::read(home.file(VPN_FILES[0])).unwrap(),
                b"fictional old CA"
            );
            assert_eq!(
                std::fs::read(home.file(VPN_FILES[1])).unwrap(),
                b"fictional old certificate"
            );
        }
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
