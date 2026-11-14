use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use open_pact_core::{
    Checkpoint, Claim, ControlValue, CsrHash, DeviceStatus, LogCheckpoint, Manifest, ManifestHash,
    Os, Pseudonym, Virtualized,
};
use rcgen::KeyPair;
use serde_json::{Value, json};

use crate::checks::repos::RepoScan;
use crate::device_config::{self, DeviceConfig};
use crate::{
    CheckpointVerifyError, ClaimResult, DeviceKey, Enrolment, Home, LogSync, Nonce, OwnEntries,
    Pins, Response, base,
};

const LOCK: &str = "claim.lock";
const WAIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(200);

/// Held while one command reads and writes the enrolment, the stored manifest, the log checkpoint,
/// the claim log or the VPN pair. `check`, `accept` and the scheduled job take it, so none of them
/// can write back a file that another one changed in the meantime.
pub(crate) struct ClaimLock(Option<File>);

impl Drop for ClaimLock {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            let _ = file.unlock();
        }
    }
}

fn open(home: &Home) -> Result<Option<File>> {
    // Without a home there is nothing to protect. The command reports the missing home itself.
    if !home.0.is_dir() {
        return Ok(None);
    }
    let path = home.file(LOCK);
    Ok(Some(
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| path.display().to_string())?,
    ))
}

/// Takes the lock for a command the owner started. Waits while another command holds it, and says
/// so once: the holder is usually the scheduled job.
pub(crate) async fn lock(home: &Home) -> Result<ClaimLock> {
    lock_for(home, WAIT, || {
        eprintln!(
            "Waiting for the scheduled job, which holds {}. It releases the lock when its claim is done.",
            home.file(LOCK).display()
        );
    })
    .await
}

async fn lock_for(home: &Home, wait: Duration, on_wait: impl FnOnce()) -> Result<ClaimLock> {
    let Some(file) = open(home)? else {
        return Ok(ClaimLock(None));
    };
    let deadline = tokio::time::Instant::now() + wait;
    let mut on_wait = Some(on_wait);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(ClaimLock(Some(file))),
            Err(std::fs::TryLockError::WouldBlock) => {
                if let Some(announce) = on_wait.take() {
                    announce();
                }
                if tokio::time::Instant::now() >= deadline {
                    bail!(
                        "another open-pact command has held {} for {} seconds; wait for it to finish and run this command again",
                        home.file(LOCK).display(),
                        wait.as_secs()
                    );
                }
                tokio::time::sleep(POLL).await;
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("lock the claim lock");
            }
        }
    }
}

/// Takes the lock for the scheduled job, which skips its tick instead of waiting.
pub(crate) fn try_lock(home: &Home) -> Result<Option<ClaimLock>> {
    let Some(file) = open(home)? else {
        return Ok(Some(ClaimLock(None)));
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(ClaimLock(Some(file)))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error).context("lock the claim lock"),
    }
}

/// When `prepare` scans the repositories below the user's home.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ScanPolicy {
    /// Scan now and store the result.
    Always,
    /// Scan and store only when the last attempt is this old; otherwise use the stored result.
    OlderThan(Duration),
    /// Scan now and store nothing, so the home stays as it is.
    Preview,
}

/// The home holds a transparency log head in the format that came before checkpoints.
#[derive(Debug)]
pub(crate) struct LegacyLogHead;

impl std::fmt::Display for LegacyLogHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the transparency log head is in the old hash-chain format; run `open-pact-client join` again to pin the new log",
        )
    }
}

impl std::error::Error for LegacyLogHead {}

/// What this device would claim, collected locally. Nothing has left the device yet.
pub(crate) struct Prepared {
    enrolment: Enrolment,
    manifest: Manifest,
    manifest_toml: String,
    device_config: Option<DeviceConfig>,
    device: DeviceKey,
    scan: Option<RepoScan>,
    os: Os,
    results: BTreeMap<String, ControlValue>,
    virtualized: Option<Virtualized>,
    compliance: BTreeMap<String, bool>,
}

/// Runs the manifest's checks. `user_home` is the profile whose repositories and `~` paths count;
/// `None` is the profile of this process.
pub(crate) async fn prepare(
    home: &Home,
    user_home: Option<&Path>,
    policy: ScanPolicy,
    insecure_dev: bool,
) -> Result<Prepared> {
    let mut can_scan_repositories = true;
    let preview = matches!(policy, ScanPolicy::Preview);
    let device_config = match DeviceConfig::load_or_migrate(home, user_home, !preview) {
        Ok(config) => Some(config),
        Err(error) => {
            can_scan_repositories = false;
            eprintln!(
                "{error:#}\nThis file holds your choices and is not meant for hand editing. Delete it and answer again with `schedule on` and `folders add`. Other controls will still run."
            );
            None
        }
    };
    let enrolment = home.enrolment()?;
    crate::check_scheme(&enrolment.gateway, insecure_dev)?;
    if home.has_legacy_log_head() {
        return Err(LegacyLogHead.into());
    }
    let manifest_toml = String::from_utf8(std::fs::read(home.file("manifest.toml"))?)
        .context("manifest.toml is not UTF-8")?;
    let manifest = Manifest::parse(manifest_toml.as_bytes())?;
    if manifest.hash() != &enrolment.manifest {
        return Err(crate::stored_manifest_mismatch(
            home,
            manifest.hash(),
            &enrolment.manifest,
        ));
    }
    crate::checks::check_supported(&manifest)
        .map_err(|e| anyhow::anyhow!("{e}; nothing was run or sent"))?;
    let scan = if !can_scan_repositories {
        None
    } else {
        match policy {
            ScanPolicy::Always => {
                crate::scan_repositories_from(
                    home,
                    user_home,
                    &manifest,
                    device_config.as_ref(),
                    true,
                )
                .await?
            }
            ScanPolicy::Preview => {
                crate::scan_repositories_from(
                    home,
                    user_home,
                    &manifest,
                    device_config.as_ref(),
                    false,
                )
                .await?
            }
            ScanPolicy::OlderThan(age) => {
                let now = chrono::Utc::now().timestamp();
                let age = i64::try_from(age.as_secs()).unwrap_or(i64::MAX);
                let due = crate::checks::repos::load_attempt(&home.0)?
                    .is_none_or(|last| now.saturating_sub(last.scanned_at) >= age);
                if due {
                    if crate::scans_repositories(&manifest) {
                        crate::checks::repos::lower_process_priority();
                    }
                    crate::scan_repositories_from(
                        home,
                        user_home,
                        &manifest,
                        device_config.as_ref(),
                        true,
                    )
                    .await?
                } else {
                    crate::stored_repo_scan(home)?
                }
            }
        }
    };
    let device = DeviceKey::load(&home.0)?;
    if enrolment.device != Pseudonym::of(&device.public_key()) {
        bail!("device key does not match enrolment");
    }
    let os = crate::current_os()?;
    let (results, virtualized) = {
        let manifest = manifest.clone();
        let config = device_config.clone();
        let scan = scan.clone();
        tokio::task::spawn_blocking(move || {
            let results = crate::collect_results(&manifest, os, config.as_ref(), scan.as_ref());
            let virtualized = crate::disclosable_virtualized(&manifest, crate::virtualized);
            (results, virtualized)
        })
        .await
        .context("control collection task stopped")?
    };
    let compliance = open_pact_core::control_compliance(&manifest, os, &results);
    Ok(Prepared {
        enrolment,
        manifest,
        manifest_toml,
        device_config,
        device,
        scan,
        os,
        results,
        virtualized,
        compliance,
    })
}

/// The daily repository scan, for the scheduled job. The job runs it before it takes the claim lock,
/// so a long scan never makes `check` or `accept` wait. `prepare` then reads the stored result.
/// A home that does not read cleanly is left to `prepare`, which says what is wrong.
pub(crate) async fn scan_if_due(
    home: &Home,
    user_home: Option<&Path>,
    age: Duration,
) -> Result<()> {
    let Ok(text) = std::fs::read(home.file("manifest.toml")) else {
        return Ok(());
    };
    let Ok(manifest) = Manifest::parse(&text) else {
        return Ok(());
    };
    let Ok(config) = DeviceConfig::load_or_migrate(home, user_home, false) else {
        return Ok(());
    };
    if !crate::scans_repositories(&manifest) {
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp();
    let age = i64::try_from(age.as_secs()).unwrap_or(i64::MAX);
    let due = crate::checks::repos::load_attempt(&home.0)?
        .is_none_or(|last| now.saturating_sub(last.scanned_at) >= age);
    if due {
        crate::checks::repos::lower_process_priority();
        crate::scan_repositories_from(home, user_home, &manifest, Some(&config), true).await?;
    }
    Ok(())
}

/// How a claim went, after the pipeline printed what happened.
pub(crate) enum Outcome {
    Accepted {
        changed: Option<ManifestHash>,
    },
    Denied {
        reasons: Vec<String>,
        changed: Option<ManifestHash>,
    },
    NotSent(NotSent),
    /// A log alarm, or an accepted response that failed log verification.
    Alarm(String),
}

pub(crate) enum NotSent {
    Pending,
    Revoked,
    /// The gateway enforces a manifest this device has not signed.
    AcceptPending(ManifestHash),
    /// The caller's last check before the claim said the device is off the VPN.
    OffVpn,
}

impl NotSent {
    /// Why `check` sends nothing, for the end of a dry run.
    fn reason(&self) -> &'static str {
        match self {
            NotSent::Pending => "this device waits for IT approval",
            NotSent::Revoked => "IT revoked this device",
            NotSent::AcceptPending(_) => {
                "the gateway enforces a manifest this device has not signed yet"
            }
            NotSent::OffVpn => "the VPN probe failed",
        }
    }
}

impl Outcome {
    /// One sentence on why `check` sends nothing. `None` when it sends.
    pub(crate) fn why_nothing_is_sent(&self) -> Option<String> {
        match self {
            Outcome::NotSent(reason) => Some(reason.reason().to_owned()),
            Outcome::Alarm(_) => Some("the transparency log did not verify".to_owned()),
            Outcome::Accepted { .. } | Outcome::Denied { .. } => None,
        }
    }

    /// The gateway received the claim and answered, whatever its verdict.
    pub(crate) fn delivered(&self) -> bool {
        matches!(self, Outcome::Accepted { .. } | Outcome::Denied { .. })
    }

    pub(crate) fn exit_code(&self) -> ExitCode {
        match self {
            Outcome::Accepted { .. } => ExitCode::SUCCESS,
            Outcome::Denied { .. } | Outcome::NotSent(_) => ExitCode::FAILURE,
            Outcome::Alarm(_) => ExitCode::from(2),
        }
    }
}

/// What `check --dry-run` found.
pub(crate) enum Preview {
    /// The request `send` would post, with a placeholder for each field only the gateway or the
    /// clock can fill.
    Request(Value),
    /// `check` would send nothing. The pipeline already printed why.
    NotSent(Outcome),
}

const NONCE_PLACEHOLDER: &str = "<nonce from POST /v1/nonce>";
const TIME_PLACEHOLDER: &str = "<time of sending>";
const CSR_PLACEHOLDER: &str = "<certificate request for the VPN key>";

impl Prepared {
    pub(crate) fn compliance(&self) -> &BTreeMap<String, bool> {
        &self.compliance
    }

    /// The table of results, and what the repository scan could not read.
    pub(crate) fn print_local_report(&self) {
        device_config::print_table(
            &self.manifest,
            self.os,
            self.device_config.as_ref(),
            &self.results,
        );
        let Some(scan) = &self.scan else {
            return;
        };
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

    fn claim(
        &self,
        nonce: String,
        time: chrono::DateTime<chrono::Utc>,
        csr_sha256: CsrHash,
        log_checkpoint: Option<LogCheckpoint>,
    ) -> Claim {
        let device_key = self.device.public_key();
        Claim {
            manifest: self.manifest.hash().clone(),
            device: Pseudonym::of(&device_key),
            device_key,
            nonce,
            time,
            client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
            os: self.os,
            trust_level: self.device.trust_level(),
            virtualized: self.virtualized,
            results: self.results.clone(),
            csr_sha256: Some(csr_sha256),
            log_checkpoint,
        }
    }

    /// Shows the request `send` would post, after GET checks and locally known admission state.
    /// Own-entry admission needs a signed request, so the dry run reports that result as unknown.
    pub(crate) async fn dry_run(self, home: &Home) -> Result<Preview> {
        let http = crate::http_client()?;
        let enrolment = self.enrolment.clone();
        let enforced = crate::enforced_manifest(&http, &enrolment.gateway).await?;
        let changed = (enforced != enrolment.manifest).then(|| enforced.clone());
        let verified = match crate::sync_checkpoint_with(
            &http,
            home,
            &enrolment.gateway,
            self.manifest.body().log.as_ref(),
            false,
        )
        .await?
        {
            Ok(checkpoint) => checkpoint,
            Err(text) => {
                crate::report_log(LogSync::Alarm(text.clone()), home);
                return Ok(Preview::NotSent(Outcome::Alarm(text)));
            }
        };
        if let Some(changed) = changed {
            let command = crate::client_command(&home.0);
            println!("{}", crate::manifest_change_notice(&changed, &command));
            crate::print_claim_log_status(home, None, Some("the manifest changed"));
            return Ok(Preview::NotSent(Outcome::NotSent(NotSent::AcceptPending(
                changed,
            ))));
        }
        match enrolment.last_status {
            Some(DeviceStatus::Pending) => {
                let command = crate::client_command(&home.0);
                println!("This device waits for IT approval.");
                println!("Wizard step [4/6] is unfinished. Continue with: {command} join");
                crate::print_claim_log_status(
                    home,
                    None,
                    Some("the device is waiting for IT approval"),
                );
                return Ok(Preview::NotSent(Outcome::NotSent(NotSent::Pending)));
            }
            Some(DeviceStatus::Revoked) => {
                println!("IT revoked this device.");
                crate::print_claim_log_status(home, None, Some("IT revoked this device"));
                return Ok(Preview::NotSent(Outcome::NotSent(NotSent::Revoked)));
            }
            Some(DeviceStatus::Approved) | None => {}
        }
        println!(
            "check also asks the gateway whether this device may send; the dry run skips that signed request."
        );
        let log_checkpoint = crate::disclosable_checkpoint(&self.manifest, Some(verified));
        let claim = self.claim(
            String::new(),
            chrono::DateTime::UNIX_EPOCH,
            CsrHash::of(b""),
            log_checkpoint,
        );
        let mut shown = serde_json::to_value(&claim)?;
        shown["nonce"] = NONCE_PLACEHOLDER.into();
        shown["time"] = TIME_PLACEHOLDER.into();
        shown["csr_sha256"] = CSR_PLACEHOLDER.into();
        let mut request = json!({ "claim": shown, "csr_pem": CSR_PLACEHOLDER });
        if changed.is_some() {
            request["manifest_toml"] = self.manifest_toml.clone().into();
        }
        Ok(Preview::Request(request))
    }

    /// Verifies the log, signs the claim, posts it and installs the VPN pair the gateway answers
    /// with. `probe` runs before the first gateway request and again once the claim is ready,
    /// before the first POST; when it returns false, nothing more is sent.
    pub(crate) async fn send(self, home: &Home, probe: impl AsyncFn() -> bool) -> Result<Outcome> {
        if !probe().await {
            println!("The VPN probe failed before the gateway was contacted. Nothing was sent.");
            return Ok(Outcome::NotSent(NotSent::OffVpn));
        }
        let mut enrolment = self.enrolment.clone();
        let manifest = &self.manifest;
        let os = self.os;
        home.recover_vpn()?;
        let command = crate::client_command(&home.0);
        let http = crate::http_client()?;
        let enforced = crate::enforced_manifest(&http, &enrolment.gateway).await?;
        let changed = (enforced != enrolment.manifest).then(|| enforced.clone());
        let notice = || crate::manifest_change_notice(&enforced, &command);
        let (mut verified, own) = match admit(
            &http,
            home,
            manifest,
            &enforced,
            &mut enrolment,
            changed.as_ref(),
            true,
        )
        .await?
        {
            Ok(admitted) => admitted,
            Err(outcome) => return Ok(outcome),
        };
        let gateway = base(&enrolment.gateway);
        let log_checkpoint = crate::disclosable_checkpoint(manifest, home.checkpoint()?);
        if !probe().await {
            println!("The VPN probe failed before the claim was sent. Nothing was sent.");
            return Ok(Outcome::NotSent(NotSent::OffVpn));
        }
        let nonce: Nonce = http
            .post(format!("{gateway}/v1/nonce"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let (csr_pem, csr_der) = crate::vpn_csr(home)?;
        let claim = self.claim(
            nonce.nonce,
            chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).context("clock")?,
            CsrHash::of(&csr_der),
            log_checkpoint,
        );
        let mut request = json!({ "jws": self.device.sign_claim(&claim)?, "csr_pem": csr_pem });
        if changed.is_some() {
            request["manifest_toml"] = self.manifest_toml.clone().into();
        }
        let sent = serde_json::to_vec(&request)?;
        let resp = http
            .post(format!("{gateway}/v1/claim"))
            .header("content-type", "application/json")
            .body(sent.clone())
            .send()
            .await?;
        let status = resp.status();
        let received = resp.bytes().await?;
        crate::locallog::append_with_status(
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
        let sent_at = claim
            .time
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let (result, reasons) = match serde_json::from_slice::<Response>(&received)
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
                        crate::verify_checkpoint(
                            &http,
                            home,
                            gateway,
                            &key,
                            policy,
                            Some(&verified),
                            &text,
                        )
                        .await
                    }
                };
                match checked? {
                    Ok(cp) => verified = cp,
                    Err(e) => {
                        println!("ACCEPTED, but the response failed log verification");
                        let text = format!(
                            "the checkpoint in the accepted claim response: {}; no certificate was installed",
                            e.alarm_text()
                        );
                        crate::report_log(crate::alarm(text.clone()), home);
                        crate::print_claim_log_status(
                            home,
                            Some((
                                sent_at,
                                ClaimResult::ResponseUnverified,
                                claim.results.len(),
                            )),
                            None,
                        );
                        return Ok(Outcome::Alarm(text));
                    }
                }
                println!("{}", crate::ui::bold("ACCEPTED", crate::ui::styled()));
                for w in &warnings {
                    println!("  warning: {w}");
                }
                crate::print_hints(manifest, &claim.results, os);
                let vpn_key =
                    KeyPair::from_pem(&std::fs::read_to_string(home.file("vpn-key.pem"))?)?;
                let certificate_pem = certificate_pem.context(
                    "the accepted response carries no VPN certificate for the request this check sent; the installed ones are kept",
                )?;
                let described = crate::check_vpn_pair(&ca_pem, &certificate_pem, &vpn_key)
                    .context("the accepted response carries an unusable VPN certificate or CA; the installed ones are kept")?;
                home.install_vpn_pair(ca_pem.as_bytes(), certificate_pem.as_bytes())?;
                println!(
                    "VPN certificate {} ({described})",
                    home.file("vpn-cert.pem").display(),
                );
                println!("VPN CA          {}", home.file("ca.pem").display());
                (ClaimResult::Accepted, Vec::new())
            }
            Response::Denied { reasons } => {
                println!("{}", crate::ui::bold("DENIED", crate::ui::styled()));
                for r in &reasons {
                    println!("  {r}");
                }
                crate::print_hints(manifest, &claim.results, os);
                (ClaimResult::Denied, reasons)
            }
        };
        crate::report_log(LogSync::Verified(verified, own), home);
        let accepted = matches!(result, ClaimResult::Accepted);
        crate::print_claim_log_status(home, Some((sent_at, result, claim.results.len())), None);
        if changed.is_some() {
            println!("\n{}", notice());
        }
        if !accepted {
            println!("\nNext: fix the items above, then run {command} check again.");
        }
        Ok(if accepted {
            Outcome::Accepted { changed }
        } else {
            Outcome::Denied { reasons, changed }
        })
    }
}

/// Verifies the log and this device's own entries, then finds out whether the gateway lets the
/// device send. `Err` is the outcome of a `check` that sends nothing; what happened is printed.
/// With `store` false no file is written.
async fn admit(
    http: &reqwest::Client,
    home: &Home,
    manifest: &Manifest,
    enforced: &ManifestHash,
    enrolment: &mut Enrolment,
    changed: Option<&ManifestHash>,
    store: bool,
) -> Result<std::result::Result<(Checkpoint, OwnEntries), Outcome>> {
    let command = crate::client_command(&home.0);
    let notice = || crate::manifest_change_notice(enforced, &command);
    let sync = match crate::sync_log_with(http, home, manifest, enforced, enrolment, store).await {
        Err(error)
            if error.downcast_ref::<reqwest::Error>().is_some_and(|error| {
                error.status() == Some(reqwest::StatusCode::FORBIDDEN)
                    && error
                        .url()
                        .is_some_and(|url| url.path().ends_with("/v1/log/mine"))
            }) =>
        {
            let state = match (
                crate::status_after_log_denial(http, home, enrolment).await,
                changed,
            ) {
                (Ok(state), _) => state,
                (Err(_), Some(_)) => {
                    println!("{}", notice());
                    crate::print_claim_log_status(home, None, Some("the manifest changed"));
                    return Ok(Err(Outcome::NotSent(NotSent::AcceptPending(
                        enforced.clone(),
                    ))));
                }
                (Err(error), None) => return Err(error),
            };
            if store && enrolment.last_status != Some(state) {
                enrolment.last_status = Some(state);
                home.write("enrolment.json", &serde_json::to_vec_pretty(enrolment)?)?;
            }
            return match state {
                DeviceStatus::Pending => {
                    println!("This device waits for IT approval.");
                    println!(
                        "Wizard step [4/6] is unfinished. Continue with: {} join",
                        command
                    );
                    crate::print_claim_log_status(
                        home,
                        None,
                        Some("the device is waiting for IT approval"),
                    );
                    if changed.is_some() {
                        println!("\n{}", notice());
                    }
                    Ok(Err(Outcome::NotSent(NotSent::Pending)))
                }
                DeviceStatus::Revoked => {
                    println!("IT revoked this device.");
                    crate::print_claim_log_status(home, None, Some("IT revoked this device"));
                    Ok(Err(Outcome::NotSent(NotSent::Revoked)))
                }
                DeviceStatus::Approved => {
                    crate::print_claim_log_status(
                        home,
                        None,
                        Some("the gateway denied log access after approval"),
                    );
                    Err(error)
                }
            };
        }
        result => result?,
    };
    if store
        && matches!(&sync, LogSync::Verified(..))
        && enrolment.last_status != Some(DeviceStatus::Approved)
    {
        enrolment.last_status = Some(DeviceStatus::Approved);
        home.write("enrolment.json", &serde_json::to_vec_pretty(enrolment)?)?;
    }
    Ok(match sync {
        LogSync::Verified(cp, own) => Ok((cp, own)),
        LogSync::AcceptPending(pending) => {
            crate::report_log(LogSync::AcceptPending(pending.clone()), home);
            crate::print_claim_log_status(home, None, Some("the manifest changed"));
            Err(Outcome::NotSent(NotSent::AcceptPending(pending)))
        }
        LogSync::Alarm(text) => {
            crate::report_log(LogSync::Alarm(text.clone()), home);
            crate::print_claim_log_status(home, None, Some("log verification did not complete"));
            Err(Outcome::Alarm(text))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_holder_cannot_take_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let first = lock(&home).await.unwrap();
        assert!(try_lock(&home).unwrap().is_none());
        drop(first);
        assert!(try_lock(&home).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_waiting_command_gives_up_with_the_lock_path() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let _held = try_lock(&home).unwrap().unwrap();
        let mut waits = 0;
        let error = lock_for(&home, Duration::from_millis(300), || waits += 1)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("claim.lock"), "{error}");
        assert_eq!(waits, 1, "the wait is announced once, not on every poll");
    }

    #[tokio::test]
    async fn a_free_lock_announces_no_wait() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let mut waits = 0;
        let _lock = lock_for(&home, Duration::from_millis(300), || waits += 1)
            .await
            .unwrap();
        assert_eq!(waits, 0);
    }

    #[tokio::test]
    async fn a_missing_home_has_nothing_to_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().join("absent"));
        assert!(lock(&home).await.is_ok());
        assert!(try_lock(&home).unwrap().is_some());
        assert!(!home.0.exists());
    }
}
