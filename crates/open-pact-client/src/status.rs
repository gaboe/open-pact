use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use open_pact_core::{DeviceStatus, Manifest, ManifestHash, verify_claim};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::device_config::{DeviceConfig, RunAs};
use crate::machine::MachineState;
use crate::schedule::{JobInspection, JobStatus};
use crate::{Enrolment, Home, Pins, PublishedManifest, Response, locallog};

/// The options of `status`, without the parser.
#[derive(Clone, Debug)]
pub struct Options {
    /// Refresh approval, manifest, log, VPN probe, and OS job state. Sends no claim
    pub online: bool,
    /// Print the same evidence and issues as JSON
    pub json: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    NoKnownProblem,
    ActionNeeded,
    Alarm,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    Alarm,
    Action,
    Warning,
}

#[derive(Debug, Serialize)]
pub struct Issue {
    pub urgency: Urgency,
    pub message: String,
    pub fix: Option<String>,
    pub command: Option<String>,
    pub stop_job_command: Option<String>,
    pub deadline: String,
}

#[derive(Debug, Serialize)]
pub struct ApprovalEvidence {
    pub state: Option<DeviceStatus>,
    pub live: bool,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct ClaimEvidence {
    pub sent_at: Option<String>,
    pub response_at: String,
    pub response: String,
    pub warnings: Vec<String>,
    pub reasons: Vec<String>,
    pub manifest: Option<ManifestHash>,
    pub os: Option<open_pact_core::Os>,
    pub results: std::collections::BTreeMap<String, open_pact_core::ControlValue>,
}

#[derive(Debug, Serialize)]
pub struct ManifestEvidence {
    pub signed: ManifestHash,
    pub enforced: Option<ManifestHash>,
    pub agreement: String,
}

#[derive(Debug, Serialize)]
pub struct ScheduleEvidence {
    pub owner_consented: Option<bool>,
    pub policy: String,
    pub policy_defined: bool,
    pub job: String,
    pub job_status: Option<JobStatus>,
    /// The owner chose a SYSTEM job. Only an elevated prompt can install or update it.
    pub system_job: bool,
    /// The owner chose a SYSTEM job in the wizard and it is not installed yet.
    pub system_job_pending: bool,
    /// The SYSTEM task that a pending choice waits for. `job_status` stays the job that runs now.
    pub pending_job_status: Option<JobStatus>,
    /// The machine client of a SYSTEM job, which is a fact of its own beside the task.
    pub machine_client: Option<MachineState>,
    /// The exact text that fixes the machine client, for the desktop to show.
    pub machine_fix: Option<String>,
    /// The exact text that fixes the task, for the desktop to show.
    pub job_fix: Option<String>,
    pub vpn: String,
    pub last_scheduled_claim: Option<ScheduledClaim>,
    pub last_job_note: Option<String>,
    pub last_job_log_line: Option<String>,
    /// Why `last_job_log_line` is empty although a SYSTEM job writes a log: only an elevated
    /// prompt reads it.
    pub last_job_log_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScheduledClaim {
    pub answered_at: String,
    pub response: Option<String>,
}

#[derive(Default, Deserialize)]
struct TickEvidence {
    vpn_up: bool,
    last_success: Option<i64>,
    last_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub observed_at: String,
    pub mode: &'static str,
    pub verdict: Verdict,
    pub exit_code: u8,
    pub online_command: Option<String>,
    pub current_compliance: &'static str,
    pub approval: ApprovalEvidence,
    pub last_claim: Option<ClaimEvidence>,
    pub manifest: Option<ManifestEvidence>,
    pub schedule: ScheduleEvidence,
    pub log: String,
    pub issues: Vec<Issue>,
    pub limitations: Vec<String>,
    pub update: Option<crate::update::Notice>,
}

/// The status report. With `online` it also asks whether a newer release exists.
pub(crate) async fn report(
    home: &Home,
    online: bool,
    insecure_dev: bool,
    executable: &Path,
) -> Result<Report> {
    let mut report = collect(home, online, insecure_dev, executable).await?;
    if online && home.file("enrolment.json").exists() {
        // The check waits on the network on a thread of its own, so it must not hold a worker.
        report.update = tokio::task::spawn_blocking(crate::update::latest_notice)
            .await
            .ok()
            .flatten();
    }
    Ok(report)
}

pub(crate) async fn run(
    home: &Home,
    options: Options,
    insecure_dev: bool,
    executable: &Path,
) -> Result<ExitCode> {
    let report = report(home, options.online, insecure_dev, executable).await?;
    let text = if options.json {
        serde_json::to_string_pretty(&report)? + "\n"
    } else {
        report.render()
    };
    print!("{text}");
    Ok(ExitCode::from(report.exit_code))
}

/// The SYSTEM job log and, when it cannot be read, the one line that says where it is.
fn read_system_job_log(path: Result<std::path::PathBuf>) -> (Option<String>, Option<String>) {
    let note = |place: String| {
        format!("The SYSTEM job log is {place}. Reading it needs an elevated prompt.")
    };
    match path {
        Ok(path) => match std::fs::read_to_string(&path) {
            Ok(text) => (Some(text), None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(_) => (None, Some(note(path.display().to_string()))),
        },
        Err(_) => (
            None,
            Some(note(
                r"schedule.log in the SYSTEM state folder below C:\ProgramData\open-pact\system"
                    .into(),
            )),
        ),
    }
}

async fn collect(
    home: &Home,
    online: bool,
    insecure_dev: bool,
    executable: &Path,
) -> Result<Report> {
    collect_with_pending(
        home,
        online,
        insecure_dev,
        executable,
        OffsetDateTime::now_utc(),
        |home, config| crate::schedule::inspect_job(home, config, executable),
        crate::schedule::inspect_system_job,
    )
    .await
}

#[cfg(test)]
async fn collect_with(
    home: &Home,
    online: bool,
    insecure_dev: bool,
    executable: &Path,
    now: OffsetDateTime,
    inspect_job: impl FnOnce(&Home, &DeviceConfig) -> Result<JobInspection>,
) -> Result<Report> {
    collect_with_pending(
        home,
        online,
        insecure_dev,
        executable,
        now,
        inspect_job,
        crate::schedule::inspect_system_job,
    )
    .await
}

/// `inspect_pending` looks at the SYSTEM job that a pending choice waits for. The job that runs
/// now comes from `inspect_job`.
async fn collect_with_pending(
    home: &Home,
    online: bool,
    insecure_dev: bool,
    executable: &Path,
    now: OffsetDateTime,
    inspect_job: impl FnOnce(&Home, &DeviceConfig) -> Result<JobInspection>,
    inspect_pending: impl FnOnce(&Home) -> Result<JobInspection>,
) -> Result<Report> {
    let mut damaged = Vec::new();
    let config = DeviceConfig::load(home).unwrap_or_else(|error| {
        damaged.push(("device.json", error));
        DeviceConfig::default()
    });
    let tick: TickEvidence = home
        .read_json("report-state.json")
        .unwrap_or_else(|error| {
            damaged.push(("report-state.json", error));
            None
        })
        .unwrap_or_default();
    // A SYSTEM job writes its log to a folder that only administrators read. The log in the home is
    // not its log: a user can write there.
    let (job_log, job_log_note) = if config.run_as == RunAs::System {
        read_system_job_log(crate::schedule::system_job_log_path(home))
    } else {
        let log = home.read_text("schedule.log").unwrap_or_else(|error| {
            damaged.push(("schedule.log", error));
            None
        });
        (log, None)
    };
    let config_damaged = damaged.iter().any(|(file, _)| *file == "device.json");
    let tick_damaged = damaged.iter().any(|(file, _)| *file == "report-state.json");
    let mut report = Report {
        schema_version: 1,
        observed_at: timestamp(now),
        mode: if online { "online" } else { "local" },
        verdict: Verdict::Unknown,
        exit_code: 3,
        online_command: None,
        current_compliance: "unknown; status does not run checks or send a claim",
        approval: ApprovalEvidence { state: None, live: false, source: "not enrolled".into() },
        last_claim: None,
        manifest: None,
        schedule: ScheduleEvidence {
            owner_consented: (!config_damaged).then_some(config.auto_send),
            policy: "unknown without a signed manifest".into(),
            policy_defined: false,
            job: if home.file(crate::schedule::APPLIED).exists() {
                "installation recorded; OS job not checked".into()
            } else {
                "no installation record; OS job not checked".into()
            },
            job_status: None,
            system_job: !config_damaged
                && config.auto_send
                && config.run_as == crate::device_config::RunAs::System,
            system_job_pending: !config_damaged && config.system_job_pending,
            pending_job_status: None,
            machine_client: None,
            machine_fix: None,
            job_fix: None,
            vpn: "not probed".into(),
            last_scheduled_claim: tick
                .last_success
                .and_then(|time| OffsetDateTime::from_unix_timestamp(time).ok())
                .map(|time| ScheduledClaim { answered_at: timestamp(time), response: None }),
            last_job_note: tick.last_note.clone(),
            last_job_log_note: job_log_note,
            last_job_log_line: job_log.and_then(|text| text.lines().rev().find(|line| !line.trim().is_empty()).map(|line| line.chars().take(512).collect())),
        },
        log: "not verified by status; manual alarms are not saved".into(),
        issues: Vec::new(),
        limitations: vec![
            "An accepted saved response does not prove a verified certificate install.".into(),
            "Exact grace deadlines are unavailable; the gateway returns text, not first-failure times.".into(),
        ],
        update: None,
    };
    let command = crate::client_command(&home.0);
    for (file, error) in damaged {
        report.damaged(file, &error, &command);
    }
    if config_damaged {
        report
            .limitations
            .push("Automatic sending consent is unknown because device.json is damaged.".into());
        report.schedule.job = "unknown; device.json is damaged".into();
    }
    if let Some(note) = tick
        .last_note
        .as_deref()
        .and_then(|note| note.strip_prefix("alarm "))
    {
        report.issue(
            Urgency::Alarm,
            format!("Saved scheduled log alarm: {note}"),
            "Keep the last checkpoint and tell IT.",
            &command,
            "log head",
            "Review now.",
        );
    }
    let (enrolment, manifest) =
        match read_generation(|file| match crate::home_fs::read(&home.file(file)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }) {
            Ok(Generation::Enrolled(generation)) => {
                let EnrolledGeneration {
                    enrolment,
                    manifest,
                } = *generation;
                (enrolment, manifest)
            }
            Ok(Generation::Busy) => {
                report
                    .limitations
                    .push("busy: another command changed this device during status".into());
                report.finish_unknown();
                return Ok(report);
            }
            Err(error) => {
                report.damaged("enrolment.json", &error, &command);
                report.finish_unknown();
                return Ok(report);
            }
            Ok(Generation::NotEnrolled) => {
                report.issue(
                    Urgency::Action,
                    "This device is not enrolled.",
                    "Get an invitation from IT.",
                    &command,
                    "join <invitation from IT>",
                    "Not applicable before enrolment.",
                );
                report.finish_unknown();
                return Ok(report);
            }
        };
    report.approval = ApprovalEvidence {
        state: enrolment.last_status,
        live: false,
        source: "saved on this device; not refreshed".into(),
    };
    let changed_note = tick
        .last_note
        .as_deref()
        .and_then(|note| note.strip_prefix("changed "))
        .filter(|hash| *hash != enrolment.manifest.as_str());
    let manifest = match manifest {
        Ok(manifest) => Some(manifest),
        Err(error) => {
            report.issue(
                Urgency::Action,
                format!("The signed local manifest is unavailable: {error:#}"),
                "Finish the manifest review.",
                &command,
                "accept",
                "Before the next claim.",
            );
            None
        }
    };
    report.manifest = Some(ManifestEvidence {
        signed: enrolment.manifest.clone(),
        enforced: None,
        agreement: "unknown; gateway not checked".into(),
    });
    if let Some(manifest) = &manifest {
        report.schedule.policy_defined = manifest.body().schedule.is_some();
        report.schedule.policy = manifest
            .body()
            .schedule
            .as_ref()
            .map(|schedule| {
                let line = schedule.to_string();
                line.strip_prefix("Automatic claims: ")
                    .unwrap_or(&line)
                    .to_string()
            })
            .unwrap_or_else(|| "none; the signed manifest defines no automatic sending".into());
        if manifest
            .body()
            .schedule
            .as_ref()
            .is_some_and(|schedule| schedule.probe().is_some())
        {
            report.schedule.vpn = if tick_damaged {
                "unknown; report-state.json is damaged".into()
            } else if home.file("report-state.json").exists() {
                format!(
                    "last job probe {}; time not recorded",
                    if tick.vpn_up { "answered" } else { "failed" }
                )
            } else {
                "unknown; no saved probe".into()
            };
        } else {
            report.schedule.vpn = "not required by the signed schedule".into();
        }
        if config.auto_send && manifest.body().schedule.is_none() {
            report.issue(
                Urgency::Action,
                "Automatic sending is on, but the signed manifest has no schedule.",
                "Turn automatic sending off.",
                &command,
                "schedule off",
                "No automatic claim can run under this manifest.",
            );
        }
    }
    if !online && manifest.is_some() {
        report.online_command = Some(format!("{command} status --online"));
    }
    if let Err(error) = report.read_claim(home, &enrolment, manifest.as_ref(), now, &command) {
        report.damaged("claims.jsonl", &error, &command);
    }
    if online {
        match if config_damaged {
            Ok(None)
        } else {
            inspect_job(home, &config).map(Some)
        } {
            Ok(None) => (),
            Ok(Some(job)) => report.job(&job, home, &command),
            Err(error) => {
                report.schedule.job = format!("unknown; OS query failed: {error:#}");
                report.issue(
                    Urgency::Action,
                    "The OS job could not be inspected.",
                    "Inspect automatic sending before relying on it.",
                    &command,
                    "schedule status",
                    "Before relying on automatic sending.",
                );
            }
        }
        if let Some(manifest) = &manifest {
            match refresh(home, &enrolment, manifest, insecure_dev, executable).await {
                Ok(live) => {
                    if let Some(approval) = live.approval {
                        report.approval = ApprovalEvidence {
                            state: Some(approval),
                            live: true,
                            source: "gateway refreshed now".into(),
                        };
                    }
                    if let Some(enforced) = &live.enforced
                        && let Some(evidence) = &mut report.manifest
                    {
                        evidence.agreement = if *enforced == enrolment.manifest {
                            "yes; gateway checked now"
                        } else {
                            "no; acceptance pending"
                        }
                        .into();
                        evidence.enforced = Some(enforced.clone());
                    }
                    if live
                        .enforced
                        .as_ref()
                        .is_some_and(|hash| *hash != enrolment.manifest)
                    {
                        report.issue(
                            Urgency::Action,
                            "The gateway enforces a manifest you have not signed.",
                            "Review the changes and sign if you agree.",
                            &command,
                            "accept",
                            "Unknown; new controls can already be in grace.",
                        );
                    }
                    match live.log {
                        Ok(()) => {
                            report.log =
                                "checkpoint verified now; own-entry proofs not requested".into()
                        }
                        Err(LogFailure::Alarm(text)) => {
                            report.log =
                                "ALARM; live checkpoint or pinned keys did not verify".into();
                            report.issue(
                                Urgency::Alarm,
                                text,
                                "Keep the last checkpoint and tell IT.",
                                &command,
                                "log head",
                                "Review now.",
                            );
                        }
                        Err(LogFailure::Unavailable(text)) => {
                            report.log = "unknown; consistency proof unavailable".into();
                            report.issue(
                                Urgency::Action,
                                text,
                                "Connect the company network and retry.",
                                &command,
                                "status --online",
                                "Unknown while the consistency proof is unavailable.",
                            );
                        }
                        Err(LogFailure::Damaged(error)) => {
                            report.log = "unknown; saved checkpoint is damaged".into();
                            report.damaged(crate::LOG_CHECKPOINT, &error, &command);
                        }
                    }
                    if let Some(vpn) = live.vpn {
                        report.schedule.vpn = if vpn {
                            "probe answered now"
                        } else {
                            "probe failed now; automatic sending pauses"
                        }
                        .into();
                        if !vpn && config.auto_send {
                            report.issue(
                                Urgency::Action,
                                "The signed VPN probe failed.",
                                "Connect the company VPN, then retry.",
                                &command,
                                "check",
                                "No grace deadline follows from the VPN probe.",
                            );
                        }
                    }
                }
                Err(error) => {
                    report
                        .limitations
                        .push(format!("Gateway refresh failed: {error:#}"));
                    report.issue(
                        Urgency::Action,
                        "Live approval and manifest agreement could not be confirmed.",
                        "Connect the company network and retry.",
                        &command,
                        "status --online",
                        "Unknown while the gateway cannot be reached.",
                    );
                }
            }
        }
    } else {
        report.limitations.push("Local mode makes no network or OS job queries. Approval, manifest agreement, and live VPN state can have changed.".into());
        if !config_damaged && !config.auto_send && home.file(crate::schedule::APPLIED).exists() {
            report.issue(
                Urgency::Action,
                "An installation record remains while automatic sending is off.",
                "Remove the job and its saved state.",
                &command,
                "schedule off",
                "No grace deadline.",
            );
        }
    }
    if !config_damaged && config.system_job_pending {
        let inspection = if online {
            inspect_pending(home).ok()
        } else {
            None
        };
        report.pending_system_job(home, online, &command, inspection.as_ref());
    }
    if let Some(note) = changed_note
        && !report
            .manifest
            .as_ref()
            .is_some_and(|evidence| evidence.enforced.as_ref() == Some(&evidence.signed))
    {
        report.issue(
            Urgency::Action,
            format!("The job last reported a changed manifest: {note}"),
            "Refresh status online, then review the manifest if it still differs.",
            &command,
            "status --online",
            "Unknown; the saved job note has no grace deadline.",
        );
    }
    match report.approval.state {
        Some(DeviceStatus::Pending) => report.issue(
            Urgency::Action,
            "This device waits for IT approval.",
            "Continue enrolment and wait for IT.",
            &command,
            "join",
            "IT has not supplied an approval deadline.",
        ),
        Some(DeviceStatus::Revoked) => report.issues.push(Issue {
            urgency: Urgency::Action,
            message: "IT revoked this device. It cannot send claims. Contact IT.".into(),
            fix: None,
            command: None,
            stop_job_command: config.auto_send.then(|| {
                if config.run_as == RunAs::System && online {
                    crate::schedule::system_stop_text(&home.0)
                } else if config.run_as == RunAs::System {
                    // Local mode starts no process, so the package state is not known here.
                    crate::schedule::system_stop_text_unprobed(&home.0)
                } else {
                    format!("{command} schedule off")
                }
            }),
            deadline: if report.approval.live {
                "Revoked now."
            } else {
                "Revoked now if the saved state is current."
            }
            .into(),
        }),
        _ => (),
    }
    report.finish();
    Ok(report)
}

struct Live {
    approval: Option<DeviceStatus>,
    enforced: Option<ManifestHash>,
    log: std::result::Result<(), LogFailure>,
    vpn: Option<bool>,
}

enum LogFailure {
    Alarm(String),
    Unavailable(String),
    Damaged(anyhow::Error),
}

enum Generation {
    NotEnrolled,
    Enrolled(Box<EnrolledGeneration>),
    Busy,
}

struct EnrolledGeneration {
    enrolment: Enrolment,
    manifest: Result<Manifest>,
}

fn read_generation(mut read: impl FnMut(&str) -> Result<Option<Vec<u8>>>) -> Result<Generation> {
    for _ in 0..3 {
        let before = read("enrolment.json")?;
        let manifest = read("manifest.toml");
        let after = read("enrolment.json")?;
        if before != after {
            continue;
        }
        let Some(bytes) = before else {
            return Ok(Generation::NotEnrolled);
        };
        let enrolment: Enrolment = serde_json::from_slice(&bytes)?;
        // Retry only when enrolment.json changed. A stable enrolment with another manifest is reported, not retried.
        let manifest = manifest.and_then(|bytes| {
            let manifest = Manifest::parse(&bytes.context("manifest.toml is missing")?)?;
            if manifest.hash() != &enrolment.manifest {
                bail!(
                    "manifest.toml is not the enrolled manifest {}",
                    enrolment.manifest.as_str()
                );
            }
            Ok(manifest)
        });
        return Ok(Generation::Enrolled(Box::new(EnrolledGeneration {
            enrolment,
            manifest,
        })));
    }
    Ok(Generation::Busy)
}

async fn refresh(
    home: &Home,
    enrolment: &Enrolment,
    manifest: &Manifest,
    insecure_dev: bool,
    executable: &Path,
) -> Result<Live> {
    crate::check_scheme(&enrolment.gateway, insecure_dev)?;
    let device = crate::DeviceKey::load(&home.0)?;
    if open_pact_core::Pseudonym::of(&device.public_key()) != enrolment.device {
        bail!("device key does not match enrolment");
    }
    let http = crate::http_client_with(Duration::from_secs(2), Duration::from_secs(3))?;
    let gateway = crate::base(&enrolment.gateway);
    let pins = Pins::load(home)?;
    let published: PublishedManifest =
        crate::get_json(&http, format!("{gateway}/v1/manifest")).await?;
    let enforced = ManifestHash::of(published.toml.as_bytes());
    let mut log = if published.company.key.fingerprint() != pins.company {
        Err(LogFailure::Alarm(
            "The gateway company key differs from the pinned key.".into(),
        ))
    } else if !published.company.verify(&enforced) {
        Err(LogFailure::Alarm(
            "The gateway manifest signature did not verify.".into(),
        ))
    } else {
        let log_key = crate::get_text(&http, format!("{gateway}/v1/log/key")).await?;
        pins.differs(&published.company.key.fingerprint(), &log_key)
            .map_or(Ok(()), |text| Err(LogFailure::Alarm(text)))
    };
    if log.is_ok() {
        let checkpoint = crate::get_text(&http, format!("{gateway}/v1/log/checkpoint")).await?;
        log = match home.checkpoint() {
            Err(error) => Err(LogFailure::Damaged(error)),
            Ok(previous) => crate::verify_checkpoint_unstored(
                &http,
                gateway,
                &pins.log,
                manifest.body().log.as_ref(),
                previous.as_ref(),
                &checkpoint,
            )
            .await?
            .map(|_| ())
            .map_err(|error| match error {
                crate::CheckpointVerifyError::Network(error) => LogFailure::Unavailable(format!(
                    "No consistency proof from the gateway: {error:#}"
                )),
                crate::CheckpointVerifyError::Alarm(text) => LogFailure::Alarm(text),
            }),
        };
    }
    // Do not authenticate to a gateway whose pinned keys or signature changed.
    let approval = if log.is_ok() {
        Some(crate::status_after_log_denial(&http, home, enrolment).await?)
    } else {
        None
    };
    let vpn = if let Some(probe) = manifest
        .body()
        .schedule
        .as_ref()
        .and_then(open_pact_core::Schedule::probe)
    {
        Some(
            crate::schedule::vpn_up(
                probe.address.as_str(),
                probe.name.as_ref().map(|name| name.as_str()),
                executable,
            )
            .await,
        )
    } else {
        None
    };
    let enforced = log.is_ok().then_some(enforced);
    Ok(Live {
        approval,
        enforced,
        log,
        vpn,
    })
}

fn timestamp(time: OffsetDateTime) -> String {
    open_pact_core::timestamp::rfc3339_secs(time)
}

type Outcome = (&'static str, Vec<String>, Vec<String>);

fn outcome_of(record: &locallog::Record) -> Result<Outcome> {
    let response = if record.response_incomplete {
        None
    } else {
        serde_json::from_slice::<Response>(&record.response()?).ok()
    };
    Ok(match response {
        Some(Response::Accepted { warnings, .. })
            if record
                .status
                .is_none_or(|status| (200..300).contains(&status)) =>
        {
            ("accepted", warnings, Vec::new())
        }
        Some(Response::Denied { reasons }) => ("denied", Vec::new(), reasons),
        _ => (
            "unknown; response incomplete or unusable",
            Vec::new(),
            Vec::new(),
        ),
    })
}

/// The gateway prints the time left as "23h", "30m", "3d" or "2d 5h" and rounds it down.
fn access_span(message: &str) -> Option<(&str, time::Duration)> {
    const MARK: &str = "access ends in ";
    let span = &message[message.rfind(MARK)? + MARK.len()..];
    let mut total = time::Duration::ZERO;
    let mut parts = 0;
    for part in span.split(' ') {
        let (number, unit) = part.split_at(part.len().checked_sub(1)?);
        let number: i64 = number.parse().ok()?;
        total += match unit {
            "m" => open_pact_core::timestamp::seconds(number.checked_mul(60)?)?,
            "h" => open_pact_core::timestamp::seconds(number.checked_mul(3600)?)?,
            "d" => open_pact_core::timestamp::seconds(number.checked_mul(86400)?)?,
            _ => return None,
        };
        parts += 1;
    }
    (1..=2).contains(&parts).then_some((span, total))
}

fn warning_deadline(message: &str, response_time: &str, now: OffsetDateTime) -> String {
    let Some((span, left)) = access_span(message) else {
        return "Exact deadline unknown; the gateway warning gives no time.".into();
    };
    let Some(deadline) = open_pact_core::timestamp::parse_rfc3339(response_time)
        .and_then(|time| time.to_offset(time::UtcOffset::UTC).checked_add(left))
    else {
        return "Exact deadline unknown; the response time is unreadable.".into();
    };
    let said = format!("(gateway said 'access ends in {span}' at {response_time})");
    if deadline < now {
        format!("Deadline passed at about {} {said}", timestamp(deadline))
    } else {
        format!("about {} {said}", timestamp(deadline))
    }
}

impl Report {
    fn damaged(&mut self, file: &str, error: &anyhow::Error, command: &str) {
        let fact = format!("damaged: {file}");
        self.limitations.push(format!("{fact}: {error:#}"));
        self.issue(
            Urgency::Action,
            fact,
            "Keep the file and tell IT.",
            command,
            "status",
            "Review before trusting this evidence.",
        );
    }

    fn finish_unknown(&mut self) {
        self.issues.sort_by_key(|issue| issue.urgency);
        (self.verdict, self.exit_code) = if self
            .issues
            .iter()
            .any(|issue| issue.urgency == Urgency::Alarm)
        {
            (Verdict::Alarm, 2)
        } else {
            (Verdict::Unknown, 3)
        };
    }

    fn issue(
        &mut self,
        urgency: Urgency,
        message: impl Into<String>,
        fix: &str,
        command: &str,
        action: &str,
        deadline: &str,
    ) {
        self.issues.push(Issue {
            urgency,
            message: message.into(),
            fix: Some(fix.into()),
            command: Some(format!("{command} {action}")),
            stop_job_command: None,
            deadline: deadline.into(),
        });
    }

    fn read_claim(
        &mut self,
        home: &Home,
        enrolment: &Enrolment,
        manifest: Option<&Manifest>,
        now: OffsetDateTime,
        command: &str,
    ) -> Result<()> {
        let (records, damaged) = locallog::read_lenient(&home.file("claims.jsonl"))?;
        if damaged > 0 {
            self.issue(Urgency::Action, format!("The local claim log has {damaged} damaged records; the latest outcome is unknown."),
                "Keep the log and tell IT.", command, "log show", "Review before trusting claim history.");
        }
        let Some(record) = records.last() else {
            self.issue(
                Urgency::Action,
                "No claim response is recorded yet.",
                "Run the signed checks and send the first claim.",
                command,
                "check",
                "Unknown until the gateway answers a claim.",
            );
            return Ok(());
        };
        let sent: serde_json::Value = serde_json::from_slice(&record.sent()?)?;
        let verified = sent["jws"].as_str().and_then(|jws| verify_claim(jws).ok());
        let claim = verified.as_ref().map(|verified| verified.claim());
        let (outcome, warnings, reasons) = outcome_of(record)?;
        let evidence = ClaimEvidence {
            sent_at: claim.map(|claim| timestamp(claim.time)),
            response_at: record.time.clone(),
            response: outcome.into(),
            warnings,
            reasons,
            manifest: claim.map(|claim| claim.manifest.clone()),
            os: claim.map(|claim| claim.os),
            results: claim.map(|claim| claim.results.clone()).unwrap_or_default(),
        };
        for (urgency, messages) in [
            (Urgency::Action, &evidence.reasons),
            (Urgency::Warning, &evidence.warnings),
        ] {
            for message in messages {
                let hint = manifest
                    .filter(|manifest| Some(manifest.hash()) == evidence.manifest.as_ref())
                    .and_then(|manifest| {
                        evidence.results.iter().find_map(|(id, value)| {
                            let control = manifest.body().control(id)?;
                            let os = evidence.os?;
                            if !message.starts_with(&format!("{id} "))
                                || control.required.get(&os)?.contains(value)
                            {
                                return None;
                            }
                            crate::checks::fix_hint(id, &value.to_string(), os)
                        })
                    })
                    .unwrap_or("Fix the reported item. Tell IT if the cause is unclear.");
                let deadline = if urgency == Urgency::Warning {
                    warning_deadline(message, &record.time, now)
                } else {
                    "The gateway denied that claim at the recorded time.".into()
                };
                self.issue(
                    urgency,
                    format!("Gateway at {}: {message}", record.time),
                    hint,
                    command,
                    "check",
                    &deadline,
                );
            }
        }
        if outcome.starts_with("unknown") {
            self.issue(
                Urgency::Action,
                "The last claim response is unconfirmed.",
                "Refresh with a new check. Keep the log if the failure repeats.",
                command,
                "check",
                "Unknown; a lost response does not prove rejection.",
            );
        } else if outcome == "denied" && evidence.reasons.is_empty() {
            self.issue(
                Urgency::Action,
                "The gateway denied the last claim without a reason.",
                "Tell IT and retry the check.",
                command,
                "check",
                "The gateway denied that claim at the recorded time.",
            );
        }
        if let Some(claim) = claim {
            if claim.device != enrolment.device {
                self.issue(
                    Urgency::Action,
                    "The saved claim belongs to another device.",
                    "Keep the log and tell IT.",
                    command,
                    "log show",
                    "Review now.",
                );
            }
            if let Some(age) =
                manifest.and_then(|manifest| manifest.body().claim_max_age.min_duration())
            {
                let expires = claim
                    .time
                    .checked_add(age)
                    .context("claim expiry overflows")?;
                if now > expires || claim.time > now + time::Duration::minutes(5) {
                    self.issue(
                        Urgency::Action,
                        "The recorded claim is stale or has a future time.",
                        "Check the device clock, then send a new claim.",
                        command,
                        "check",
                        &format!("Claim validity ends at {}.", timestamp(expires)),
                    );
                }
            }
        } else {
            self.issue(
                Urgency::Action,
                "The saved claim signature could not be verified.",
                "Keep the log and tell IT.",
                command,
                "log show",
                "Review now.",
            );
        }
        self.last_claim = Some(evidence);
        Ok(())
    }

    fn job(&mut self, inspection: &JobInspection, home: &Home, command: &str) {
        let job = inspection.job;
        self.schedule.job_status = Some(job);
        self.schedule.job = match job {
            JobStatus::Current => "installed and current; OS checked now",
            JobStatus::Missing => "missing; OS checked now",
            JobStatus::Outdated => "out of date; OS checked now",
            JobStatus::Leftover => "leftover job or saved state; OS checked now",
            JobStatus::Absent => "not installed; OS checked now",
            JobStatus::SystemUnconfirmed => {
                "SYSTEM job; installation and protected state not inspected"
            }
            JobStatus::NotOurs => "a SYSTEM task that is not the machine client's; OS checked now",
        }
        .into();
        self.schedule.machine_client = inspection.machine_state();
        self.schedule.machine_fix = inspection.machine_fix();
        self.schedule.job_fix = inspection
            .is_system()
            .then(|| inspection.job_fix(&home.0))
            .flatten();
        // The package and the task are two facts: each has its own issue and its own fix, and
        // neither hides the other.
        if let Some(fix) = self.schedule.machine_fix.clone() {
            let message = match inspection.machine_state() {
                Some(MachineState::Missing) => "The machine client is not installed.",
                Some(MachineState::Unprotected) => "The machine client is not protected.",
                Some(MachineState::Unknown) => "The machine client cannot be read.",
                _ => "The machine client is older than this client.",
            };
            self.issue_text(
                Urgency::Action,
                message,
                fix,
                "Before the next automatic claim can run.",
            );
        }
        match job {
            JobStatus::Missing | JobStatus::Outdated | JobStatus::NotOurs
                if self.schedule.system_job =>
            {
                let message = if job == JobStatus::NotOurs {
                    "A SYSTEM task for this home is not the machine client's. open-pact does not change it."
                } else {
                    "Automatic sending is on, but its job needs installation or update."
                };
                match self.schedule.job_fix.clone() {
                    Some(fix) => self.issue_text(
                        Urgency::Action,
                        message,
                        fix,
                        "Before the next automatic claim can run.",
                    ),
                    None if !inspection.is_system() => self.issue(
                        Urgency::Action,
                        message,
                        "From an elevated prompt, install the job for the signed schedule.",
                        command,
                        "schedule on --system",
                        "Before the next automatic claim can run.",
                    ),
                    // The machine client line above carries the fix.
                    None => self.issues.push(Issue {
                        urgency: Urgency::Action,
                        message: message.into(),
                        fix: None,
                        command: None,
                        stop_job_command: None,
                        deadline: "Before the next automatic claim can run.".into(),
                    }),
                }
            }
            JobStatus::Missing | JobStatus::Outdated => self.issue(Urgency::Action, "Automatic sending is on, but its job needs installation or update.",
                "Install the job for the signed schedule.", command, "schedule on", "Before the next automatic claim can run."),
            JobStatus::Leftover => self.issue(Urgency::Action, "A job or saved state remains while automatic sending is off.",
                "Remove the job and its saved state.", command, "schedule off", "No grace deadline."),
            JobStatus::SystemUnconfirmed => self.limitations.push(
                self.schedule
                    .job_fix
                    .clone()
                    .unwrap_or_else(|| "SYSTEM job installation is unconfirmed. Ask IT to inspect the task from an elevated PowerShell prompt.".into()),
            ),
            _ => (),
        }
    }

    /// An issue whose fix is a text, such as a block to paste, with no command of its own.
    fn issue_text(&mut self, urgency: Urgency, message: &str, fix: String, deadline: &str) {
        self.issues.push(Issue {
            urgency,
            message: message.into(),
            fix: Some(fix),
            command: None,
            stop_job_command: None,
            deadline: deadline.into(),
        });
    }

    /// Automatic sending waits for the SYSTEM job that the wizard could not install.
    ///
    /// The online report also says what state the machine client is in and what the SYSTEM task
    /// is, so that the desktop offers the administrator install only where it can work.
    fn pending_system_job(
        &mut self,
        home: &Home,
        online: bool,
        command: &str,
        inspection: Option<&JobInspection>,
    ) {
        // Local mode probes nothing, so it cannot know that the machine client passed its
        // protection check. It names no line that runs it and points at the online report.
        let fix = if let Some(inspection) = inspection.filter(|_| online) {
            if inspection.is_system() {
                self.schedule.machine_client = inspection.machine_state();
                self.schedule.pending_job_status = Some(inspection.job);
            }
            inspection
                .pending_fix(&home.0)
                .unwrap_or_else(|| crate::schedule::system_on_text(&home.0))
        } else if online {
            crate::schedule::system_on_text(&home.0)
        } else {
            format!(
                "Run `{command} status --online` to check the machine client. Install or repair it first when it is missing. Then run its `schedule on --system` from an elevated PowerShell prompt."
            )
        };
        self.issue_text(
            Urgency::Action,
            "Automatic sending waits for the SYSTEM job.",
            fix,
            "Before the next automatic claim can run.",
        );
    }

    fn finish(&mut self) {
        self.issues.sort_by_key(|issue| issue.urgency);
        (self.verdict, self.exit_code) = if self
            .issues
            .iter()
            .any(|issue| issue.urgency == Urgency::Alarm)
        {
            (Verdict::Alarm, 2)
        } else if !self.issues.is_empty() {
            (Verdict::ActionNeeded, 1)
        } else if self.mode == "online"
            && self.approval.state == Some(DeviceStatus::Approved)
            && self
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.enforced.as_ref() == Some(&manifest.signed))
            && self
                .last_claim
                .as_ref()
                .is_some_and(|claim| claim.response == "accepted")
            && matches!(
                self.schedule.job_status,
                Some(JobStatus::Current | JobStatus::Absent)
            )
        {
            (Verdict::NoKnownProblem, 0)
        } else {
            (Verdict::Unknown, 3)
        };
    }

    fn health(&self) -> &'static str {
        match self.verdict {
            Verdict::NoKnownProblem => "No known problem. The last claim was accepted.",
            Verdict::ActionNeeded => "Action needed. See the items below.",
            Verdict::Alarm => "LOG ALARM. Keep the checkpoint and tell IT.",
            Verdict::Unknown => "Some status is unknown. See the evidence below.",
        }
    }

    fn approval_text(&self) -> String {
        let state = match self.approval.state {
            Some(DeviceStatus::Approved) => "approved",
            Some(DeviceStatus::Pending) => "pending approval",
            Some(DeviceStatus::Revoked) => "revoked",
            None => "unknown",
        };
        format!("Device: {state} ({}).", self.approval.source)
    }

    fn sending_text(&self) -> String {
        let choice = match self.schedule.owner_consented {
            Some(true) => "on",
            Some(false) => "off",
            None => "unknown",
        };
        let sent = self
            .last_claim
            .as_ref()
            .and_then(|claim| claim.sent_at.as_deref())
            .unwrap_or("none confirmed in the local log");
        let last = self
            .last_claim
            .as_ref()
            .map(|claim| format!("{}, {}", claim.response_at, claim.response))
            .unwrap_or_else(|| "none recorded".into());
        let mut lines = vec![
            format!("Automatic sending: {choice}. Job: {}.", self.schedule.job),
            if self.schedule.owner_consented != Some(false) || !self.schedule.policy_defined {
                format!("Signed schedule: {}.", self.schedule.policy)
            } else {
                format!(
                    "Signed schedule (not used while automatic sending is off): {}.",
                    self.schedule.policy
                )
            },
            format!("VPN: {}.", self.schedule.vpn),
            format!("Last claim sent: {sent}."),
            format!("Last claim response: {last}."),
        ];
        if let Some(scheduled) = &self.schedule.last_scheduled_claim {
            lines.push(format!(
                "Last answered scheduled claim: {}.",
                scheduled.answered_at
            ));
        }
        if let Some(line) = &self.schedule.last_job_log_line {
            lines.push(format!("Last job log line (saved): {line}"));
        }
        if let Some(note) = &self.schedule.last_job_log_note {
            lines.push(note.clone());
        }
        lines.join("\n")
    }

    fn manifest_text(&self) -> String {
        match &self.manifest {
            Some(manifest) => format!(
                "Manifest agreement: {}.\nSigned: {}\nEnforced: {}",
                manifest.agreement,
                manifest.signed,
                manifest
                    .enforced
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown; gateway not checked".into())
            ),
            None => "Manifest agreement: no enrolled manifest.".into(),
        }
    }

    fn render(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        let _ = writeln!(text, "{}", self.health());
        let _ = writeln!(text, "Observed: {} ({}).", self.observed_at, self.mode);
        if let Some(command) = &self.online_command {
            let _ = writeln!(text, "Run `{command}` for current approval and manifest.");
        }
        self.render_issues(&mut text);
        let _ = writeln!(
            text,
            "\n{}\n{}\n{}",
            self.approval_text(),
            self.sending_text(),
            self.manifest_text()
        );
        let _ = writeln!(
            text,
            "\nLog: {}.\nCurrent checks: {}.",
            self.log, self.current_compliance
        );
        for limitation in &self.limitations {
            let _ = writeln!(text, "Note: {limitation}");
        }
        let _ = writeln!(text, "Exit: {}", self.exit_code);
        if let Some(update) = &self.update {
            let _ = writeln!(text, "{}", update.line());
        }
        text
    }

    fn render_issues(&self, text: &mut String) {
        use std::fmt::Write;
        if self.issues.is_empty() {
            let _ = writeln!(
                text,
                "\nNo recorded item needs a fix. Current checks have not run."
            );
        }
        for (index, issue) in self.issues.iter().enumerate() {
            let _ = writeln!(text, "\n{}. {}", index + 1, issue.message);
            if let Some(fix) = &issue.fix {
                let _ = writeln!(text, "   Fix: {fix}");
            }
            if let Some(command) = &issue.command {
                let _ = writeln!(text, "   Run: {command}");
            }
            if let Some(command) = &issue.stop_job_command {
                let _ = writeln!(text, "   To stop the job: {command}");
            }
            if issue.deadline.starts_with("Deadline passed") {
                let _ = writeln!(text, "   {}", issue.deadline);
            } else {
                let _ = writeln!(text, "   Deadline: {}", issue.deadline);
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod timestamp_pins {
    use super::*;

    fn at(s: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(s).unwrap()
    }

    #[test]
    fn timestamps_drop_fractions_and_read_offsets() {
        assert_eq!(
            timestamp(at("2026-11-16T10:00:00.999Z")),
            "2026-11-16T10:00:00Z"
        );
        assert_eq!(
            timestamp(at("2026-11-16T11:00:00.5+01:00")),
            "2026-11-16T10:00:00Z"
        );
    }

    #[test]
    fn access_spans_read_minutes_hours_and_days_and_refuse_overflow() {
        assert_eq!(
            access_span("firewall = off, access ends in 2d 5h"),
            Some(("2d 5h", time::Duration::hours(53)))
        );
        assert_eq!(
            access_span("access ends in 30m").map(|(_, left)| left),
            Some(time::Duration::minutes(30))
        );
        assert_eq!(
            access_span("access ends in 153722867280912m").map(|(_, left)| left.whole_seconds()),
            Some(9_223_372_036_854_720)
        );
        assert_eq!(access_span("access ends in 153722867280913m"), None);
        assert_eq!(access_span("access ends in 9999999999999999h"), None);
        assert_eq!(access_span("access ends in 3x"), None);
    }

    #[test]
    fn warning_deadlines_add_the_time_left_to_the_response_time() {
        let now = at("2026-11-16T10:00:00Z");
        let message = "firewall = off, access ends in 23h";
        assert_eq!(
            warning_deadline(message, "2026-11-16T09:50:00Z", now),
            "about 2026-11-17T08:50:00Z (gateway said 'access ends in 23h' at 2026-11-16T09:50:00Z)"
        );
        assert_eq!(
            warning_deadline(message, "2026-11-16T11:50:00.9+02:00", now),
            "about 2026-11-17T08:50:00Z (gateway said 'access ends in 23h' at 2026-11-16T11:50:00.9+02:00)"
        );
        assert_eq!(
            warning_deadline(message, "2026-11-16T09:50:00Z", at("2026-11-17T09:00:00Z")),
            "Deadline passed at about 2026-11-17T08:50:00Z (gateway said 'access ends in 23h' at 2026-11-16T09:50:00Z)"
        );
        assert_eq!(
            warning_deadline(message, "yesterday", now),
            "Exact deadline unknown; the response time is unreadable."
        );
    }
}
