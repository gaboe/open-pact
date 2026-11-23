use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use open_pact_core::{CheckPeriod, Manifest, ManifestHash, OnConnect, Place, ProbeName, Schedule};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::{self, NotSent, Outcome, ScanPolicy};
use crate::device_config::{self, DeviceConfig, RunAs};
use crate::machine::{MachineClient, MachineState, same_windows_path};
use crate::{Home, checks};

const STATE: &str = "report-state.json";
/// What the job tells the owner: manifest changes, denials, log alarms and errors. The OS also
/// sends the job's output here where it can.
const JOB_LOG: &str = "schedule.log";
const JOB_LOG_LIMIT: u64 = 256 * 1024;
/// Files an earlier client left. `schedule off` removes them.
const HOME_LEFTOVER_FILES: &[&str] = &[
    "report-schedule.json",
    STATE,
    "reports.jsonl",
    "reports.jsonl.tmp",
];
const HOME_REMOVE_FILES: &[&str] = &[
    "report-schedule.json",
    STATE,
    "report-state.json.tmp",
    "report-schedule.json.tmp",
    "reports.jsonl",
    "reports.jsonl.tmp",
    JOB_LOG,
    "schedule.log.1",
    JOB_REFRESH,
];
/// How often the OS wakes the job. Each wake costs one process start and one probe; the check and
/// send periods come from the signed manifest, and a wake with nothing due exits at once.
const WAKE_MINUTES: u32 = 1;
const WAKE_SECS: u32 = WAKE_MINUTES * 60;
/// The wake period as Task Scheduler reports a trigger's repeat interval.
const WAKE_ISO: &str = "PT1M";
const REPO_SCAN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const LOCK: &str = "report-schedule.lock";
/// The client version and path that last compared the job with its own definition.
const JOB_REFRESH: &str = "job-refresh.json";

/// The `schedule` commands of the CLI, without the parser.
#[derive(Clone, Debug)]
pub enum Command {
    On {
        system: bool,
        user: bool,
        dry_run: bool,
        /// The profile a SYSTEM job reads. Only with `system`.
        user_home: Option<PathBuf>,
    },
    Off {
        dry_run: bool,
    },
    Status,
    Run {
        system: bool,
        user_home: Option<PathBuf>,
    },
    Probe {
        address: String,
        name: Option<String>,
    },
}

enum Operation {
    Install {
        system: bool,
        user_home: Option<PathBuf>,
        /// A SYSTEM update keeps the state of the running job.
        keep_state: bool,
    },
    Uninstall {
        system: bool,
    },
    Run {
        system: bool,
        user_home: Option<PathBuf>,
    },
}

/// Why a scheduled run sends a claim. It never leaves the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    Connect,
    Event,
    Periodic,
}

impl Trigger {
    fn name(self) -> &'static str {
        match self {
            Trigger::Connect => "connect",
            Trigger::Event => "event",
            Trigger::Periodic => "periodic",
        }
    }
}

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
struct State {
    /// Whether the last wake found the VPN answering.
    vpn_up: bool,
    #[serde(default)]
    reconnect_pending: bool,
    last_success: Option<i64>,
    /// The last time the gateway answered an attempt, with a verdict or without one (waiting for
    /// approval, revoked, accept pending). No periodic or connect claim comes sooner than
    /// `interval` after it.
    #[serde(default)]
    last_attempt: Option<i64>,
    /// What the job log last said about the outcome, so the same news is written once.
    #[serde(default)]
    last_note: Option<String>,
    #[serde(default)]
    last_events: Option<checks::EventMarkers>,
    #[serde(default)]
    event_baseline: Option<EventBaseline>,
    #[serde(default)]
    last_compliance: Option<BTreeMap<String, bool>>,
    #[serde(default)]
    last_observed_compliance: Option<BTreeMap<String, bool>>,
    #[serde(default)]
    event_pending: bool,
    /// When the last local check finished. A connect clears it, so the first wake on the VPN checks.
    #[serde(default)]
    last_check: Option<i64>,
    /// When each control that fails now first failed on this device, for the local grace.
    #[serde(default)]
    first_failed: BTreeMap<String, i64>,
    /// A removal at grace expiry failed and its claim was already forced, so the next check that
    /// fails the same way does not force another.
    #[serde(default)]
    removal_failed: bool,
    /// The client version that last ran this job, so the job log names each version once.
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct EventBaseline {
    security_log_cleared: bool,
    antimalware_detection: bool,
}

impl State {
    fn observe(&mut self, vpn_up: bool) {
        if vpn_up && !self.vpn_up {
            self.reconnect_pending = true;
            self.last_check = None;
        }
        self.vpn_up = vpn_up;
    }

    /// The last answered attempt is older than the interval, or there is none, or the clock ran
    /// back past it.
    fn interval_elapsed(&self, now: i64, interval: i64) -> bool {
        self.last_attempt
            .max(self.last_success)
            .is_none_or(|last| now < last || now.saturating_sub(last) >= interval)
    }

    /// The gateway answered an attempt less than `within` seconds ago.
    fn answered_within(&self, now: i64, within: i64) -> bool {
        self.last_attempt
            .max(self.last_success)
            .is_some_and(|last| now >= last && now - last < within)
    }

    /// The last local check is older than `period`, or there is none, or the clock ran back.
    fn check_older_than(&self, now: i64, period: i64) -> bool {
        self.last_check
            .is_none_or(|last| now < last || now - last >= period)
    }

    /// Notes when each control first failed on this device, and forgets a control that passes or
    /// is no longer required.
    fn observe_failures(&mut self, compliance: &BTreeMap<String, bool>, now: i64) {
        self.first_failed
            .retain(|id, _| compliance.get(id) == Some(&false));
        for (id, compliant) in compliance {
            if !compliant {
                self.first_failed.entry(id.clone()).or_insert(now);
            }
        }
    }

    fn new_events(&self, current: checks::EventMarkerReads) -> bool {
        let baseline = self.baseline();
        let previous = self.last_events.unwrap_or_default();
        newer(
            current.security_log_cleared,
            baseline.security_log_cleared,
            previous.security_log_cleared,
        ) || newer(
            current.antimalware_detection,
            baseline.antimalware_detection,
            previous.antimalware_detection,
        )
    }

    fn observe_compliance(&mut self, current: &BTreeMap<String, bool>) {
        if let Some(previous) = self
            .last_observed_compliance
            .as_ref()
            .or(self.last_compliance.as_ref())
            && current
                .iter()
                .any(|(id, compliant)| !compliant && previous.get(id) == Some(&true))
        {
            self.event_pending = true;
        }
        self.last_observed_compliance = Some(current.clone());
    }

    fn acknowledged(&mut self, now: i64, events: checks::EventMarkerReads) {
        self.last_success = Some(now);
        self.last_attempt = Some(now);
        self.reconnect_pending = false;
        self.merge_events(events);
    }

    /// The gateway answered without a verdict on the claim: the device waits for approval, IT
    /// revoked it, or the manifest awaits `accept`. That counts as the attempt, so the job asks
    /// again only after the interval.
    fn attempted(
        &mut self,
        now: i64,
        events: checks::EventMarkerReads,
        compliance: BTreeMap<String, bool>,
    ) {
        self.last_attempt = Some(now);
        self.reconnect_pending = false;
        self.merge_events(events);
        self.last_compliance = Some(compliance);
        self.event_pending = false;
    }

    /// What a finished attempt does to the state. No answer at all (a network error) never gets
    /// here, so the next run tries again.
    fn record(
        &mut self,
        outcome: &Outcome,
        now: i64,
        events: checks::EventMarkerReads,
        compliance: BTreeMap<String, bool>,
    ) {
        match outcome {
            Outcome::NotSent(NotSent::OffVpn) => self.sent(false, now, events, compliance),
            outcome if outcome.delivered() => self.sent(true, now, events, compliance),
            _ => self.attempted(now, events, compliance),
        }
    }

    fn sent(
        &mut self,
        acknowledged: bool,
        now: i64,
        events: checks::EventMarkerReads,
        compliance: BTreeMap<String, bool>,
    ) {
        if acknowledged {
            self.acknowledged(now, events);
            self.last_compliance = Some(compliance);
            self.event_pending = false;
        } else {
            self.observe(false);
        }
    }

    fn baseline(&self) -> EventBaseline {
        self.event_baseline.unwrap_or(EventBaseline {
            security_log_cleared: self.last_events.is_some(),
            antimalware_detection: self.last_events.is_some(),
        })
    }

    fn establish_baseline(&mut self, events: checks::EventMarkerReads) {
        let mut markers = self.last_events.unwrap_or_default();
        let mut baseline = self.baseline();
        if !baseline.security_log_cleared
            && let checks::EventMarkerRead::Read(timestamp) = events.security_log_cleared
        {
            markers.security_log_cleared = timestamp;
            baseline.security_log_cleared = true;
        }
        if !baseline.antimalware_detection
            && let checks::EventMarkerRead::Read(timestamp) = events.antimalware_detection
        {
            markers.antimalware_detection = timestamp;
            baseline.antimalware_detection = true;
        }
        if baseline.security_log_cleared || baseline.antimalware_detection {
            self.last_events = Some(markers);
            self.event_baseline = Some(baseline);
        }
    }

    fn merge_events(&mut self, events: checks::EventMarkerReads) {
        let mut markers = self.last_events.unwrap_or_default();
        let mut baseline = self.baseline();
        if let checks::EventMarkerRead::Read(timestamp) = events.security_log_cleared {
            markers.security_log_cleared = timestamp;
            baseline.security_log_cleared = true;
        }
        if let checks::EventMarkerRead::Read(timestamp) = events.antimalware_detection {
            markers.antimalware_detection = timestamp;
            baseline.antimalware_detection = true;
        }
        if baseline.security_log_cleared || baseline.antimalware_detection {
            self.last_events = Some(markers);
            self.event_baseline = Some(baseline);
        }
    }
}

fn newer(current: checks::EventMarkerRead, initialized: bool, previous: Option<i64>) -> bool {
    initialized
        && matches!(current, checks::EventMarkerRead::Read(Some(current))
            if previous.is_none_or(|previous| current > previous))
}

/// A connect claim comes at most this often (seconds). A VPN that flaps does not flood the gateway:
/// the claim that went out within this window already proves the device, and any change in a
/// result still sends at once.
const CONNECT_REUSE_SECS: i64 = 5 * 60;
/// How often a device that sends on any network, off the VPN, runs its checks.
const ELSEWHERE_CHECK_SECS: i64 = 5 * 60;
/// The shortest check period on Windows, where one check starts PowerShell. Lower it only after
/// `check --dry-run --timings` shows a median cost the fleet accepts.
const WINDOWS_CHECK_FLOOR_SECS: i64 = 5 * 60;

fn check_floor_secs() -> i64 {
    if cfg!(windows) {
        WINDOWS_CHECK_FLOOR_SECS
    } else {
        0
    }
}

/// What one wake does, decided before any check runs.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    /// Run the checks now. A wake that runs none exits after its probe.
    check: bool,
    /// Send a claim after the checks, and why. A result that gets worse during the checks adds an
    /// `Event` send; ask again after them.
    send: Option<Trigger>,
}

impl Plan {
    fn idle(&self) -> bool {
        !self.check && self.send.is_none()
    }
}

/// How far ahead `next_due` looks. A send interval is at most 24 hours.
const HORIZON_SECS: i64 = 3 * 24 * 60 * 60;

/// The first second at or after `now` where `due` holds, if it holds within the horizon. `due`
/// only turns from false to true as time passes.
fn first_time(now: i64, due: impl Fn(i64) -> bool) -> Option<i64> {
    if due(now) {
        return Some(now);
    }
    let end = now.saturating_add(HORIZON_SECS);
    if !due(end) {
        return None;
    }
    let (mut low, mut high) = (now, end);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if due(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    Some(high)
}

/// When the next check and the next claim fall due if the device stays where the last wake found
/// it. Derived from `plan`, so it says what the job will do.
#[derive(Debug, PartialEq, Eq)]
struct NextDue {
    check: Option<i64>,
    send: Option<i64>,
}

fn next_due(schedule: &Schedule, state: &State, now: i64) -> NextDue {
    let place = if state.vpn_up {
        Place::Vpn
    } else {
        Place::Elsewhere
    };
    let floor = check_floor_secs();
    NextDue {
        check: first_time(now, |at| plan(schedule, state, place, at, floor).check),
        send: first_time(now, |at| {
            plan(schedule, state, place, at, floor).send.is_some()
        }),
    }
}

fn time_text(time: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(time).map_or_else(
        |_| "an unknown time".to_owned(),
        open_pact_core::timestamp::rfc3339_secs,
    )
}

/// What `schedule status` and `accept` say about the job's next steps.
fn next_due_lines(schedule: &Schedule, state: &State, now: i64) -> Vec<String> {
    let next = next_due(schedule, state, now);
    let off_vpn = !state.vpn_up && !schedule.may_send(Place::Elsewhere);
    let line = |what: &str, due: Option<i64>| match due {
        Some(time) if time <= now => format!("Next {what} due: at the next wake, within a minute."),
        Some(time) => format!("Next {what} due: {}.", time_text(time)),
        None if off_vpn => format!(
            "Next {what} due: none while the VPN does not answer. The job only tests whether it does."
        ),
        None => format!("Next {what} due: none within three days."),
    };
    let mut lines = Vec::new();
    if let Some(last) = state.last_check {
        lines.push(format!("Last check: {}.", time_text(last)));
    }
    lines.push(line("check", next.check));
    lines.push(line("claim", next.send));
    lines
}

/// The home that holds the job's saved state: the client home for a user job, the protected
/// directory of the SYSTEM job on Windows.
fn job_state_home(home: &Home, run_as: RunAs, _executable: &Path) -> Result<Home> {
    let absolute = Home(schedule_home(&home.0, true)?);
    match run_as {
        RunAs::User => Ok(absolute),
        RunAs::System if crate::current_os()? == open_pact_core::Os::Windows => Ok(Home(
            windows_protected_paths(&absolute, &crate::machine::machine_path())?,
        )),
        RunAs::System => bail!("a SYSTEM job exists only on Windows"),
    }
}

/// `next_due_lines` from the saved state of the job that runs (`run_as`), or from a fresh state
/// when the job has not run yet. A state that cannot be read is said so: it is not a new job.
pub(crate) fn next_due_text(
    home: &Home,
    run_as: RunAs,
    schedule: &Schedule,
    executable: &Path,
) -> Vec<String> {
    due_text(job_state_home(home, run_as, executable), schedule)
}

fn due_text(state_home: Result<Home>, schedule: &Schedule) -> Vec<String> {
    match state_home.and_then(|state_home| state_home.read_json::<State>(STATE)) {
        Ok(state) => next_due_lines(
            schedule,
            &state.unwrap_or_default(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        ),
        Err(error) => vec![format!(
            "Next check and claim: unknown. The job's saved state cannot be read ({error:#})."
        )],
    }
}

/// The decision of one wake. Pure: the caller probes for `place`, reads `state` and the clock,
/// and then does only what the plan names.
///
/// - Checks: on the VPN every `check` of the schedule and on the first wake after a connect;
///   elsewhere only where the schedule sends from any network, every five minutes. A claim that is
///   due always runs fresh checks first. `check_floor` raises the VPN check period (Windows).
/// - Sends: where the schedule allows a claim at this place, at once when a result got worse, at
///   once on a connect (unless a claim was answered within the last five minutes; the flat 0.7 form
///   waits for its interval), and when the interval has passed.
fn plan(schedule: &Schedule, state: &State, place: Place, now: i64, check_floor: i64) -> Plan {
    let connect = place == Place::Vpn && state.reconnect_pending;
    let send = schedule.period(place).and_then(|period| {
        if state.event_pending {
            Some(Trigger::Event)
        } else if connect
            && schedule.on_connect() == Some(OnConnect::Send)
            && !state.answered_within(now, CONNECT_REUSE_SECS)
        {
            Some(Trigger::Connect)
        } else if state.interval_elapsed(now, period.as_secs()) {
            Some(if connect {
                Trigger::Connect
            } else {
                Trigger::Periodic
            })
        } else {
            None
        }
    });
    let check_period = match place {
        Place::Vpn => schedule
            .vpn_check_period()
            .map_or(CheckPeriod::DEFAULT.as_secs(), |period| period.as_secs())
            .max(check_floor),
        Place::Elsewhere => ELSEWHERE_CHECK_SECS.max(check_floor),
    };
    let checks_here = match place {
        Place::Vpn => true,
        Place::Elsewhere => schedule.may_send(place),
    };
    Plan {
        check: send.is_some() || (checks_here && state.check_older_than(now, check_period)),
        send,
    }
}

async fn probe_process(command: &mut tokio::process::Command, limit: Duration) -> bool {
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    match tokio::time::timeout(limit, child.wait()).await {
        Ok(Ok(status)) => status.success(),
        _ => {
            let _ = child.kill().await;
            false
        }
    }
}

/// Whether the VPN answers at `probe`. With `name`, the answer must also be a TLS connection whose
/// certificate is valid for `name`.
pub(crate) async fn vpn_up(probe: &str, name: Option<&str>, executable: &Path) -> bool {
    let Some(name) = name else {
        return tcp_up(probe, executable).await;
    };
    if let Ok(address) = probe.parse::<std::net::SocketAddr>() {
        return named_up(address, name, Vec::new()).await;
    }
    // System DNS can block indefinitely. Only a separate process can be cancelled.
    probe_process(
        tokio::process::Command::new(executable).args([
            "schedule",
            "probe",
            "--address",
            probe,
            "--name",
            name,
        ]),
        NAMED_PROBE_LIMIT,
    )
    .await
}

async fn tcp_up(probe: &str, executable: &Path) -> bool {
    if let Ok(address) = probe.parse::<std::net::SocketAddr>() {
        return matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(address)
            )
            .await,
            Ok(Ok(_))
        );
    }
    // System DNS can block indefinitely. Only a separate process can be cancelled.
    probe_process(
        tokio::process::Command::new(executable).args(["schedule", "probe", "--address", probe]),
        Duration::from_secs(2),
    )
    .await
}

/// The whole named probe, DNS included, must finish within this limit.
const NAMED_PROBE_LIMIT: Duration = Duration::from_secs(5);

/// A TLS connection to `address` that completes with a certificate valid for `name`. The name is
/// never looked up in DNS. The connection goes to `address`, and `name` sets only the SNI and the
/// certificate check. Any HTTP status counts, because the handshake is what proves the host.
async fn named_up(
    address: std::net::SocketAddr,
    name: &str,
    roots: Vec<reqwest::Certificate>,
) -> bool {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(NAMED_PROBE_LIMIT)
        .resolve(name, address);
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    let Ok(client) = builder.build() else {
        return false;
    };
    client
        .get(format!("https://{name}:{}/", address.port()))
        .send()
        .await
        .is_ok()
}

fn check_probe(address: &str) -> Result<()> {
    open_pact_core::ProbeAddress::try_from(address.to_owned()).map_err(anyhow::Error::msg)?;
    Ok(())
}

pub(crate) fn probe_blocking(address: &str) -> Result<()> {
    use std::net::{TcpStream, ToSocketAddrs};
    check_probe(address)?;
    for address in address.to_socket_addrs()? {
        if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok() {
            return Ok(());
        }
    }
    bail!("VPN probe failed")
}

/// The `schedule probe` command: exits with success only when the probe connects, and with `name`
/// only when the TLS check passes too.
pub(crate) async fn probe_command(address: &str, name: Option<&str>) -> Result<()> {
    let Some(name) = name else {
        return probe_blocking(address);
    };
    check_probe(address)?;
    for address in tokio::net::lookup_host(address).await? {
        if named_up(address, name, Vec::new()).await {
            return Ok(());
        }
    }
    bail!("VPN probe failed")
}

struct ScheduleLock(File);

impl Drop for ScheduleLock {
    fn drop(&mut self) {
        // A concurrent spawn can inherit the descriptor until exec closes it.
        let _ = self.0.unlock();
    }
}

fn lock_path(path: &Path) -> Result<ScheduleLock> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            bail!("another schedule command is running");
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    Ok(ScheduleLock(file))
}

fn lock(home: &Home) -> Result<ScheduleLock> {
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(&home.0)?;
    lock_path(&home.file(LOCK))
}

fn lock_system_state(home: &Home) -> Result<ScheduleLock> {
    let parent = home.0.parent().context("SYSTEM state parent is missing")?;
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    directory.create(parent)?;
    let lock = home.0.with_extension("lock");
    match lock_path(&lock) {
        Ok(lock) => Ok(lock),
        Err(error)
            if error
                .to_string()
                .contains("another schedule command is running") =>
        {
            Err(error).context("SYSTEM job state is in use; retry this command")
        }
        Err(error) => Err(error).context(format!(
            "cannot lock SYSTEM job state at {}; run from an elevated prompt",
            home.0.display()
        )),
    }
}

/// How long a SYSTEM removal waits for a tick that still runs: first for the state lock, then for
/// the protected binary to be free.
const SYSTEM_WAIT: Duration = Duration::from_secs(30);
const SYSTEM_WAIT_STEP: Duration = Duration::from_millis(250);

fn is_state_in_use(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("SYSTEM job state is in use")
}

/// Runs `attempt` again after `step` while it fails with "SYSTEM job state is in use", for at
/// most `budget`. The last error stays unchanged when the budget runs out or the error differs.
fn retry_while_state_in_use<T>(
    budget: Duration,
    step: Duration,
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut waited = Duration::ZERO;
    loop {
        match attempt() {
            Err(error) if is_state_in_use(&error) && waited < budget => {
                let pause = step.min(budget - waited);
                sleep(pause);
                waited += pause;
            }
            other => return other,
        }
    }
}

fn save<T: Serialize>(home: &Home, name: &str, value: &T) -> Result<()> {
    let temp = home.file(&format!("{name}.tmp"));
    remove_if_exists(&temp)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = std::fs::metadata(home.file(name))
            .map(|metadata| metadata.permissions().mode() & 0o600)
            .unwrap_or(0o600);
        options.mode(mode);
    }
    let mut file = options.open(&temp)?;
    let result = (|| -> Result<()> {
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        std::fs::rename(&temp, home.file(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    Ok(())
}

fn text(path: &Path) -> Result<&str> {
    let text = path.to_str().context("scheduler paths must be UTF-8")?;
    if text.chars().any(char::is_control) {
        bail!("scheduler path contains a control character");
    }
    Ok(text)
}

fn xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_arg(raw: &str) -> String {
    format!(
        "\"{}\"",
        raw.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}

/// One argument of a command line, quoted only where Windows needs it, as Rust's own spawn does.
fn windows_command_line_arg(raw: &str) -> String {
    if !raw.is_empty() && !raw.contains([' ', '\t', '"']) {
        return raw.to_owned();
    }
    windows_arg(raw)
}

fn windows_arg(raw: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in raw.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.push_str(&"\\".repeat(if c == '"' { slashes * 2 + 1 } else { slashes }));
        out.push(c);
        slashes = 0;
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

struct Job {
    id: String,
    argv: Vec<String>,
    /// Where the OS sends the job's output. Task Scheduler cannot, so the job also writes its own
    /// notes there.
    log: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskRunAs {
    CurrentUser,
    System,
}

#[derive(Clone, Copy)]
enum RegistrationAction {
    Install(TaskRunAs),
    Uninstall,
}

impl RegistrationAction {
    fn installs(self) -> bool {
        matches!(self, Self::Install(_))
    }
}

/// The id of the OS job of `home`: the first 16 hex digits of the SHA-256 of the home path.
fn task_id(home: &Path) -> Result<String> {
    Ok(format!(
        "org.open-pact.report.{}",
        &hex::encode(Sha256::digest(text(home)?.as_bytes()))[..16]
    ))
}

impl Job {
    fn new(executable: &Path, home: &Path) -> Result<Self> {
        Ok(Self {
            id: task_id(home)?,
            argv: vec![
                text(executable)?.into(),
                "--home".into(),
                text(home)?.into(),
                "schedule".into(),
                "run".into(),
            ],
            log: text(&home.join(JOB_LOG))?.into(),
        })
    }

    /// The job runs as SYSTEM, so repositories and `~` paths come from `user_home`, not from the
    /// SYSTEM profile.
    fn for_system(mut self, user_home: &Path) -> Result<Self> {
        self.argv.extend([
            "--system".into(),
            "--user-home".into(),
            text(user_home)?.into(),
        ]);
        Ok(self)
    }

    fn plist(&self) -> String {
        let args = self
            .argv
            .iter()
            .map(|arg| format!("<string>{}</string>", xml(arg)))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array>{args}</array>
<key>StartInterval</key><integer>{WAKE_SECS}</integer>
<key>RunAtLoad</key><true/>
<key>StandardOutPath</key><string>{log}</string>
<key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
            self.id,
            log = xml(&self.log)
        )
    }

    fn service(&self) -> String {
        let args = self
            .argv
            .iter()
            .enumerate()
            .map(|(index, arg)| {
                // Systemd expands environment variables in arguments, but not in the executable.
                if index == 0 {
                    systemd_arg(arg).replace("$$", "$")
                } else {
                    systemd_arg(arg)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let log = self.log.replace('%', "%%");
        format!(
            "[Unit]\nDescription=Open-pact scheduled claim\n[Service]\nType=oneshot\nStandardOutput=append:{log}\nStandardError=append:{log}\nExecStart={args}\n"
        )
    }

    fn timer(&self) -> String {
        format!(
            "[Unit]\nDescription=Wake open-pact every minute and send claims when the signed schedule says so\n[Timer]\nOnStartupSec=1min\nOnUnitActiveSec=1min\nAccuracySec=1s\nUnit={}.service\n[Install]\nWantedBy=timers.target\n",
            self.id
        )
    }

    fn schtasks_install(&self, run_as: TaskRunAs) -> Vec<String> {
        let mut args = vec![
            "/Create".into(),
            "/TN".into(),
            self.id.clone(),
            "/SC".into(),
            "MINUTE".into(),
            "/MO".into(),
            WAKE_MINUTES.to_string(),
            "/TR".into(),
            self.argv
                .iter()
                .map(|arg| windows_arg(arg))
                .collect::<Vec<_>>()
                .join(" "),
        ];
        match run_as {
            TaskRunAs::CurrentUser => args.extend(["/RL".into(), "LIMITED".into()]),
            TaskRunAs::System => args.extend([
                "/RU".into(),
                "SYSTEM".into(),
                "/RL".into(),
                "HIGHEST".into(),
            ]),
        }
        // A user's task is replaced in place. A SYSTEM task is created after the old task is
        // deleted, so it never keeps the security descriptor of a task that a user planted.
        if run_as == TaskRunAs::CurrentUser {
            args.push("/F".into());
        }
        args
    }
}

fn execute(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("start {program}"))?;
    command_result(program, output)
}

fn command_result(program: &str, output: std::process::Output) -> Result<()> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if program.rsplit(['\\', '/']).next() == Some("schtasks.exe") {
            bail!(
                "schtasks.exe failed with code {:?}; run from an elevated prompt. {stderr} {stdout}",
                output.status.code()
            );
        }
        bail!("{program} failed: {}", stderr);
    }
    Ok(())
}

fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn schedule_home(path: &Path, allow_missing: bool) -> Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let absolute = normalize_absolute_path(&absolute);
            let mut existing = absolute.clone();
            let mut missing = Vec::new();
            let canonical = loop {
                match std::fs::canonicalize(&existing) {
                    Ok(path) => break path,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if let Some(name) = existing.file_name() {
                            missing.push(name.to_os_string());
                            existing.pop();
                        } else {
                            return Err(error).context("resolve schedule home");
                        }
                    }
                    Err(error) => return Err(error).context("resolve schedule home"),
                }
            };
            let mut normalized = canonical;
            for component in missing.iter().rev() {
                normalized.push(component);
            }
            Ok(normalized)
        }
        Err(error) => Err(error).context("resolve schedule home"),
    }
}

/// Fails closed when a link leads to the `--home` of a SYSTEM run. Install stored the resolved
/// path, so a home that resolves elsewhere now is a junction or symbolic link that a user planted
/// in the home or above it. Nothing may open the target, not even to create a lock.
fn require_home_without_link(given: &Path, resolved: &Path) -> Result<()> {
    if home_resolves_to_itself(given, resolved) {
        return Ok(());
    }
    bail!(
        "refuse the client home {}: a link leads to {}",
        given.display(),
        resolved.display()
    )
}

/// Whether `resolved`, from `std::fs::canonicalize`, names `given`. Windows paths ignore case, and
/// the `\\?\` prefix does not count, so the form that install stored passes.
fn home_resolves_to_itself(given: &Path, resolved: &Path) -> bool {
    match (given.to_str(), resolved.to_str()) {
        (Some(given), Some(resolved)) => crate::home_fs::same_path(resolved, given),
        _ => false,
    }
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn systemd_dir() -> Result<PathBuf> {
    Ok(match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => PathBuf::from(path),
        None => user_home()?.join(".config"),
    }
    .join("systemd/user"))
}

fn systemd_status(timer: &str, query: &str) -> Result<bool> {
    Ok(std::process::Command::new("systemctl")
        .args(["--user", query, timer])
        .output()?
        .status
        .success())
}

fn launch_domain() -> Result<String> {
    let output = std::process::Command::new("id").arg("-u").output()?;
    let uid = String::from_utf8(output.stdout)?
        .trim()
        .parse::<u32>()
        .context("read user id")?;
    if !output.status.success() {
        bail!("read user id failed");
    }
    Ok(format!("gui/{uid}"))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

fn home_schedule_has_leftovers(home: &Home) -> bool {
    HOME_LEFTOVER_FILES
        .iter()
        .any(|name| home.file(name).exists())
}

fn remove_home_schedule_files(home: &Home) -> Result<()> {
    for name in HOME_REMOVE_FILES {
        let path = home.file(name);
        match crate::home_fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("remove {}", path.display())),
        }
    }
    Ok(())
}

/// Removes the home files of a SYSTEM job. The home is protected while they go, so a link at the
/// home or above it stops the removal before anything is deleted.
fn remove_protected_home_schedule_files(home: &Home) -> Result<()> {
    let _protection = crate::home_fs::protect(&home.0, &home.0)?;
    remove_home_schedule_files(home)
}

fn remove_system_state_directory(path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(path)
}

fn register(job: &Job, action: RegistrationAction) -> Result<()> {
    match crate::current_os()? {
        open_pact_core::Os::Macos => {
            let path = user_home()?
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", job.id));
            let domain = launch_domain()?;
            let target = format!("{domain}/{}", job.id);
            let loaded = std::process::Command::new("launchctl")
                .args(["print", &target])
                .output()?
                .status
                .success();
            if loaded {
                execute("launchctl", &["bootout", &target])?;
            }
            if action.installs() {
                std::fs::create_dir_all(path.parent().context("LaunchAgents directory")?)?;
                std::fs::write(&path, job.plist())?;
                execute("launchctl", &["bootstrap", &domain, text(&path)?])?;
            } else {
                remove_if_exists(&path)?;
            }
        }
        open_pact_core::Os::Linux => {
            let dir = systemd_dir()?;
            let service = dir.join(format!("{}.service", job.id));
            let timer = dir.join(format!("{}.timer", job.id));
            let timer_name = format!("{}.timer", job.id);
            if action.installs() {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&service, job.service())?;
                std::fs::write(&timer, job.timer())?;
                execute("systemctl", &["--user", "daemon-reload"])?;
                execute("systemctl", &["--user", "enable", "--now", &timer_name])?;
                // `enable --now` leaves a running timer on its old period.
                execute("systemctl", &["--user", "restart", &timer_name])?;
            } else if timer.exists()
                || service.exists()
                || systemd_status(&timer_name, "is-active")?
                || systemd_status(&timer_name, "is-enabled")?
            {
                execute("systemctl", &["--user", "disable", "--now", &timer_name])?;
                execute(
                    "systemctl",
                    &["--user", "stop", &format!("{}.service", job.id)],
                )?;
                remove_if_exists(&timer)?;
                remove_if_exists(&service)?;
                execute("systemctl", &["--user", "daemon-reload"])?;
            }
        }
        open_pact_core::Os::Windows => match action {
            RegistrationAction::Install(run_as) => {
                let args = job.schtasks_install(run_as);
                match run_as {
                    TaskRunAs::System => {
                        windows_powershell(&windows_clear_for_system_script(
                            job,
                            &crate::machine::machine_path(),
                        ))?;
                        let schtasks = crate::machine::system_schtasks();
                        execute(
                            &schtasks.to_string_lossy(),
                            &args.iter().map(String::as_str).collect::<Vec<_>>(),
                        )?;
                    }
                    // The check and the create run in one PowerShell call.
                    TaskRunAs::CurrentUser => {
                        windows_powershell(&windows_register_user_script(job, &args))?;
                    }
                }
            }
            RegistrationAction::Uninstall => {
                windows_uninstall(job, false, &crate::machine::machine_path())?;
            }
        },
    }
    Ok(())
}

fn validate_windows_home(home: &Path) -> Result<()> {
    if text(home)?.contains('%') {
        bail!("choose a home path without %");
    }
    Ok(())
}

/// A PowerShell string literal. It doubles the ASCII apostrophe and the four typographic single
/// quotes, which PowerShell reads as quote characters too. It is the one literal function of the
/// client.
pub(crate) fn powershell_literal(value: &str) -> String {
    let mut literal = String::from("'");
    for character in value.chars() {
        literal.push(character);
        if matches!(
            character,
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
        ) {
            literal.push(character);
        }
    }
    literal.push('\'');
    literal
}

pub(crate) fn windows_powershell(script: &str) -> Result<String> {
    let script =
        format!("[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false);\n{script}");
    let mut command = std::process::Command::new(crate::machine::system_powershell());
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script,
    ]);
    // A GUI caller has no console: without this flag each probe flashes a PowerShell window.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().context("start Windows scheduler helper")?;
    if !output.status.success() {
        bail!(
            "Windows scheduler helper failed with code {:?}; run from an elevated prompt. {} {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// The check that a path is protected: owned by SYSTEM, the administrators or TrustedInstaller, and
/// writable by none of the others. The machine client, its folder and Program Files pass it by
/// inheritance: it skips inherit-only rules.
pub(crate) const ASSERT_PROTECTED: &str = r#"$ErrorActionPreference = 'Stop'
function AssertProtected($path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected path is a reparse point' }
    $acl = if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($path) } else { [IO.File]::GetAccessControl($path) }
    $allowed = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw 'Protected path has a non-admin owner' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band 0xD0156) -and $allowed -notcontains $rule.IdentityReference.Value) {
            throw 'Protected path ACL grants write or modify to a non-admin principal'
        }
    }
}
"#;

/// The helpers that prepare the protected state folders. They call \`AssertProtected\`.
const PROTECTED_DIRECTORY: &str = r#"
function IsAdminOwner($owner) {
    if (@('S-1-5-18','S-1-5-32-544') -contains $owner) { return $true }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $identity.User.Value -eq $owner -and $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function ProtectedDirectory($path) {
    if (-not [IO.Directory]::Exists($path)) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        [void][IO.Directory]::CreateDirectory($path,$acl)
    }
    AssertProtected $path
}
function ResetSystemStateDirectory($path) {
    if (-not [IO.Directory]::Exists($path)) {
        ProtectedDirectory $path
        return
    }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected path is a reparse point' }
    $acl = [IO.Directory]::GetAccessControl($path)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not (IsAdminOwner $owner)) { throw 'Protected path has a non-admin owner' }
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    [IO.Directory]::SetAccessControl($path,$acl)
    AssertProtected $path
}
"#;

/// The job log of the SYSTEM job of `home`, in its protected state folder. It is computed from
/// `ProgramData` and the home, so no process starts and no elevation is needed to name it.
pub(crate) fn system_job_log_path(home: &Home) -> Result<PathBuf> {
    let absolute = schedule_home(&home.0, true)?;
    let program_data = std::env::var_os("ProgramData").context("ProgramData is not set")?;
    system_job_log_in(Path::new(&program_data), &absolute)
}

fn system_job_log_in(program_data: &Path, absolute: &Path) -> Result<PathBuf> {
    let hash = hex::encode(Sha256::digest(text(absolute)?.as_bytes()));
    Ok(program_data
        .join("open-pact")
        .join("system")
        .join(hash)
        .join(JOB_LOG))
}

/// Checks Program Files, the folder and the file of the machine client, and prepares the protected
/// state folder of the SYSTEM job. Returns the state folder.
fn windows_protected_paths(home: &Home, machine: &Path) -> Result<PathBuf> {
    let absolute = &home.0;
    validate_windows_home(absolute)?;
    let hash = hex::encode(Sha256::digest(text(absolute)?.as_bytes()));
    let script = windows_protected_paths_script(&hash, &powershell_literal(text(machine)?));
    let output = windows_powershell(&script)?;
    let mut lines = output.lines();
    let state = PathBuf::from(lines.next().context("protected state path missing")?);
    if lines.next().is_some() {
        bail!("unexpected protected path output");
    }
    Ok(state)
}

fn windows_protected_paths_script(hash: &str, machine: &str) -> String {
    format!(
        r#"{ASSERT_PROTECTED}{PROTECTED_DIRECTORY}
$machine = {machine}
$folder = Split-Path -Parent $machine
AssertProtected (Split-Path -Parent $folder)
AssertProtected $folder
AssertProtected $machine
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'open-pact'
ProtectedDirectory $data
$data = Join-Path $data 'system'
ProtectedDirectory $data
$data = Join-Path $data '{hash}'
ResetSystemStateDirectory $data
Write-Output $data
"#
    )
}

fn windows_task_query_script(job: &Job) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
function IsSystemTask($task) {{
    $user = [string]$task.Definition.Principal.UserId
    if (-not $user) {{ return $false }}
    return @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -contains $user.ToUpperInvariant()
}}
function NormalPath($value) {{
    $text = ([string]$value).Trim().Trim('"')
    if ($text.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {{ $text = $text.Substring(4) }}
    return $text
}}
function IsOurs($task, $machine) {{
    $actions = @($task.Definition.Actions)
    if ($actions.Count -ne 1 -or -not $machine) {{ return $false }}
    $path = [string]$actions[0].Path
    $arguments = [string]$actions[0].Arguments
    if ($path -match '[\x00-\x1f\x7f]' -or $arguments -match '[\x00-\x1f\x7f]') {{ return $false }}
    # One path rule for Rust and PowerShell (`same_windows_path`): a leading \\?\ and the case of
    # the letters do not tell two paths apart.
    return (NormalPath $path) -ieq (NormalPath $machine)
}}
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
try {{ $task = $folder.GetTask({id}) }} catch {{
    $failure = $_.Exception
    while ($null -ne $failure.InnerException) {{ $failure = $failure.InnerException }}
    if (($failure.HResult -band 0xffff) -ne 2) {{ throw }}
    $task = $null
}}
"#,
        id = powershell_literal(&job.id)
    )
}

fn windows_require_elevation_script() -> &'static str {
    r#"$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run `schedule on` or `schedule off` from an elevated prompt'
}"#
}

fn windows_require_elevation() -> Result<()> {
    windows_powershell(windows_require_elevation_script())?;
    Ok(())
}

/// The script that registers the task of `job` for the current user, with the `schtasks` `args`
/// that `schtasks_install` made. It queries the task again in this same call and stops at a SYSTEM
/// task, ours or not, before it creates anything: a user job never replaces a SYSTEM task, and an
/// elevated switch to user mode has removed the machine client's own task before it comes here.
/// `/Create /F` has no compare-and-create, so a SYSTEM task that an administrator adds between this
/// check and the create is the one race that stays. A command that a standard user runs cannot
/// replace a SYSTEM task in any case.
fn windows_register_user_script(job: &Job, args: &[String]) -> String {
    let query = windows_task_query_script(job);
    let line = args
        .iter()
        .map(|arg| windows_command_line_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"{query}
if ($null -ne $task -and (IsSystemTask $task)) {{ throw 'a SYSTEM task for this home exists, so a user job does not replace it. Run `schedule off` from an elevated prompt first' }}
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
$info.Arguments = {line}
$info.UseShellExecute = $false
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.CreateNoWindow = $true
$process = [Diagnostics.Process]::Start($info)
$printed = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
$process.WaitForExit()
if ($process.ExitCode -ne 0) {{ throw ('schtasks.exe failed with code ' + $process.ExitCode + ': ' + $printed.Trim()) }}
"#,
        line = powershell_literal(&line)
    )
}

/// The script that removes the task of `job`. It deletes a task only after it checked, in this same
/// call, that the task is a user's or the machine client's own: a SYSTEM task that does not run
/// `machine` alone is never deleted. Task Scheduler offers no compare-and-delete, so a task that an
/// administrator swaps between this check and `DeleteTask` is the one race that stays.
fn windows_uninstall_script(job: &Job, system: bool, machine: &Path) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{query}
$machine = {machine}
if ($null -ne $task -and (IsSystemTask $task)) {{
    if (-not {system}) {{ throw 'run `schedule on` or `schedule off` from an elevated prompt' }}
    if (-not (IsOurs $task $machine)) {{ throw 'a SYSTEM task for this home does not run the machine client alone, so open-pact does not change it' }}
}}
if ($null -ne $task) {{ $folder.DeleteTask({id},0) }}
try {{
    $task = $folder.GetTask({id})
}} catch {{
    $failure = $_.Exception
    while ($null -ne $failure.InnerException) {{ $failure = $failure.InnerException }}
    if (($failure.HResult -band 0xffff) -eq 2) {{ return }}
    throw
}}
throw 'scheduled task remains: {name}'
"#,
        system = if system { "$true" } else { "$false" },
        id = powershell_literal(&job.id),
        name = job.id,
        machine = powershell_literal(&machine.to_string_lossy()),
    )
}

/// The script that makes room for a new SYSTEM task: it deletes the task with this id when it is a
/// user's (a planted one) or the machine client's own, and stops when it is another SYSTEM task. The
/// install then creates the task without `/F`, so a task that appears after this check fails the
/// create. A replace in place would keep the security descriptor of a user's task, and the user
/// could still disable or delete the SYSTEM job. The same Task Scheduler race as above remains.
fn windows_clear_for_system_script(job: &Job, machine: &Path) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{query}
$machine = {machine}
if ($null -ne $task) {{
    if ((IsSystemTask $task) -and -not (IsOurs $task $machine)) {{ throw 'a SYSTEM task for this home does not run the machine client alone, so open-pact does not change it' }}
    $folder.DeleteTask({id},0)
}}
"#,
        id = powershell_literal(&job.id),
        machine = powershell_literal(&machine.to_string_lossy()),
    )
}

fn windows_end_task_script(job: &Job, enabled: bool, machine: &Path) -> String {
    let query = windows_task_query_script(job);
    let (note, stop) = if enabled {
        ("", "")
    } else {
        (
            "\n    Write-Output $(if ($task.Enabled) { 'enabled' } else { 'disabled' })",
            "\n    try { $task.Stop(0) } catch {}",
        )
    };
    format!(
        r#"{query}
$machine = {machine}
if ($null -ne $task -and (IsSystemTask $task) -and (IsOurs $task $machine)) {{{note}
    try {{ $task.Enabled = ${enabled} }} catch {{}}{stop}
}}
"#,
        machine = powershell_literal(&machine.to_string_lossy())
    )
}

/// Disables the SYSTEM task, so the scheduler starts no new tick, then ends a running tick so it
/// releases the state lock and the binary. A task that is not running, or cannot be changed, is
/// not an error: the lock wait decides. A task that is not the machine client's own is left alone,
/// checked in the same call. Returns whether the task was enabled before, so a failed removal does
/// not enable a task that the owner had disabled.
fn windows_end_task(job: &Job, machine: &Path) -> bool {
    windows_powershell(&windows_end_task_script(job, false, machine))
        .map_or(true, |output| output.trim() != "disabled")
}

/// Undoes `windows_end_task` when the removal did not finish and the task still exists.
fn windows_resume_task(job: &Job, machine: &Path) {
    let _ = windows_powershell(&windows_end_task_script(job, true, machine));
}

fn windows_uninstall(job: &Job, system: bool, machine: &Path) -> Result<()> {
    windows_powershell(&windows_uninstall_script(job, system, machine))
        .context("run `schedule on` or `schedule off` from an elevated prompt")?;
    Ok(())
}

fn windows_existing_system_state(home: &Path) -> Result<Option<PathBuf>> {
    validate_windows_home(home)?;
    let hash = hex::encode(Sha256::digest(text(home)?.as_bytes()));
    let output = windows_powershell(&windows_existing_system_state_script(&hash))?;
    Ok(if output.is_empty() {
        None
    } else {
        Some(PathBuf::from(output))
    })
}

fn windows_existing_system_state_script(hash: &str) -> String {
    format!(
        r#"{ASSERT_PROTECTED}
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'open-pact'
$system = Join-Path $data 'system'
$state = Join-Path $system '{hash}'
if (Test-Path -LiteralPath $state) {{
    AssertProtected $data
    AssertProtected $system
    AssertProtected $state
    Write-Output $state
}}
"#
    )
}

/// Set by the console handler while a `ConsoleInterruptHold` lives.
static CONSOLE_INTERRUPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The console handler of a `ConsoleInterruptHold`: it records Ctrl-C and Ctrl-Break and returns
/// TRUE, so the system does not end the process for them. A console close, a logoff and a shutdown
/// still end the process, whatever the handler returns.
#[cfg(windows)]
unsafe extern "system" fn hold_console_interrupt(_event: u32) -> i32 {
    CONSOLE_INTERRUPT.store(true, std::sync::atomic::Ordering::SeqCst);
    1
}

/// Keeps a console Ctrl-C from ending the process while it lives, and remembers that it came.
/// The PowerShell children run with `CREATE_NO_WINDOW`, so they have their own console and never
/// see the user's Ctrl-C. It does nothing outside Windows.
struct ConsoleInterruptHold;

/// Adds or removes `hold_console_interrupt` in the console handler list of the process.
#[cfg(windows)]
fn set_console_handler(add: bool) {
    // SAFETY: the handler is a `'static` function that only stores to an atomic.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(hold_console_interrupt),
            i32::from(add),
        );
    }
}

#[cfg(not(windows))]
fn set_console_handler(_add: bool) {}

impl ConsoleInterruptHold {
    fn new() -> Self {
        CONSOLE_INTERRUPT.store(false, std::sync::atomic::Ordering::SeqCst);
        set_console_handler(true);
        Self
    }

    fn interrupted(&self) -> bool {
        CONSOLE_INTERRUPT.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for ConsoleInterruptHold {
    fn drop(&mut self) {
        set_console_handler(false);
    }
}

/// A command that held off Ctrl-C ends as interrupted once it has restored the task state. The CLI
/// maps [`crate::Interrupted`] to exit code 130. The failure that the command had is printed first.
fn end_after_held_interrupt(interrupted: bool, result: Result<()>) -> Result<()> {
    if !interrupted {
        return result;
    }
    if let Err(error) = result {
        eprintln!("{error:#}");
    }
    Err(crate::Interrupted.into())
}

/// Runs the removal of a SYSTEM job under a held Ctrl-C. When the removal succeeds, the home files
/// go too, even after a Ctrl-C: the task is gone, so its leftovers must not stay. A failed removal
/// keeps the home files.
fn finish_system_removal(
    home: &Home,
    home_exists: bool,
    remove: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // Held until the task is resumed or removed: a Ctrl-C in the wait must not leave it disabled.
    let hold = ConsoleInterruptHold::new();
    let result = remove().and_then(|()| {
        if home_exists {
            remove_protected_home_schedule_files(home).map_err(|error| {
                anyhow::anyhow!(
                    "the SYSTEM task is already removed, but the home files were not all removed: {error:#}. Run `open-pact-client schedule off` again, with the same --home, to remove them."
                )
            })?;
        }
        Ok(())
    });
    let interrupted = hold.interrupted();
    drop(hold);
    end_after_held_interrupt(interrupted, result)
}

fn windows_system_uninstall_held(job: &Job, state: Option<PathBuf>, machine: &Path) -> Result<()> {
    let was_enabled = windows_end_task(job, machine);
    println!(
        "Waiting up to {} s for the running SYSTEM tick to end. Ctrl-C waits until the task state is restored.",
        SYSTEM_WAIT.as_secs()
    );
    let _state_lock = match state
        .as_ref()
        .map(|path| {
            retry_while_state_in_use(SYSTEM_WAIT, SYSTEM_WAIT_STEP, std::thread::sleep, || {
                lock_system_state(&Home(path.clone()))
            })
        })
        .transpose()
        .context("SYSTEM uninstall stopped before task or binary cleanup")
    {
        Ok(lock) => lock,
        Err(error) => {
            if was_enabled {
                windows_resume_task(job, machine);
            }
            return Err(error);
        }
    };
    let mut failures = Vec::new();
    if let Err(error) = windows_uninstall(job, true, machine) {
        failures.push(format!("task {}: {error:#}", job.id));
    }
    if let Some(state) = state
        && let Err(error) = remove_system_state_directory(&state)
    {
        failures.push(format!(
            "SYSTEM job state remains at {}: {error}",
            state.display()
        ));
    }
    if !failures.is_empty() {
        if was_enabled {
            windows_resume_task(job, machine);
        }
        bail!("SYSTEM cleanup incomplete:\n{}", failures.join("\n"));
    }
    Ok(())
}

fn validate_system_install(system: bool, os: open_pact_core::Os) -> Result<()> {
    if system && os != open_pact_core::Os::Windows {
        bail!("Running the job as SYSTEM is available only on Windows");
    }
    Ok(())
}

/// Where the device is now: on the VPN when the schedule has a probe and it answers.
async fn place(schedule: &Schedule, executable: &Path) -> Place {
    match schedule.probe() {
        Some(probe)
            if vpn_up(
                probe.address.as_str(),
                probe.name.as_ref().map(ProbeName::as_str),
                executable,
            )
            .await =>
        {
            Place::Vpn
        }
        _ => Place::Elsewhere,
    }
}

/// Whether the schedule lets the job send now. A schedule without a VPN part needs no probe.
async fn may_send(schedule: &Schedule, executable: &Path) -> bool {
    schedule.may_send(place(schedule, executable).await)
}

/// One scheduled run: note whether the policy lets the job send, collect the results, and send a
/// claim when a trigger is due and the policy still lets the job send.
pub(crate) async fn tick(
    home: &Home,
    state_home: &Home,
    user_home: Option<&Path>,
    authorization: &ScheduleAuthorization,
    executable: &Path,
    read_events: impl FnOnce() -> checks::EventMarkerReads,
) -> Result<()> {
    tick_with_scan(
        home,
        state_home,
        user_home,
        authorization,
        executable,
        read_events,
        claim::scan_if_due(home, user_home, REPO_SCAN_INTERVAL),
    )
    .await
}

/// The schedule and the owner's agreement to use the signed manifest's schedule.
#[derive(Clone)]
pub(crate) struct ScheduleAuthorization {
    pub(crate) manifest_hash: ManifestHash,
    pub(crate) schedule: open_pact_core::Schedule,
    pub(crate) owner_consented: bool,
    /// Whether a failing control whose grace ended deletes the VPN certificate. The job always
    /// does; a test turns it off where the machine's real check results must not matter.
    pub(crate) self_removal: bool,
}

pub(crate) async fn tick_with_scan(
    home: &Home,
    state_home: &Home,
    user_home: Option<&Path>,
    authorization: &ScheduleAuthorization,
    executable: &Path,
    read_events: impl FnOnce() -> checks::EventMarkerReads,
    scan: impl Future<Output = Result<()>>,
) -> Result<()> {
    let schedule = &authorization.schedule;
    let mut state: State = state_home.read_json(STATE)?.unwrap_or_default();
    let before = state.clone();
    let place = place(schedule, executable).await;
    state.observe(place == Place::Vpn);
    if state != before || !state_home.file(STATE).exists() {
        save(state_home, STATE, &state)?;
    }
    // A wake with nothing due ends here: no check, no scan, no gateway request.
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if plan(schedule, &state, place, now, check_floor_secs()).idle() {
        return Ok(());
    }
    // The scan can take long. It runs before the claim lock, which `check` and `accept` wait for.
    scan.await?;
    let Some(_claim_lock) = claim::try_lock(home)? else {
        return Ok(());
    };
    let config = DeviceConfig::load_or_migrate(home, user_home, false)?;
    let manifest = home.signed_manifest()?;
    // `accept` can replace the signed policy during the unlocked scan.
    if !authorization.owner_consented
        || authorization.owner_consented != config.auto_send
        || &authorization.manifest_hash != manifest.hash()
    {
        return Ok(());
    }
    let prepared = claim::prepare(
        home,
        user_home,
        ScanPolicy::OlderThan(REPO_SCAN_INTERVAL),
        false,
    )
    .await?;
    let events = read_events();
    let compliance = prepared.compliance().clone();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    state.last_check = Some(now);
    state.observe_compliance(&compliance);
    state.observe_failures(&compliance, now);
    state.event_pending |= state.new_events(events);
    if authorization.self_removal {
        let lapsed = lapsed_controls(&manifest, &compliance, prepared.results(), &state, now);
        if lapsed.is_empty() {
            state.removal_failed = false;
        } else {
            retire_certificate(home, state_home, &mut state, &lapsed)?;
        }
    }
    let due = plan(schedule, &state, place, now, check_floor_secs()).send;
    if let Some(trigger) = due {
        save(state_home, STATE, &state)?;
        let outcome = prepared
            .send(home, || may_send(schedule, executable))
            .await?;
        note_outcome(home, &mut state, trigger, &outcome);
        state.record(
            &outcome,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            events,
            compliance,
        );
    } else if !state.baseline().security_log_cleared || !state.baseline().antimalware_detection {
        state.establish_baseline(events);
    }
    save(state_home, STATE, &state)?;
    Ok(())
}

/// The controls that fail now and whose grace has ended on this device, so the gateway would deny
/// them too. Grace counts from the first check that saw the failure; `0d` ends at once, and a result
/// that cannot be read counts against `unknown_grace`.
fn lapsed_controls(
    manifest: &Manifest,
    compliance: &BTreeMap<String, bool>,
    results: &BTreeMap<String, open_pact_core::ControlValue>,
    state: &State,
    now: i64,
) -> Vec<String> {
    let body = manifest.body();
    compliance
        .iter()
        .filter(|(_, compliant)| !**compliant)
        .filter_map(|(id, _)| {
            let control = body.control(id)?;
            let unknown = results.get(id).is_none_or(|value| value == "unknown");
            let span = if unknown {
                &body.unknown_grace
            } else {
                &control.grace
            };
            let since = state.first_failed.get(id).copied().unwrap_or(now);
            let ended = span.is_zero()
                || span.min_duration().is_some_and(|length| {
                    time::Duration::seconds(now.saturating_sub(since)) > length
                });
            ended.then(|| id.clone())
        })
        .collect()
}

/// A control failed and its grace ended: the device stops being a good VPN client by itself. It
/// deletes the installed VPN certificate, writes one line to the job log, and asks for a claim at
/// once. A claim that the gateway accepts later installs a new certificate as always.
///
/// The claim is owed from the moment the deletion starts, so the pending claim is saved before the
/// first file goes: a crash after the deletion still leaves it for the next run, which sends it.
/// The save is skipped inside a run of failed removals, whose one claim was forced already.
fn retire_certificate(
    home: &Home,
    state_home: &Home,
    state: &mut State,
    lapsed: &[String],
) -> Result<()> {
    if home.vpn_removal_owed() && !state.removal_failed {
        state.event_pending = true;
        save(state_home, STATE, state)?;
    }
    let removal = home.remove_vpn_pair();
    if removal.is_ok() {
        state.removal_failed = false;
    }
    match removal {
        Ok(false) => {}
        Ok(true) => {
            job_log(
                home,
                &format!(
                    "Removed the VPN certificate: {} failed and its grace ended. A claim goes out at once.",
                    lapsed.join(", ")
                ),
            );
            state.event_pending = true;
        }
        Err(error) => {
            // The certificate may still work, so the gateway must hear of the failure now. One
            // forced claim per run of failures: a later check does not repeat it.
            if !state.removal_failed {
                state.event_pending = true;
                state.removal_failed = true;
            }
            let key = format!("removal failed {error:#}");
            if state.last_note.as_deref() != Some(key.as_str()) {
                job_log(
                    home,
                    &format!(
                        "Could not remove the VPN certificate after {} failed: {error:#}",
                        lapsed.join(", ")
                    ),
                );
                state.last_note = Some(key);
            }
        }
    }
    Ok(())
}

/// Tells the owner what only the owner can fix: a changed manifest, a denial, an alarm. Each piece
/// of news is written once, when it changes, and not on every run.
fn note_outcome(home: &Home, state: &mut State, trigger: Trigger, outcome: &Outcome) {
    let command = crate::client_command(&home.0);
    let changed =
        |hash: &open_pact_core::ManifestHash| crate::manifest_change_notice(hash, &command);
    let (key, lines) = match outcome {
        Outcome::Accepted { changed: None } => {
            state.last_note = None;
            return;
        }
        Outcome::Accepted {
            changed: Some(hash),
        } => (format!("changed {hash}"), vec![changed(hash)]),
        Outcome::Denied {
            reasons,
            changed: hash,
        } => {
            let mut key = format!("denied {}", reasons.join("; "));
            let mut lines = vec![format!(
                "The gateway denied the {} claim: {}. Run `{command} check` to see what to fix.",
                trigger.name(),
                reasons.join("; ")
            )];
            if let Some(hash) = hash {
                key.push_str(&format!(" changed {hash}"));
                lines.push(changed(hash));
            }
            (key, lines)
        }
        Outcome::NotSent(NotSent::AcceptPending(hash)) => {
            (format!("changed {hash}"), vec![changed(hash)])
        }
        Outcome::NotSent(NotSent::Pending) => (
            "pending".to_owned(),
            vec!["This device waits for IT approval. No claim was sent.".to_owned()],
        ),
        Outcome::NotSent(NotSent::Revoked) => (
            "revoked".to_owned(),
            vec!["IT revoked this device. No claim was sent.".to_owned()],
        ),
        Outcome::NotSent(NotSent::OffVpn) => return,
        Outcome::Alarm(text) => (
            format!("alarm {text}"),
            vec![format!(
                "TRANSPARENCY LOG ALARM: {text}. Run `{command} check` and tell IT. No VPN certificate was installed."
            )],
        ),
    };
    if state.last_note.as_deref() == Some(key.as_str()) {
        return;
    }
    for line in lines {
        job_log(home, &line);
    }
    state.last_note = Some(key);
}

/// Appends a dated line to the job log. The log keeps the last two files of at most
/// `JOB_LOG_LIMIT` bytes each. A failed write is only reported: it must not stop the job.
/// A SYSTEM job writes it to its protected state folder, never to the home the user controls.
pub(crate) fn job_log(home: &Home, line: &str) {
    write_job_log(&Home(crate::home_fs::job_log_home(&home.0)), line);
}

/// `job_log` into the folder `log`.
fn write_job_log(log: &Home, line: &str) {
    if let Err(error) = append_job_log(log, line) {
        eprintln!(
            "warning: could not write {}: {error}",
            log.file(JOB_LOG).display()
        );
    }
}

/// Moves a job log of `JOB_LOG_LIMIT` bytes or more to `schedule.log.1`, which replaces the older
/// copy. The OS appends the job's output to the log too, and only the job can bound that.
fn rotate_job_log(home: &Home) -> std::io::Result<()> {
    let path = home.file(JOB_LOG);
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= JOB_LOG_LIMIT) {
        std::fs::rename(&path, home.file("schedule.log.1"))?;
    }
    Ok(())
}

fn append_job_log(home: &Home, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let path = home.file(JOB_LOG);
    rotate_job_log(home)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    writeln!(
        options.open(&path)?,
        "{} {line}",
        open_pact_core::timestamp::rfc3339_secs(time::OffsetDateTime::now_utc())
    )
}

pub(crate) const APPLIED: &str = "schedule-applied.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Applied {
    run_as: RunAs,
    executable: PathBuf,
    /// The profile a SYSTEM job reads. Only a SYSTEM job has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_home: Option<PathBuf>,
}

impl Applied {
    /// Whether `other` asks for the same job. A SYSTEM job runs the machine client, so its action
    /// path comes from observation and the receipt compares only who runs it and whose profile it reads.
    fn same_intent(&self, other: &Self) -> bool {
        self.run_as == other.run_as
            && self.user_home == other.user_home
            && (self.run_as == RunAs::System || self.executable == other.executable)
    }
}

/// What `schedule-applied.json` records. A file an earlier client wrote has another shape and
/// reads as nothing, so `schedule on` replaces the job.
fn read_applied(home: &Home) -> Result<Option<Applied>> {
    let path = home.file(APPLIED);
    let Some(text) = read_text_if_exists(&path)? else {
        return Ok(None);
    };
    Ok(serde_json::from_str(&text).ok())
}

#[derive(Debug, Default)]
struct Observed {
    exists: bool,
    matches: bool,
    system: bool,
    leftovers: bool,
    protected_leftovers: bool,
    windows_task: Option<WindowsTaskState>,
}

/// What Task Scheduler says about a Windows task.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WindowsTaskState {
    enabled: bool,
    triggers: usize,
    trigger_enabled: bool,
    trigger_type: Option<i32>,
    /// The repeat interval of the trigger, as Task Scheduler writes it (such as `PT1M`).
    repetition: Option<String>,
    actions: Vec<ObservedAction>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ObservedAction {
    path: String,
    args: String,
}

impl WindowsTaskState {
    /// The task is enabled and wakes every minute: one enabled trigger of the right type and
    /// interval.
    fn shape_matches(&self) -> bool {
        self.enabled
            && self.triggers == 1
            && self.trigger_enabled
            && self.trigger_type == Some(1)
            && self.repetition.as_deref() == Some(WAKE_ISO)
    }
}

/// What a SYSTEM-mode look at a task finds. Only a task whose principal is SYSTEM is ever `NotOurs`
/// or reads as ours: a task with the id that runs as a user is a user job.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SystemTask {
    Missing,
    User,
    /// A SYSTEM task whose actions are not the machine client alone.
    NotOurs {
        action: String,
    },
    /// A SYSTEM task whose one action is the machine client. `profile` is the valid `--user-home` the
    /// task carries.
    Ours {
        profile: Option<PathBuf>,
        current: bool,
    },
}

impl Observed {
    /// Classifies the observed task against the machine client at `machine`. `fallback` is the
    /// profile to expect when the task carries no valid one.
    fn system_task(&self, machine: &Path, home: &Path, fallback: Option<&Path>) -> SystemTask {
        if !self.exists {
            return SystemTask::Missing;
        }
        if !self.system {
            return SystemTask::User;
        }
        let task = self.windows_task.as_ref();
        let actions = task.map_or(&[][..], |task| task.actions.as_slice());
        let [action] = actions else {
            return SystemTask::NotOurs {
                action: describe_actions(actions),
            };
        };
        // An empty machine path equals an empty action path, and a control character can hide
        // text from the one who reads it: neither is ever ours.
        if machine.as_os_str().is_empty()
            || action.path.chars().any(char::is_control)
            || action.args.chars().any(char::is_control)
            || !same_windows_path(Path::new(unquote(&action.path)), machine)
        {
            return SystemTask::NotOurs {
                action: describe_actions(actions),
            };
        }
        let profile = task_user_home(&action.args)
            .and_then(|value| crate::machine::validate_user_home(Path::new(&value)).ok());
        let expected = profile.as_deref().or(fallback);
        let current = task.is_some_and(WindowsTaskState::shape_matches)
            && expected
                .and_then(|profile| system_arguments(machine, home, profile).ok())
                .is_some_and(|expected| arguments_match(&action.args, &expected));
        SystemTask::Ours { profile, current }
    }
}

/// Whether the arguments of a task are the ones that `expected` names. The words compare exactly,
/// because the command line parser of the client is case sensitive (`schedule RUN` is an error).
/// Only a path, the word after `--home` or `--user-home`, ignores case, as a Windows path does.
fn arguments_match(actual: &str, expected: &str) -> bool {
    let actual = split_windows_args(actual);
    let expected = split_windows_args(expected);
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(&expected)
            .enumerate()
            .all(|(at, (left, right))| {
                let is_path =
                    at > 0 && matches!(expected[at - 1].as_str(), "--home" | "--user-home");
                if is_path {
                    same_windows_path(Path::new(left), Path::new(right))
                } else {
                    left == right
                }
            })
}

fn unquote(path: &str) -> &str {
    let path = path.trim();
    path.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(path)
}

/// The programs of the actions, as a text for a person. A control character shows as `?`, so a task
/// cannot hide or fake a line of the text.
fn describe_actions(actions: &[ObservedAction]) -> String {
    if actions.is_empty() {
        return "no program".into();
    }
    actions
        .iter()
        .map(|action| unquote(&action.path))
        .collect::<Vec<_>>()
        .join(", ")
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

/// The arguments that `schtasks /TR` stores for the SYSTEM task of `home` that runs `machine`.
fn system_arguments(machine: &Path, home: &Path, profile: &Path) -> Result<String> {
    Ok(windows_task_arguments(
        &Job::new(machine, home)?.for_system(profile)?,
    ))
}

/// The command line after the program, as `schtasks /TR` stores it.
fn windows_task_arguments(job: &Job) -> String {
    job.argv
        .iter()
        .skip(1)
        .map(|arg| windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The words of a Windows command line, by the rules of `CommandLineToArgvW`.
fn split_windows_args(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut args = Vec::new();
    let mut at = 0;
    loop {
        while at < chars.len() && matches!(chars[at], ' ' | '\t') {
            at += 1;
        }
        if at >= chars.len() {
            return args;
        }
        let mut arg = String::new();
        let mut quoted = false;
        loop {
            let mut slashes = 0;
            while at < chars.len() && chars[at] == '\\' {
                slashes += 1;
                at += 1;
            }
            if at < chars.len() && chars[at] == '"' {
                arg.push_str(&"\\".repeat(slashes / 2));
                if slashes % 2 == 1 {
                    arg.push('"');
                } else {
                    quoted = !quoted;
                }
                at += 1;
            } else {
                arg.push_str(&"\\".repeat(slashes));
                if at >= chars.len() || (!quoted && matches!(chars[at], ' ' | '\t')) {
                    break;
                }
                arg.push(chars[at]);
                at += 1;
            }
        }
        args.push(arg);
    }
}

/// The value after `--user-home` in the arguments of a task.
fn task_user_home(args: &str) -> Option<String> {
    let words = split_windows_args(args);
    let at = words.iter().position(|word| word == "--user-home")?;
    words.get(at + 1).cloned()
}

/// What the observation script printed about one task: one JSON object. Every string of the task
/// is a JSON string, so no text of the task can pass for a field.
struct ParsedTask {
    exists: bool,
    system: bool,
    task: Option<WindowsTaskState>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskJson {
    exists: bool,
    principal: Option<String>,
    enabled: Option<bool>,
    triggers: Option<usize>,
    trigger_enabled: Option<bool>,
    trigger_type: Option<i32>,
    repetition: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    actions: Vec<ActionJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionJson {
    path: String,
    args: String,
}

/// PowerShell 5.1 writes an array of one as the item itself in some shapes, and nothing as `null`.
fn one_or_many<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shape<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<Shape<T>>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(Shape::Many(items)) => items,
        Some(Shape::One(item)) => vec![item],
    })
}

/// Reads the observation. An answer that is not one complete object is an error, never a guess.
fn parse_windows_task(output: &str) -> Result<ParsedTask> {
    let json: TaskJson = serde_json::from_str(output.trim())
        .context("Task Scheduler gave an answer that is not one JSON object")?;
    if !json.exists {
        return Ok(ParsedTask {
            exists: false,
            system: false,
            task: None,
        });
    }
    let system = match json.principal.as_deref() {
        Some("system") => true,
        Some("user") => false,
        _ => bail!("Task Scheduler did not say who runs the task"),
    };
    let (Some(enabled), Some(triggers), Some(trigger_enabled)) =
        (json.enabled, json.triggers, json.trigger_enabled)
    else {
        bail!("Task Scheduler gave an incomplete answer about the task");
    };
    Ok(ParsedTask {
        exists: true,
        system,
        task: Some(WindowsTaskState {
            enabled,
            triggers,
            trigger_enabled,
            trigger_type: json.trigger_type,
            repetition: json.repetition,
            actions: json
                .actions
                .into_iter()
                .map(|action| ObservedAction {
                    path: action.path,
                    args: action.args,
                })
                .collect(),
        }),
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Change {
    Install,
    Update,
    Remove,
    None,
}

fn reconcile(desired: Option<&Applied>, applied: Option<&Applied>, observed: &Observed) -> Change {
    match desired {
        Some(_) if !observed.exists => Change::Install,
        Some(desired)
            if applied.is_none_or(|applied| !desired.same_intent(applied))
                || !observed.matches
                || observed
                    .windows_task
                    .as_ref()
                    .is_some_and(|task| !task.shape_matches()) =>
        {
            Change::Update
        }
        Some(_) => Change::None,
        None if observed.exists || observed.leftovers || applied.is_some() => Change::Remove,
        None => Change::None,
    }
}

fn read_text_if_exists(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn windows_observation_script(job: &Job) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{query}
if ($null -eq $task) {{ Write-Output '{{"exists":false}}'; return }}
$triggers = @($task.Definition.Triggers)
$trigger = if ($triggers.Count -eq 1) {{ $triggers[0] }} else {{ $null }}
$actions = @($task.Definition.Actions | ForEach-Object {{ [ordered]@{{ path = [string]$_.Path; args = [string]$_.Arguments }} }})
$observation = [ordered]@{{
    exists = $true
    principal = $(if (IsSystemTask $task) {{ 'system' }} else {{ 'user' }})
    enabled = [bool]$task.Enabled
    triggers = $triggers.Count
    trigger_enabled = $(if ($trigger) {{ [bool]$trigger.Enabled }} else {{ $false }})
    trigger_type = $(if ($trigger) {{ [int]$trigger.Type }} else {{ $null }})
    repetition = $(if ($trigger) {{ [string]$trigger.Repetition.Interval }} else {{ $null }})
    actions = $actions
}}
Write-Output ($observation | ConvertTo-Json -Compress -Depth 4)
"#
    )
}

fn observe(
    home: &Home,
    desired: Option<&Applied>,
    inspect_protected: bool,
    current_executable: &Path,
) -> Result<Observed> {
    let executable = desired
        .map(|settings| settings.executable.clone())
        .unwrap_or_else(|| current_executable.to_path_buf());
    let mut job = Job::new(&executable, &home.0)?;
    if let Some(settings) = desired
        && settings.run_as == RunAs::System
        && let Some(user_home) = settings.user_home.as_deref()
    {
        job = job.for_system(user_home)?;
    }
    let leftovers = home_schedule_has_leftovers(home);
    Ok(match crate::current_os()? {
        open_pact_core::Os::Macos => {
            let path = user_home()?
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", job.id));
            let stored = read_text_if_exists(&path)?;
            let target = format!("{}/{}", launch_domain()?, job.id);
            let loaded = std::process::Command::new("launchctl")
                .args(["print", &target])
                .output()?
                .status
                .success();
            Observed {
                exists: stored.is_some() || loaded,
                matches: stored.as_deref() == Some(job.plist().as_str()) && loaded,
                leftovers,
                system: false,
                protected_leftovers: false,
                windows_task: None,
            }
        }
        open_pact_core::Os::Linux => {
            let dir = systemd_dir()?;
            let service = read_text_if_exists(&dir.join(format!("{}.service", job.id)))?;
            let timer = read_text_if_exists(&dir.join(format!("{}.timer", job.id)))?;
            let timer_name = format!("{}.timer", job.id);
            let active = systemd_status(&timer_name, "is-active")?;
            let enabled = systemd_status(&timer_name, "is-enabled")?;
            Observed {
                exists: service.is_some() || timer.is_some() || active || enabled,
                matches: service.as_deref() == Some(job.service().as_str())
                    && timer.as_deref() == Some(job.timer().as_str())
                    && active
                    && enabled,
                leftovers,
                system: false,
                protected_leftovers: false,
                windows_task: None,
            }
        }
        open_pact_core::Os::Windows => {
            let expected_args = windows_task_arguments(&job);
            let output = windows_powershell(&windows_observation_script(&job))?;
            let parsed = parse_windows_task(&output)?;
            let wants_system = desired.is_some_and(|settings| settings.run_as == RunAs::System);
            let runs_expected = parsed.task.as_ref().is_some_and(|task| {
                task.shape_matches()
                    && task.actions.len() == 1
                    && observed_action_matches(
                        &task.actions[0],
                        &executable.to_string_lossy(),
                        &expected_args,
                    )
            });
            let matches = if wants_system {
                parsed.system
                    && desired.is_some_and(|settings| settings.user_home.is_some())
                    && runs_expected
            } else {
                runs_expected && !parsed.system
            };
            let protected_leftovers =
                inspect_protected && windows_existing_system_state(&home.0)?.is_some();
            Observed {
                exists: parsed.exists,
                matches,
                system: parsed.system,
                leftovers: leftovers || protected_leftovers,
                protected_leftovers,
                windows_task: parsed.task,
            }
        }
    })
}

/// Task Scheduler stores the command exactly as `schtasks /TR` got it, so the program comes back
/// with its quotes (`"C:\\client.exe"`). The paths of Windows ignore case.
fn observed_action_matches(action: &ObservedAction, executable: &str, expected_args: &str) -> bool {
    same_windows_path(Path::new(unquote(&action.path)), Path::new(executable))
        && arguments_match(&action.args, expected_args)
}

/// The exact command that makes `change` (such as `schedule off`) from an elevated prompt.
pub(crate) fn apply_command(home: &Path, change: &str, executable: &Path) -> String {
    #[cfg(windows)]
    {
        format!(
            "& {} --home {} {change}",
            powershell_literal(&executable.to_string_lossy()),
            powershell_literal(&home.to_string_lossy())
        )
    }
    #[cfg(not(windows))]
    {
        let _ = executable;
        format!(
            "open-pact-client --home '{}' {change}",
            home.to_string_lossy().replace('\'', "'\"'\"'")
        )
    }
}

fn needs_system_cleanup(requested_system: bool, removing: bool, observed: &Observed) -> bool {
    requested_system || observed.system || (removing && observed.protected_leftovers)
}

/// What the owner wants the job to be.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Wanted {
    On(RunAs),
    Off,
}

impl Wanted {
    /// The command that repeats this change from an elevated prompt.
    fn command(self) -> &'static str {
        match self {
            Wanted::On(RunAs::System) => "schedule on --system",
            Wanted::On(RunAs::User) => "schedule on --user",
            Wanted::Off => "schedule off",
        }
    }
}

/// The profile that a SYSTEM job reads. The `--user-home` argument wins and must be valid. Else
/// the valid value of the machine client's own task for this home. Else the profile of the account
/// that owns this process (`own`, from its token SID), which must be valid too. The receipt is no
/// source: a user can write it, and so is `USERPROFILE`.
fn choose_profile(
    argument: Option<&Path>,
    task: Option<&Path>,
    own: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(argument) = argument {
        return crate::machine::validate_user_home(argument).context("--user-home is not usable");
    }
    if let Some(task) = task {
        return Ok(task.to_path_buf());
    }
    let profile = own.context(
        "Windows lists no profile for this account; a SYSTEM job needs the profile whose repositories it scans. Pass --user-home",
    )?;
    crate::machine::validate_user_home(&profile)
        .context("the profile of this account is not usable. Pass --user-home")
}

/// What the job should be when `wanted` is on: it runs `executable`, the installed client, and
/// never the program that asks for the change. For a SYSTEM job `executable` is the machine client
/// and `profile` the profile it reads. Nothing when `wanted` is off.
fn desired_job(
    wanted: Wanted,
    executable: &Path,
    profile: Option<PathBuf>,
) -> Result<Option<Applied>> {
    let Wanted::On(run_as) = wanted else {
        return Ok(None);
    };
    if executable.as_os_str().is_empty() {
        bail!("cannot find the path of this program, so the job cannot be installed");
    }
    Ok(Some(Applied {
        run_as,
        executable: executable.to_path_buf(),
        user_home: (run_as == RunAs::System).then_some(profile).flatten(),
    }))
}

/// What to run when a SYSTEM job needs an elevated prompt. For `schedule on --system` it is the
/// machine client's command, with the install block first when the machine client is not there.
/// For a SYSTEM task found during a removal or a user switch it is `schedule off` through the
/// machine client, or the removal block when the machine client is not usable.
///
/// The machine client appears in a line that an administrator runs only when the protection check
/// passed, or after an install block that puts a verified one in place. Else the text is the fix
/// for the package alone.
fn system_retry_text(
    home: &Path,
    wanted: Wanted,
    machine_client: &MachineClient,
    profile: Option<&Path>,
    ours: bool,
) -> String {
    let machine = crate::machine::machine_path();
    let running = crate::machine::running_version();
    let state = crate::machine::machine_state(machine_client, &running);
    match wanted {
        Wanted::On(RunAs::System) => {
            let command =
                crate::machine::machine_command(home, wanted.command(), &machine, profile);
            match crate::machine::machine_fix(machine_client, state, &machine, &running) {
                _ if state.usable() => command,
                Some(fix) if state.usable_after_fix() => format!("{fix}\nThen run:\n{command}"),
                Some(fix) => fix,
                None => command,
            }
        }
        Wanted::On(RunAs::User) | Wanted::Off => {
            if state.usable() {
                crate::machine::machine_command(home, "schedule off", &machine, None)
            } else if wanted == Wanted::Off && ours {
                // Only a removal of a task that inspection found to be the machine client's own
                // gets the block. Else the owner has no task to remove, or a task of another
                // kind, and a block that removes it would be the wrong advice.
                os_job_id(home).map_or_else(
                    |error| format!("{error:#}"),
                    |id| crate::machine::removal_block(home, &id, None),
                )
            } else {
                crate::machine::machine_fix(machine_client, state, &machine, &running)
                    .unwrap_or_else(|| "The machine client cannot be used.".into())
            }
        }
    }
}

/// The refusal for a SYSTEM task that does not run the machine client alone. open-pact never
/// changes it: the owner removes it with Windows tools, and then installs the machine client's job.
///
/// `profile` is the `--user-home` that the owner gave and that passed validation: the retry keeps
/// it, so the job still scans the profile that was asked for.
fn not_ours_text(
    home: &Path,
    wanted: Wanted,
    action: &str,
    machine_client: &MachineClient,
    profile: Option<&Path>,
) -> String {
    let machine = crate::machine::machine_path();
    let running = crate::machine::running_version();
    let state = crate::machine::machine_state(machine_client, &running);
    let id = task_id(home).unwrap_or_default();
    let mut text = format!(
        "A SYSTEM task {id} for this home runs {action}, not the machine client at {}. open-pact does not change it.\nRemove it from an elevated PowerShell prompt:\n{}",
        machine.display(),
        crate::machine::removal_block(home, &id, state.usable().then_some(machine.as_path()))
    );
    if wanted == Wanted::On(RunAs::System) {
        if let Some(fix) = crate::machine::machine_fix(machine_client, state, &machine, &running)
            && !state.usable()
        {
            text.push_str(&format!(
                "\nThen install or repair the machine client:\n{fix}"
            ));
        }
        if state.usable_after_fix() {
            text.push_str(&format!(
                "\nThen run:\n{}",
                crate::machine::machine_command(home, wanted.command(), &machine, profile)
            ));
        }
    }
    text
}

/// Refuses a change to a SYSTEM task that the machine client does not own.
fn refuse_not_ours(
    home: &Path,
    wanted: Wanted,
    task: &SystemTask,
    profile: Option<&Path>,
) -> Result<()> {
    if let SystemTask::NotOurs { action } = task {
        bail!(
            "{}",
            not_ours_text(
                home,
                wanted,
                action,
                &crate::machine::read_machine_client(),
                profile
            )
        );
    }
    Ok(())
}

/// The id of the OS job of `home`, through the one canonical home that install hashes. A text that
/// names the job of a home as the owner spelled it would name another job where the spellings differ.
fn os_job_id(home: &Path) -> Result<String> {
    task_id(&schedule_home(home, true)?)
}

/// What to tell the owner when the OS job could not be queried: the query error and the platform's
/// own step to look at the job. The state of the job is unknown, so the text never says to stop or
/// remove it, never names the program that was started (a copy that a user can write), and never
/// shows a command of another platform. On Windows a SYSTEM install runs the machine client when
/// it passed its protection check, else the step is the package fix first. Any other change reads
/// the job through a read-only Task Scheduler query and needs no package.
fn inspect_failure_text(
    home: &Path,
    os: open_pact_core::Os,
    machine_client: &MachineClient,
    system_install: bool,
    error: &anyhow::Error,
) -> String {
    let id = os_job_id(home).unwrap_or_default();
    let step = match os {
        open_pact_core::Os::Windows if !system_install => format!(
            "Look at the job from PowerShell:\nGet-ScheduledTask -TaskName '{id}' | Get-ScheduledTaskInfo"
        ),
        open_pact_core::Os::Windows => {
            let machine = crate::machine::machine_path();
            let running = crate::machine::running_version();
            let state = crate::machine::machine_state(machine_client, &running);
            let command = crate::machine::machine_command(home, "schedule status", &machine, None);
            match crate::machine::machine_fix(machine_client, state, &machine, &running) {
                _ if state.usable() => {
                    format!(
                        "If access is denied, run this from an elevated PowerShell prompt to read the job:\n{command}"
                    )
                }
                Some(fix) if state.usable_after_fix() => format!(
                    "Install the machine client first:\n{fix}\nThen run this from an elevated PowerShell prompt to read the job:\n{command}"
                ),
                Some(fix) => fix,
                None => command,
            }
        }
        open_pact_core::Os::Macos => {
            format!("Look at the job with:\nlaunchctl print gui/$(id -u)/{id}")
        }
        open_pact_core::Os::Linux => {
            format!("Look at the job with:\nsystemctl --user status {id}.timer")
        }
    };
    format!(
        "Cannot inspect the scheduled job: {error:#}\nThe state of the job is unknown, so open-pact changed nothing.\n{step}"
    )
}

/// The validated `--user-home`, and the validated profile that a printed command carries: that one
/// or else the profile of this account. Only a SYSTEM install needs either, and the profile list
/// costs a start of PowerShell on Windows, so every other change gets none and reads no list.
fn printable_profiles(
    requested_system: bool,
    user_home: Option<&Path>,
) -> (Option<PathBuf>, Option<PathBuf>) {
    if !requested_system {
        return (None, None);
    }
    let valid = |path: &Path| crate::machine::validate_user_home(path).ok();
    let explicit = user_home.and_then(valid);
    let caller = user_home
        .map(Path::to_path_buf)
        .or_else(crate::machine::default_user_home)
        .and_then(|path| valid(&path));
    (explicit, caller)
}

/// Installs, updates or removes the OS job so it matches `wanted`. A SYSTEM job runs the machine
/// client and nothing else: `schedule on --system` refuses when it is missing or unprotected, and
/// no change touches a SYSTEM task that is not the machine client's. `user_home` is the profile a
/// SYSTEM job reads, from `--user-home`.
pub(crate) async fn change_job(
    home: &Home,
    wanted: Wanted,
    dry_run: bool,
    executable: &Path,
    user_home: Option<&Path>,
) -> Result<()> {
    let home_exists = home.0.try_exists()?;
    let requested_system = wanted == Wanted::On(RunAs::System);
    if user_home.is_some() && !requested_system {
        bail!("--user-home needs --system");
    }
    let given = home.0.clone();
    let home = Home(schedule_home(&home.0, true)?);
    let machine = crate::machine::machine_path();
    // The package check needs no elevation, so it comes first.
    let machine_client = requested_system.then(crate::machine::read_machine_client);
    if let Some(machine_client) = &machine_client
        && !matches!(machine_client, MachineClient::Present { .. })
    {
        let running = crate::machine::running_version();
        let state = crate::machine::machine_state(machine_client, &running);
        bail!(
            "{}",
            crate::machine::machine_fix(machine_client, state, &machine, &running)
                .unwrap_or_else(|| "The machine client cannot be used.".into())
        );
    }
    let elevated = crate::current_os()? == open_pact_core::Os::Windows
        && crate::DeviceKey::process_is_elevated();
    if elevated {
        // Resolving the home replaced the path that was given with the link target, so the link
        // check runs here, before any file of the home is locked, read or written.
        require_home_without_link(&given, &home.0)?;
    }
    // Only a SYSTEM install needs a profile, and the profile list costs a start of PowerShell on
    // Windows, so every other command skips it. Only a validated profile reaches a printed command.
    let (explicit_profile, caller_profile) = printable_profiles(requested_system, user_home);
    if let Some(machine_client) = &machine_client
        && !elevated
    {
        bail!(
            "Run this exact command from an elevated PowerShell prompt:\n{}",
            system_retry_text(
                &home.0,
                wanted,
                machine_client,
                caller_profile.as_deref(),
                false,
            )
        );
    }
    // The first look finds who owns the task and which profile it carries. Its expected
    // arguments use the profile that is known so far.
    let provisional = desired_job(
        wanted,
        if requested_system {
            &machine
        } else {
            executable
        },
        explicit_profile.clone().or_else(|| {
            requested_system
                .then(crate::machine::default_user_home)
                .flatten()
                .and_then(|path| crate::machine::validate_user_home(&path).ok())
        }),
    )?;
    let observed = observe(&home, provisional.as_ref(), elevated, executable).map_err(|error| {
        let Ok(os) = crate::current_os() else {
            return error;
        };
        // Only a SYSTEM install reads the package, so a user job or a removal starts no probe.
        let machine_client = machine_client.clone().unwrap_or(MachineClient::Missing);
        anyhow::anyhow!(inspect_failure_text(
            &home.0,
            os,
            &machine_client,
            requested_system,
            &error
        ))
    })?;
    let task = observed.system_task(&machine, &home.0, None);
    refuse_not_ours(&home.0, wanted, &task, explicit_profile.as_deref())?;
    let system = needs_system_cleanup(requested_system, wanted == Wanted::Off, &observed);
    if system && !elevated {
        bail!(
            "Run this exact command from an elevated PowerShell prompt:\n{}",
            system_retry_text(
                &home.0,
                wanted,
                &crate::machine::read_machine_client(),
                explicit_profile.as_deref(),
                matches!(task, SystemTask::Ours { .. }),
            )
        );
    }
    let profile = if requested_system {
        let from_task = match &task {
            SystemTask::Ours { profile, .. } => profile.as_deref(),
            _ => None,
        };
        Some(choose_profile(
            user_home,
            from_task,
            crate::machine::default_user_home(),
        )?)
    } else {
        None
    };
    let desired = desired_job(
        wanted,
        if requested_system {
            &machine
        } else {
            executable
        },
        profile,
    )?;
    if let Some(Applied {
        user_home: Some(profile),
        ..
    }) = &desired
    {
        println!("The job scans {}.", profile.display());
    }
    let _lock = if dry_run || !home_exists {
        None
    } else {
        Some(lock(&home)?)
    };
    let observed = observe(&home, desired.as_ref(), elevated, executable)?;
    refuse_not_ours(
        &home.0,
        wanted,
        &observed.system_task(&machine, &home.0, None),
        explicit_profile.as_deref(),
    )?;
    let applied = read_applied(&home)?;
    let change = reconcile(desired.as_ref(), applied.as_ref(), &observed);
    match change {
        Change::None => println!("no changes"),
        Change::Install => println!("schedule: install"),
        Change::Update => println!("schedule: update"),
        Change::Remove => println!("schedule: remove"),
    }
    if dry_run {
        return Ok(());
    }
    match change {
        Change::Install | Change::Update => {
            let desired = desired.as_ref().unwrap();
            if observed.system && desired.run_as == RunAs::User {
                operate(
                    &home,
                    Operation::Uninstall { system: true },
                    true,
                    executable,
                    &machine,
                )
                .await?;
            }
            operate(
                &home,
                Operation::Install {
                    system: desired.run_as == RunAs::System,
                    user_home: desired.user_home.clone(),
                    keep_state: change == Change::Update,
                },
                true,
                executable,
                &machine,
            )
            .await?;
            save(&home, APPLIED, desired)?;
        }
        Change::Remove => {
            operate(
                &home,
                Operation::Uninstall { system },
                true,
                executable,
                &machine,
            )
            .await?;
            remove_if_exists(&home.file(APPLIED))?;
        }
        // A receipt that differs from what the job is now (a stale path from an older client, or
        // a failed save after a rewrite) converges here.
        Change::None => {
            if let Some(desired) = desired.as_ref()
                && applied.as_ref() != Some(desired)
            {
                save(&home, APPLIED, desired)?;
            }
        }
    }
    Ok(())
}

/// `schedule on`: needs a manifest that defines automatic sending.
pub(crate) async fn turn_on(
    home: &Home,
    run_as: Option<RunAs>,
    dry_run: bool,
    executable: &Path,
    user_home: Option<&Path>,
) -> Result<()> {
    let manifest = home.signed_manifest()?;
    let Some(schedule) = &manifest.body().schedule else {
        bail!(
            "The company did not define automatic sending in the manifest you signed, so the job cannot be turned on. Run `{} check` to send a claim by hand.",
            crate::client_command(&home.0)
        );
    };
    let mut config = DeviceConfig::load_or_migrate(home, crate::user_profile().as_deref(), false)?;
    let run_as = run_as.unwrap_or(config.run_as);
    validate_system_install(run_as == RunAs::System, crate::current_os()?)?;
    println!("{schedule}");
    change_job(home, Wanted::On(run_as), dry_run, executable, user_home).await?;
    if !dry_run {
        let _claim_lock = claim::lock(home).await?;
        config = DeviceConfig::load_or_migrate(home, crate::user_profile().as_deref(), true)?;
        config.auto_send = true;
        config.run_as = run_as;
        config.system_job_pending = false;
        config.save(home)?;
        println!("Your choice: automatic sending is on.");
    }
    Ok(())
}

/// `schedule off`: removes the job and remembers the owner's no.
pub(crate) async fn turn_off(home: &Home, dry_run: bool, executable: &Path) -> Result<()> {
    change_job(home, Wanted::Off, dry_run, executable, None).await?;
    if !dry_run && home.0.is_dir() {
        let _claim_lock = claim::lock(home).await?;
        let mut config = DeviceConfig::load(home)?;
        if config.auto_send || config.system_job_pending {
            config.auto_send = false;
            config.system_job_pending = false;
            config.save(home)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Current,
    Missing,
    Outdated,
    Leftover,
    Absent,
    SystemUnconfirmed,
    /// A SYSTEM task for this home that does not run the machine client alone. open-pact never
    /// changes it.
    NotOurs,
}

/// What a look at the OS job found. A SYSTEM job also carries what is known about the machine
/// client, which is a fact of its own: the package and the task each have their own fix.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct JobInspection {
    pub(crate) job: JobStatus,
    system: Option<SystemInspection>,
}

#[derive(Clone, Debug, PartialEq)]
struct SystemInspection {
    machine: MachineClient,
    machine_state: MachineState,
    /// The task, when an elevated process looked at it. A standard user cannot confirm it.
    task: Option<SystemTask>,
    /// The executable the receipt names. A user can write the receipt, so it is a hint only.
    receipt: Option<PathBuf>,
    task_id: String,
    /// Why an elevated process could not read the task, when it tried. The machine client is read
    /// first and stays in the report either way.
    query_error: Option<String>,
}

#[cfg(test)]
impl JobInspection {
    /// A SYSTEM job as an elevated process found it, for the status tests: `task` is `missing`,
    /// `not_ours`, `current` or anything else for a task that is ours and out of date.
    pub(crate) fn system_fixture(machine: MachineClient, task: &str) -> Self {
        let task = match task {
            "missing" => SystemTask::Missing,
            "not_ours" => SystemTask::NotOurs {
                action: "cmd.exe".into(),
            },
            "current" => SystemTask::Ours {
                profile: None,
                current: true,
            },
            _ => SystemTask::Ours {
                profile: None,
                current: false,
            },
        };
        let job = match &task {
            SystemTask::Missing => JobStatus::Missing,
            SystemTask::NotOurs { .. } => JobStatus::NotOurs,
            SystemTask::Ours { current: true, .. } => JobStatus::Current,
            _ => JobStatus::Outdated,
        };
        Self {
            job,
            system: Some(SystemInspection {
                machine_state: crate::machine::machine_state(
                    &machine,
                    &crate::machine::running_version(),
                ),
                machine,
                task: Some(task),
                receipt: None,
                task_id: "org.open-pact.report.0123456789abcdef".into(),
                query_error: None,
            }),
        }
    }
}

impl From<JobStatus> for JobInspection {
    fn from(job: JobStatus) -> Self {
        Self { job, system: None }
    }
}

impl JobInspection {
    /// Whether this is a SYSTEM job, which carries the machine client beside the task.
    pub(crate) fn is_system(&self) -> bool {
        self.system.is_some()
    }

    /// The state of the machine client, for a SYSTEM job.
    pub(crate) fn machine_state(&self) -> Option<MachineState> {
        self.system.as_ref().map(|system| system.machine_state)
    }

    /// The fix for the machine client, with the install block first. Nothing when it is current.
    pub(crate) fn machine_fix(&self) -> Option<String> {
        let system = self.system.as_ref()?;
        crate::machine::machine_fix(
            &system.machine,
            system.machine_state,
            &crate::machine::machine_path(),
            &crate::machine::running_version(),
        )
    }

    /// What the owner does to put the SYSTEM job that a pending choice waits for in place: the
    /// removal block when a task that is not ours is in the way, else the machine client's command
    /// with the install block first. `None` for a job that is not a SYSTEM inspection.
    pub(crate) fn pending_fix(&self, home: &Path) -> Option<String> {
        let system = self.system.as_ref()?;
        if matches!(system.task, Some(SystemTask::NotOurs { .. })) {
            self.job_fix(home)
        } else {
            Some(system_on_text_for(home, &system.machine))
        }
    }

    /// The fix for the task. For a SYSTEM job it is the machine client's command, or the removal
    /// block for a task that is not ours, or what a standard user cannot confirm. For a user job it
    /// is the line `check` prints for an outdated job.
    pub(crate) fn job_fix(&self, home: &Path) -> Option<String> {
        self.task_fix(home, true)
    }

    /// `job_fix` for a screen that shows `machine_fix` on its own: the removal block of a task
    /// that is not ours then leaves out the package fix it would repeat.
    pub(crate) fn task_fix(&self, home: &Path, with_package_fix: bool) -> Option<String> {
        let Some(system) = &self.system else {
            return (self.job == JobStatus::Outdated).then(|| {
                format!(
                    "The scheduled job is out of date. Run `{} schedule on`.",
                    crate::client_command(home)
                )
            });
        };
        let machine = crate::machine::machine_path();
        let usable = system.machine_state.usable();
        // A line that runs the machine client appears only after its protection check passed.
        // Else the owner installs or repairs the package first, and the package fix says how.
        let on = |profile: Option<&Path>| {
            if usable {
                crate::machine::machine_command(home, "schedule on --system", &machine, profile)
            } else {
                PACKAGE_FIRST.to_owned()
            }
        };
        match &system.task {
            None => Some(match (&system.query_error, &system.receipt) {
                (Some(error), _) => format!(
                    "Task Scheduler could not be read ({error}). The job is unconfirmed. Ask IT to inspect the task from an elevated PowerShell prompt."
                ),
                (None, Some(receipt)) if !crate::machine::same_windows_path(receipt, &machine) => format!(
                    "The job record says the job runs {}, which is not the machine package. This is not confirmed: run status from an elevated prompt to check it.",
                    receipt.display()
                ),
                _ => "SYSTEM job installation is unconfirmed. Ask IT to inspect the task from an elevated PowerShell prompt.".into(),
            }),
            Some(SystemTask::Missing) => usable.then(|| on(None)),
            Some(SystemTask::User) => Some(on(None)),
            Some(SystemTask::Ours { current: true, .. }) => None,
            Some(SystemTask::Ours { profile, .. }) => Some(on(profile.as_deref())),
            Some(SystemTask::NotOurs { action }) => {
                let mut text = format!(
                    "A SYSTEM task {} for this home runs {action}, not the machine client at {}. open-pact does not change it.\nRemove it from an elevated PowerShell prompt:\n{}",
                    system.task_id,
                    machine.display(),
                    crate::machine::removal_block(home, &system.task_id, usable.then_some(machine.as_path()))
                );
                if with_package_fix && let Some(fix) = self.machine_fix() {
                    text.push_str(&format!("\nThen:\n{fix}"));
                }
                if system.machine_state.usable_after_fix() {
                    text.push_str(&format!(
                        "\nThen run:\n{}",
                        crate::machine::machine_command(home, "schedule on --system", &machine, None)
                    ));
                }
                Some(text)
            }
        }
    }
}

/// What stands in the place of a line that runs the machine client while its protection check has
/// not passed.
const PACKAGE_FIRST: &str = "Install or repair the machine client first, as the machine client fix says. Then run its `schedule on --system` from an elevated PowerShell prompt.";

/// The executable that the recorded OS job runs. `None` when no job is recorded.
pub(crate) fn recorded_executable(home: &Home) -> Result<Option<PathBuf>> {
    let home = Home(schedule_home(&home.0, true)?);
    Ok(read_applied(&home)?.map(|applied| applied.executable))
}

pub(crate) fn inspect_job(
    home: &Home,
    config: &DeviceConfig,
    executable: &Path,
) -> Result<JobInspection> {
    if config.auto_send && config.run_as == RunAs::System {
        return inspect_system_job(home);
    }
    let desired = config.auto_send.then(|| Applied {
        run_as: config.run_as,
        executable: executable.to_path_buf(),
        user_home: None,
    });
    let home = Home(schedule_home(&home.0, true)?);
    let observed = observe(&home, desired.as_ref(), false, executable)?;
    let applied = read_applied(&home)?;
    Ok(
        match reconcile(desired.as_ref(), applied.as_ref(), &observed) {
            Change::None if desired.is_some() => JobStatus::Current,
            Change::None => JobStatus::Absent,
            Change::Install => JobStatus::Missing,
            Change::Update => JobStatus::Outdated,
            Change::Remove => JobStatus::Leftover,
        }
        .into(),
    )
}

/// The SYSTEM job: the machine client and the task, each on its own. A standard user cannot read
/// the task, so the answer stays unconfirmed; an elevated process reads it.
pub(crate) fn inspect_system_job(home: &Home) -> Result<JobInspection> {
    if crate::current_os()? != open_pact_core::Os::Windows {
        return Ok(JobStatus::SystemUnconfirmed.into());
    }
    let machine_client = crate::machine::read_machine_client();
    let machine = crate::machine::machine_path();
    let home = Home(schedule_home(&home.0, true)?);
    let elevated = crate::DeviceKey::process_is_elevated();
    // The profile list costs a start of PowerShell, so a standard user, who cannot read the task,
    // does not read it.
    let fallback = elevated.then(crate::machine::default_user_home).flatten();
    system_job_from(
        &home,
        machine_client,
        elevated,
        &machine,
        fallback.as_deref(),
        |home| observe(home, None, false, &machine),
    )
}

/// The SYSTEM job from the machine client that was read and, for an elevated process, the task. A
/// task query that fails leaves the task unconfirmed. It never hides what the package check found.
fn system_job_from(
    home: &Home,
    machine_client: MachineClient,
    elevated: bool,
    machine: &Path,
    fallback: Option<&Path>,
    observe_task: impl FnOnce(&Home) -> Result<Observed>,
) -> Result<JobInspection> {
    let machine_state =
        crate::machine::machine_state(&machine_client, &crate::machine::running_version());
    let task_id = task_id(&home.0)?;
    let mut query_error = None;
    let (job, task) = if elevated {
        match observe_task(home) {
            Ok(observed) => {
                let task = observed.system_task(machine, &home.0, fallback);
                let job = match &task {
                    SystemTask::Missing => JobStatus::Missing,
                    SystemTask::User | SystemTask::Ours { current: false, .. } => {
                        JobStatus::Outdated
                    }
                    SystemTask::NotOurs { .. } => JobStatus::NotOurs,
                    SystemTask::Ours { current: true, .. } => JobStatus::Current,
                };
                (job, Some(task))
            }
            Err(error) => {
                query_error = Some(format!("{error:#}"));
                (JobStatus::SystemUnconfirmed, None)
            }
        }
    } else {
        (JobStatus::SystemUnconfirmed, None)
    };
    let receipt = read_applied(home)
        .ok()
        .flatten()
        .map(|applied| applied.executable);
    Ok(JobInspection {
        job,
        system: Some(SystemInspection {
            machine: machine_client,
            machine_state,
            task,
            receipt,
            task_id,
            query_error,
        }),
    })
}

/// The text that tells the owner how to stop a SYSTEM job: the removal block when the task is not
/// the machine client's, else the machine client's `schedule off` when it is usable, else the
/// removal block. Never the caller's own path.
pub(crate) fn system_stop_text(home: &Path) -> String {
    // The job is named by the canonical home that install hashes, whatever the spelling given.
    let home = match schedule_home(home, true) {
        Ok(home) => home,
        Err(error) => return format!("{error:#}"),
    };
    let home = home.as_path();
    let machine_client = crate::machine::read_machine_client();
    let state = crate::machine::machine_state(&machine_client, &crate::machine::running_version());
    let machine = crate::machine::machine_path();
    let not_ours = crate::DeviceKey::process_is_elevated()
        && schedule_home(home, true)
            .map(Home)
            .and_then(|home| observe(&home, None, false, &machine))
            .is_ok_and(|observed| {
                matches!(
                    observed.system_task(&machine, home, None),
                    SystemTask::NotOurs { .. }
                )
            });
    stop_text_for(home, state, not_ours)
}

/// The stop text for a report that probes nothing (local status): the removal block, which uses
/// Windows tools only and names no copy of the client. The package state is not known there.
pub(crate) fn system_stop_text_unprobed(home: &Path) -> String {
    // The same canonical home as install, or the block would name a job that does not exist.
    let home = match schedule_home(home, true) {
        Ok(home) => home,
        Err(error) => return format!("{error:#}"),
    };
    task_id(&home).map_or_else(
        |error| format!("{error:#}"),
        |id| crate::machine::removal_block(&home, &id, None),
    )
}

fn stop_text_for(home: &Path, state: MachineState, not_ours: bool) -> String {
    let machine = crate::machine::machine_path();
    let usable = state.usable();
    if usable && !not_ours {
        crate::machine::machine_command(home, "schedule off", &machine, None)
    } else {
        task_id(home).map_or_else(
            |error| format!("{error:#}"),
            |id| crate::machine::removal_block(home, &id, usable.then_some(machine.as_path())),
        )
    }
}

/// The text that tells the owner how to turn a SYSTEM job on: the machine client's command when
/// it is usable, else the install block and then that command.
pub(crate) fn system_on_text(home: &Path) -> String {
    system_on_text_for(home, &crate::machine::read_machine_client())
}

/// `system_on_text` for a machine client that was read already.
pub(crate) fn system_on_text_for(home: &Path, machine_client: &MachineClient) -> String {
    let profile = crate::machine::default_user_home()
        .and_then(|profile| crate::machine::validate_user_home(&profile).ok());
    on_text_for(home, machine_client, profile.as_deref())
}

fn on_text_for(home: &Path, machine_client: &MachineClient, profile: Option<&Path>) -> String {
    let running = crate::machine::running_version();
    let state = crate::machine::machine_state(machine_client, &running);
    let machine = crate::machine::machine_path();
    let command = crate::machine::machine_command(home, "schedule on --system", &machine, profile);
    match crate::machine::machine_fix(machine_client, state, &machine, &running) {
        _ if state.usable() => command,
        Some(fix) if state.usable_after_fix() => format!("{fix}\nThen run:\n{command}"),
        // An unprotected or unreadable machine client stays unusable after a fix that only
        // describes it, so no line runs it.
        Some(fix) => fix,
        None => command,
    }
}

/// The job is current except that it runs another copy of the client (the desktop app's CLI copy
/// and a Homebrew one, for example). `schedule on` from this copy would only swap the path, and
/// the other copy is the one that keeps the job, so `check` stays silent.
fn is_current_in_another_copy(home: &Home, executable: &Path) -> bool {
    let Ok(schedule_home) = schedule_home(&home.0, true).map(Home) else {
        return false;
    };
    let Ok(Some(applied)) = read_applied(&schedule_home) else {
        return false;
    };
    runs_another_current_copy(executable, &applied, |recorded| {
        observe(&schedule_home, Some(recorded), false, &recorded.executable)
    })
}

fn runs_another_current_copy(
    executable: &Path,
    applied: &Applied,
    observe_recorded: impl FnOnce(&Applied) -> Result<Observed>,
) -> bool {
    applied.run_as == RunAs::User
        && applied.executable != executable
        && observe_recorded(applied).is_ok_and(|observed| {
            reconcile(Some(applied), Some(applied), &observed) == Change::None
        })
}

/// The lines `check` prints when the job needs attention: the machine client when it is not
/// current, and the task when it is outdated or not ours. It says nothing while automatic sending
/// is off or when the OS cannot be inspected: `status` reports those.
pub(crate) fn outdated_job_notice(
    home: &Home,
    config: &DeviceConfig,
    executable: &Path,
) -> Option<String> {
    if !config.auto_send {
        return None;
    }
    let inspection = inspect_job(home, config, executable).ok()?;
    if inspection.job == JobStatus::Outdated
        && config.run_as == RunAs::User
        && is_current_in_another_copy(home, executable)
    {
        return None;
    }
    let task = matches!(inspection.job, JobStatus::Outdated | JobStatus::NotOurs)
        .then(|| inspection.task_fix(&home.0, false))
        .flatten();
    let lines: Vec<String> = inspection.machine_fix().into_iter().chain(task).collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// The saved choice of a SYSTEM job. It says what the job is meant to run, never that it runs: the
/// look at the task that follows says what is installed.
fn system_choice_line(machine: &Path) -> String {
    format!(
        "Your choice is a SYSTEM job, meant to run the machine client at {}. Run `schedule on --system` from an elevated prompt to change it.",
        machine.display()
    )
}

/// `schedule status`: the owner's choice, the company's policy and the state of the job.
async fn status(home: &Home, executable: &Path) -> Result<()> {
    let config = DeviceConfig::load_or_migrate(home, crate::user_profile().as_deref(), false)?;
    let signed = home.signed_manifest();
    let signed_schedule = signed
        .as_ref()
        .is_ok_and(|manifest| manifest.body().schedule.is_some());
    match signed {
        Ok(manifest) => match &manifest.body().schedule {
            Some(schedule) => println!("{schedule}"),
            None => {
                println!("The company did not define automatic sending in the manifest you signed.")
            }
        },
        Err(error) => println!("Manifest: {error:#}"),
    }
    println!(
        "Your choice: automatic sending is {}.",
        if config.auto_send { "on" } else { "off" }
    );
    let desired = config.auto_send.then(|| Applied {
        run_as: config.run_as,
        executable: executable.to_path_buf(),
        user_home: None,
    });
    let print_next_due = || {
        if desired.is_some()
            && let Ok(manifest) = home.signed_manifest()
            && let Some(schedule) = &manifest.body().schedule
        {
            for line in next_due_text(home, config.run_as, schedule, executable) {
                println!("{line}");
            }
        }
    };
    if config.system_job_pending {
        println!("Automatic sending waits for the SYSTEM job.");
    }
    if desired
        .as_ref()
        .is_some_and(|desired| desired.run_as == RunAs::System)
    {
        // The saved choice only. What runs comes from the look at the task below.
        println!("{}", system_choice_line(&crate::machine::machine_path()));
        match inspect_system_job(home) {
            Ok(inspection) => {
                if let Some(fix) = inspection.machine_fix() {
                    println!("{fix}");
                }
                match inspection.job {
                    JobStatus::Current => println!("The job is installed and current."),
                    JobStatus::Missing => println!("The job is not installed."),
                    JobStatus::Outdated => println!("The job is out of date."),
                    JobStatus::NotOurs => println!("The job is not the machine client's."),
                    _ => {}
                }
                if let Some(fix) = inspection.task_fix(&home.0, false) {
                    println!("{fix}");
                }
            }
            Err(error) => println!("The SYSTEM job could not be inspected: {error:#}"),
        }
        print_next_due();
        return Ok(());
    }
    let schedule_home = Home(schedule_home(&home.0, true)?);
    let observed = observe(&schedule_home, desired.as_ref(), false, executable)?;
    let applied = read_applied(&schedule_home)?;
    let command = crate::client_command(&home.0);
    println!(
        "{}",
        match reconcile(desired.as_ref(), applied.as_ref(), &observed) {
            Change::None if desired.is_some() => "The job is installed and current.".to_owned(),
            Change::None => "The job is not installed.".to_owned(),
            Change::Install => format!("The job is not installed. Run `{command} schedule on`."),
            Change::Update => format!("The job is out of date. Run `{command} schedule on`."),
            Change::Remove if observed.exists && signed_schedule => format!(
                "The job is installed, but it sends nothing while automatic sending is off. Run `{command} schedule on` to agree to the signed schedule, or `{command} schedule off` to remove the job."
            ),
            Change::Remove => format!(
                "A job from an earlier setup remains. Run `{command} schedule off` to remove it."
            ),
        }
    );
    if let Some(state) = schedule_home.read_json::<State>(STATE)?
        && let Some(last) = state.last_success
        && let Some(time) = time::OffsetDateTime::from_unix_timestamp(last).ok()
    {
        println!(
            "Last claim the gateway answered: {}.",
            open_pact_core::timestamp::rfc3339_secs(time)
        );
    }
    print_next_due();
    Ok(())
}

pub(crate) async fn run(home: &Home, command: Command, executable: &Path) -> Result<()> {
    match command {
        Command::On {
            system,
            user,
            dry_run,
            user_home,
        } => {
            let run_as = if system {
                Some(RunAs::System)
            } else {
                user.then_some(RunAs::User)
            };
            turn_on(home, run_as, dry_run, executable, user_home.as_deref()).await
        }
        Command::Off { dry_run } => turn_off(home, dry_run, executable).await,
        Command::Status => status(home, executable).await,
        Command::Run { system, user_home } => {
            operate(
                home,
                Operation::Run { system, user_home },
                false,
                executable,
                &crate::machine::machine_path(),
            )
            .await
        }
        Command::Probe { address, name } => probe_command(&address, name.as_deref()).await,
    }
}

/// One run of the job. The policy comes from the manifest the owner signed, never from a manifest
/// that waits for acceptance.
async fn run_tick(
    home: &Home,
    state_home: &Home,
    user_home: Option<&Path>,
    executable: &Path,
) -> Result<()> {
    let authorization = {
        let Some(_claim_lock) = claim::try_lock(home)? else {
            return Ok(());
        };
        let config = DeviceConfig::load_or_migrate(home, user_home, true)?;
        let command = crate::client_command(&home.0);
        if let Some(notice) =
            device_config::legacy_notice(home, device_config::Surface::Job, &command, &config)
        {
            job_log(home, &notice);
        }
        if !config.auto_send {
            return Ok(());
        }
        let manifest = home.signed_manifest()?;
        let Some(schedule) = manifest.body().schedule.clone() else {
            return Ok(());
        };
        ScheduleAuthorization {
            manifest_hash: manifest.hash().clone(),
            schedule,
            owner_consented: config.auto_send,
            self_removal: true,
        }
    };
    note_client_version(home, state_home)?;
    tick(
        home,
        state_home,
        user_home,
        &authorization,
        executable,
        checks::event_markers,
    )
    .await
}

/// Writes one job-log line when the client version that runs the job changes, so an upgrade of
/// the machine client shows in the log of the next wake.
///
/// A state file that does not read stops the run with its error. The file stays as it is: a default
/// state in its place would erase the history that decides what is due.
fn note_client_version(home: &Home, state_home: &Home) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let mut state: State = state_home.read_json(STATE)?.unwrap_or_default();
    if state.client_version.as_deref() == Some(version) {
        return Ok(());
    }
    job_log(home, &format!("This job now runs client {version}."));
    state.client_version = Some(version.to_owned());
    if let Err(error) = save(state_home, STATE, &state) {
        job_log(home, &format!("error: {error:#}"));
    }
    Ok(())
}

/// A client update leaves the OS job on the definition the old client wrote. The wake run
/// compares the job with the definition this client would install, as `schedule on` does, and
/// rewrites it when they differ. It only follows the owner's choice: nothing happens while
/// automatic sending is off, for a SYSTEM job, without a signed schedule, or when the job is gone. A
/// task that runs as SYSTEM is left as it is.
/// The check runs once for each client version and path, so a wake costs no extra process start.
/// `true` when it rewrote the job.
fn refresh_job(home: &Home, executable: &Path) -> Result<bool> {
    refresh_job_with(
        home,
        executable,
        |desired| observe(home, Some(desired), false, executable),
        rewrite_job,
    )
}

fn refresh_job_with(
    home: &Home,
    executable: &Path,
    observe_job: impl FnOnce(&Applied) -> Result<Observed>,
    rewrite: impl FnOnce(&Job) -> Result<()>,
) -> Result<bool> {
    let config = DeviceConfig::load(home)?;
    if !config.auto_send || config.run_as != RunAs::User {
        return Ok(false);
    }
    if !home
        .signed_manifest()
        .is_ok_and(|manifest| manifest.body().schedule.is_some())
    {
        return Ok(false);
    }
    let known = format!("{} {}", env!("CARGO_PKG_VERSION"), executable.display());
    if home
        .read_json::<String>(JOB_REFRESH)
        .ok()
        .flatten()
        .as_deref()
        == Some(known.as_str())
    {
        return Ok(false);
    }
    let desired = Applied {
        run_as: RunAs::User,
        executable: executable.to_path_buf(),
        user_home: None,
    };
    let checked = observe_job(&desired).and_then(|observed| Ok((observed, read_applied(home)?)));
    let (observed, applied) = match checked {
        Ok(read) => read,
        Err(error) => {
            // A blocked PowerShell must not retry and log every minute: the caller logs this once.
            save(home, JOB_REFRESH, &known)?;
            return Err(error);
        }
    };
    // A SYSTEM task is the machine client's to keep: a user job never rewrites it.
    let stale = observed.exists
        && !observed.system
        && reconcile(Some(&desired), applied.as_ref(), &observed) == Change::Update;
    // A failed rewrite is not retried every minute: `status` and `check` keep reporting the job.
    save(home, JOB_REFRESH, &known)?;
    if !stale {
        return Ok(false);
    }
    rewrite(&Job::new(executable, &home.0)?)?;
    save(home, APPLIED, &desired)?;
    Ok(true)
}

fn rewrite_job(job: &Job) -> Result<()> {
    if crate::current_os()? != open_pact_core::Os::Macos {
        return register(job, RegistrationAction::Install(TaskRunAs::CurrentUser));
    }
    let path = user_home()?
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", job.id));
    let domain = launch_domain()?;
    macos_rewrite(job, &path, &domain, |args| {
        // A helper that an earlier failed rewrite left behind would make `submit` fail.
        let _ = std::process::Command::new("launchctl")
            .args(["remove", args[2]])
            .output();
        execute("launchctl", args)
    })
}

fn shell_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\"'\"'"))
}

/// launchd stops the running job when it boots the job out, and that would stop this process
/// before it boots the job in again. So a separate launchd job (`launchctl submit`, which a job
/// that exits does not take down) waits for this run to end, boots out the old definition and
/// boots in the new one. The file is written after the helper is queued: if the helper cannot
/// be queued, the job keeps its old file and the next version tries again.
fn macos_rewrite(
    job: &Job,
    path: &Path,
    domain: &str,
    submit: impl FnOnce(&[&str]) -> Result<()>,
) -> Result<()> {
    let target = format!("{domain}/{}", job.id);
    let helper = format!("{}.refresh", job.id);
    let plist = text(path)?;
    let script = format!(
        "sleep 2; launchctl bootout {target}; test -f {plist} && launchctl bootstrap {domain} {plist}; launchctl remove {helper}",
        target = shell_quote(&target),
        plist = shell_quote(plist),
        domain = shell_quote(domain),
        helper = shell_quote(&helper),
    );
    // The helper's own output goes to the job log, so a failed bootout or bootstrap is visible.
    submit(&[
        "submit", "-l", &helper, "-o", &job.log, "-e", &job.log, "--", "/bin/sh", "-c", &script,
    ])?;
    std::fs::write(path, job.plist()).with_context(|| format!("write {}", path.display()))
}

/// §machine§ is the machine client: the only image that a SYSTEM job runs and the only one that
/// a SYSTEM task may name.
async fn operate(
    home: &Home,
    command: Operation,
    home_locked: bool,
    executable: &Path,
    machine: &Path,
) -> Result<()> {
    let os = crate::current_os()?;
    if let Operation::Install { system, .. } = &command
        && *system
    {
        validate_system_install(true, os)?;
    }
    let system_run = matches!(&command, Operation::Run { system: true, .. });
    if system_run {
        validate_system_install(true, os)?;
    }
    let uninstall = matches!(&command, Operation::Uninstall { .. });
    let absolute = schedule_home(&home.0, uninstall)?;
    if system_run {
        require_home_without_link(&home.0, &absolute)?;
        let image = std::env::current_exe().context("find the running image")?;
        if !same_windows_path(&image, machine) {
            let home = Home(absolute);
            job_log(
                &home,
                &format!(
                    "error: a SYSTEM job runs only the machine client at {}, not {}",
                    machine.display(),
                    image.display()
                ),
            );
            bail!(
                "a SYSTEM job runs only the machine client at {}, not {}",
                machine.display(),
                image.display()
            );
        }
    }
    let home = Home(absolute);
    let system_install = matches!(&command, Operation::Install { system: true, .. });
    if let Operation::Install {
        system: true,
        user_home,
        ..
    } = &command
    {
        home.enrolment()?;
        crate::DeviceKey::load(&home.0)?;
        validate_windows_home(&home.0)?;
        validate_windows_home(
            user_home
                .as_deref()
                .context("a SYSTEM install needs the user home")?,
        )?;
    }
    let system_uninstall = matches!(&command, Operation::Uninstall { system: true });
    if system_uninstall {
        validate_system_install(true, os)?;
        windows_require_elevation()?;
    }
    let protected_paths = if os == open_pact_core::Os::Windows && (system_run || system_install) {
        Some(windows_protected_paths(&home, machine)?)
    } else {
        None
    };
    let state_home = protected_paths
        .as_ref()
        .map(|state| Home(state.clone()))
        .unwrap_or_else(|| Home(home.0.clone()));
    let home_exists = home.0.exists();
    let _home_lock = if system_install && !home_locked {
        Some(lock(&home)?)
    } else {
        None
    };
    let _lock = if system_run || system_install {
        Some(lock_system_state(&state_home)?)
    } else if (!uninstall || home_exists) && !home_locked {
        Some(lock(&state_home)?)
    } else {
        None
    };
    match command {
        Operation::Run { user_home, .. } => {
            // From here on, no link the user puts in the home can redirect what SYSTEM does there.
            let _protection = if system_run {
                match crate::home_fs::protect(&home.0, &state_home.0) {
                    Ok(protection) => Some(protection),
                    Err(error) => {
                        write_job_log(&state_home, &format!("error: {error:#}"));
                        return Err(error);
                    }
                }
            } else {
                None
            };
            // The checks of the job read the user's own files, where a link is as easy to plant.
            let _user_protection = match user_home.as_deref().filter(|_| system_run) {
                Some(user_home) => match crate::home_fs::protect(user_home, &state_home.0) {
                    Ok(protection) => Some(protection),
                    Err(error) => {
                        write_job_log(&state_home, &format!("error: {error:#}"));
                        return Err(error);
                    }
                },
                None => None,
            };
            let log = Home(crate::home_fs::job_log_home(&home.0));
            if let Err(error) = rotate_job_log(&log) {
                eprintln!(
                    "warning: could not rotate {}: {error}",
                    log.file(JOB_LOG).display()
                );
            }
            let result = run_tick(&home, &state_home, user_home.as_deref(), executable).await;
            if let Err(error) = &result {
                job_log(&home, &format!("error: {error:#}"));
            }
            // Last, because the macOS reload ends this process.
            if !system_run {
                match refresh_job(&home, executable) {
                    Ok(true) => job_log(
                        &home,
                        "The job ran an older definition. This client rewrote it.",
                    ),
                    Ok(false) => {}
                    Err(error) => job_log(&home, &format!("error: job refresh: {error:#}")),
                }
            }
            result?;
        }
        Operation::Install {
            system,
            user_home,
            keep_state,
        } => {
            home.enrolment()?;
            crate::DeviceKey::load(&home.0)?;
            if os == open_pact_core::Os::Windows {
                validate_windows_home(&home.0)?;
            }
            let (executable, install_state) = if system {
                let state = protected_paths
                    .as_ref()
                    .context("SYSTEM install paths were not prepared")?;
                (machine.to_path_buf(), Home(state.clone()))
            } else {
                (executable.to_path_buf(), Home(home.0.clone()))
            };
            if os == open_pact_core::Os::Windows && text(&executable)?.contains('%') {
                bail!("choose an executable path without %");
            }
            let mut job = Job::new(&executable, &home.0)?;
            if system {
                job = job.for_system(
                    user_home
                        .as_deref()
                        .context("a SYSTEM install needs the user home")?,
                )?;
                job.log = text(&install_state.file(JOB_LOG))?.into();
            }
            // A SYSTEM update keeps the state of the running job. A new install, or a state that
            // does not read, starts empty.
            let keep = keep_state
                && system
                && install_state
                    .read_json::<State>(STATE)
                    .is_ok_and(|state| state.is_some());
            if !keep {
                save(&install_state, STATE, &State::default())?;
            }
            let run_as = if system {
                TaskRunAs::System
            } else {
                TaskRunAs::CurrentUser
            };
            register(&job, RegistrationAction::Install(run_as))?;
            println!(
                "Installed {}. The OS runs it every minute and it does nothing until a check or a claim is due. It sends the same claim as `check`, as the signed manifest allows. It writes what needs your attention to {}.",
                job.id, job.log
            );
        }
        Operation::Uninstall { system } => {
            let job = Job::new(executable, &home.0)?;
            if os == open_pact_core::Os::Windows && system {
                let state = windows_existing_system_state(&home.0)?;
                finish_system_removal(&home, home_exists, || {
                    windows_system_uninstall_held(&job, state, machine)
                })?;
            } else {
                if os == open_pact_core::Os::Windows {
                    windows_uninstall(&job, false, machine)?;
                    println!(
                        "SYSTEM leftovers, if any, are removed with `schedule off` from an elevated prompt."
                    );
                } else {
                    register(&job, RegistrationAction::Uninstall)?;
                }
                if home_exists {
                    remove_home_schedule_files(&home)?;
                }
            }
            if home_exists {
                println!("Removed {} and its schedule state and log.", job.id);
            } else {
                println!("Removed {}. The home directory does not exist.", job.id);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn powershell_functions(script: &str) -> Vec<String> {
        script
            .lines()
            .filter_map(|line| {
                let declaration = line.trim().strip_prefix("function ")?;
                let name = declaration
                    .split(|character: char| character.is_whitespace() || character == '(')
                    .next()?;
                Some(name.to_ascii_lowercase())
            })
            .collect()
    }

    fn calls_powershell_function(script: &str, name: &str) -> bool {
        script.lines().any(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("function ") {
                return false;
            }
            let lower = line.to_ascii_lowercase();
            let mut offset = 0;
            while let Some(found) = lower[offset..].find(name) {
                let start = offset + found;
                let end = start + name.len();
                let before = lower[..start].chars().next_back();
                let after = lower[end..].chars().next();
                let word_start = before
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
                let word_end = after
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
                let invocation = after
                    .is_some_and(|character| character.is_whitespace() || character == '(')
                    || (before == Some('(') && after == Some(')'));
                if word_start && word_end && invocation {
                    return true;
                }
                offset = end;
            }
            false
        })
    }

    #[test]
    fn every_built_powershell_script_defines_its_called_helpers() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let scripts = [
            windows_protected_paths_script("fixture-hash", "'machine.exe'"),
            windows_task_query_script(&job),
            windows_uninstall_script(&job, false, Path::new("machine.exe")),
            windows_clear_for_system_script(&job, Path::new("machine.exe")),
            windows_existing_system_state_script("fixture-hash"),
            windows_observation_script(&job),
            windows_require_elevation_script().to_owned(),
            crate::machine::machine_probe_script(Path::new("machine.exe")).unwrap(),
            crate::machine::install_block(&crate::machine::running_version()),
            crate::machine::removal_block(Path::new("fixture-home"), "task", None),
        ];
        let helpers = scripts
            .iter()
            .flat_map(|script| powershell_functions(script))
            .collect::<Vec<_>>();

        for script in &scripts {
            let definitions = powershell_functions(script);
            for helper in &helpers {
                if calls_powershell_function(script, helper) {
                    assert!(
                        definitions.iter().any(|defined| defined == helper),
                        "PowerShell helper {helper} is called but not defined in the same script:\n{script}"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn limited_operations_leave_protected_cleanup_for_elevated_removal() {
        let protected = Observed {
            protected_leftovers: true,
            ..Observed::default()
        };
        assert!(!needs_system_cleanup(false, false, &protected));
        assert!(needs_system_cleanup(false, true, &protected));
        assert!(needs_system_cleanup(true, true, &Observed::default()));
        assert!(needs_system_cleanup(
            false,
            false,
            &Observed {
                system: true,
                ..Observed::default()
            }
        ));
        assert!(!needs_system_cleanup(false, true, &Observed::default()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires a built OPEN_PACT_CLIENT_BIN; all scheduler commands use a fixture mock"]
    fn declarative_cli_with_mock_scheduler() {
        use std::os::unix::fs::PermissionsExt;
        let binary = std::env::var_os("OPEN_PACT_CLIENT_BIN")
            .expect("build the client and set OPEN_PACT_CLIENT_BIN");
        let root = tempfile::Builder::new()
            .prefix("open-pact-example-")
            .tempdir()
            .unwrap();
        let user = root.path().join("home");
        let path = user.join(".config/open-pact");
        let mock = root.path().join("bin");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::create_dir(&mock).unwrap();
        let home = enrolled_home(&path);
        let mut enrollment: crate::Enrolment = home.enrolment().unwrap();
        enrollment.gateway = "http://127.0.0.1:1".into();
        home.write("enrolment.json", &serde_json::to_vec(&enrollment).unwrap())
            .unwrap();
        let launchctl = mock.join("launchctl");
        std::fs::write(
            &launchctl,
            r#"#!/bin/sh
case "$1" in
  print) test -f "$OPEN_PACT_MOCK/loaded" ;;
  bootstrap) echo bootstrap >> "$OPEN_PACT_MOCK/changes"; touch "$OPEN_PACT_MOCK/loaded" ;;
  bootout) echo bootout >> "$OPEN_PACT_MOCK/changes"; rm -f "$OPEN_PACT_MOCK/loaded" ;;
  submit) echo submit >> "$OPEN_PACT_MOCK/changes" ;;
  remove) ;;
  *) exit 99 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&launchctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut transcript = String::new();
        let mut run = |args: &[&str], success: bool, expected: &str| {
            let output = std::process::Command::new(&binary)
                .args(args)
                .env("HOME", &user)
                .env("OPEN_PACT_MOCK", root.path())
                .env(
                    "PATH",
                    format!("{}:{}", mock.display(), std::env::var("PATH").unwrap()),
                )
                .env_remove("HTTP_PROXY")
                .env_remove("HTTPS_PROXY")
                .env_remove("ALL_PROXY")
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            transcript.push_str(&format!(
                "$ open-pact-client {}\n{text}exit: {:?}\n",
                args.join(" "),
                output.status.code()
            ));
            assert_eq!(output.status.success(), success, "{text}");
            assert!(text.contains(expected), "{text}");
            text
        };
        let before = std::fs::read_dir(&path).unwrap().count();
        run(&["schedule", "status"], true, "The job is not installed.");
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), before);
        run(&["schedule", "on", "--dry-run"], true, "schedule: install");
        assert!(!root.path().join("changes").exists());
        assert!(!home.file(crate::device_config::FILE).exists());
        let on = run(&["schedule", "on"], true, "schedule: install");
        assert!(
            on.contains("Automatic claims: only while vpn.example.org answers at 10.0.0.1:443")
        );
        assert!(DeviceConfig::load(&home).unwrap().auto_send);
        let plist = std::fs::read_to_string(
            user.join("Library/LaunchAgents")
                .read_dir()
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .unwrap();
        assert!(plist.contains(&format!(
            "<key>StandardOutPath</key><string>{}</string>",
            std::fs::canonicalize(&path).unwrap().join(JOB_LOG).display()
        )));
        let changes = std::fs::read(root.path().join("changes")).unwrap();
        run(&["schedule", "on"], true, "no changes");
        assert_eq!(std::fs::read(root.path().join("changes")).unwrap(), changes);
        run(
            &["schedule", "status"],
            true,
            "The job is installed and current.",
        );
        std::fs::remove_file(root.path().join("loaded")).unwrap();
        run(&["schedule", "on"], true, "schedule: update");
        run(&["schedule", "off", "--dry-run"], true, "schedule: remove");
        assert!(DeviceConfig::load(&home).unwrap().auto_send);
        run(&["schedule", "off"], true, "schedule: remove");
        assert!(!home.file(STATE).exists());
        assert!(!home.file(APPLIED).exists());
        assert!(!DeviceConfig::load(&home).unwrap().auto_send);
        run(&["schedule", "off"], true, "no changes");
        run(&["schedule", "on"], true, "schedule: install");
        let work = user.join("work");
        run(&["folders", "add", "~/work"], true, "Added");
        run(&["folders", "add", "~/work"], true, "already listed");
        assert_eq!(
            DeviceConfig::load(&home).unwrap().folders,
            std::slice::from_ref(&work)
        );
        run(&["folders", "list"], true, &work.display().to_string());
        run(&["folders", "remove", "~/work"], true, "Removed");
        run(&["folders", "remove", "~/work"], false, "is not listed");
        assert!(DeviceConfig::load(&home).unwrap().folders.is_empty());
        std::fs::write(
            home.file(crate::device_config::LEGACY_FILE),
            "[schedule]\nenabled = true\nrun_as = 'user'\n[managed_repos]\nfolders = ['~/work']\n",
        )
        .unwrap();
        let check = run(&["check"], false, "open-pact.toml is ignored now");
        assert!(check.contains("[managed_repos] folders"), "{check}");
        let second = run(&["check"], false, "control | manifest requirement");
        assert!(!second.contains("is ignored now"), "{second}");
        assert!(home.file(crate::device_config::LEGACY_FILE).exists());
        let changes = std::fs::read(root.path().join("changes")).unwrap();
        run(&["apply"], false, "unrecognized subcommand");
        run(&["finish"], false, "unrecognized subcommand");
        run(&["config", "example"], false, "unrecognized subcommand");
        assert_eq!(std::fs::read(root.path().join("changes")).unwrap(), changes);
        // The wake of a job that an older client wrote: five minutes, rewritten once.
        let plist_path = user
            .join("Library/LaunchAgents")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let current = std::fs::read_to_string(&plist_path).unwrap();
        assert!(current.contains(NEW_WAKE));
        let old = current.replace(NEW_WAKE, OLD_WAKE);
        std::fs::write(&plist_path, &old).unwrap();
        let submits = |changes: &[u8]| String::from_utf8_lossy(changes).matches("submit").count();
        let before = std::fs::read(root.path().join("changes")).unwrap();
        run(&["schedule", "run"], true, "");
        assert_eq!(std::fs::read_to_string(&plist_path).unwrap(), current);
        let after = std::fs::read(root.path().join("changes")).unwrap();
        assert_eq!(submits(&after), submits(&before) + 1);
        run(&["schedule", "run"], true, "");
        assert_eq!(std::fs::read_to_string(&plist_path).unwrap(), current);
        assert_eq!(std::fs::read(root.path().join("changes")).unwrap(), after);
        // A job the owner turned off stays as it is.
        run(&["schedule", "off"], true, "schedule: remove");
        std::fs::write(&plist_path, &old).unwrap();
        run(&["schedule", "run"], true, "");
        assert_eq!(std::fs::read_to_string(&plist_path).unwrap(), old);
        assert!(!home.file(JOB_REFRESH).exists());
        std::fs::remove_dir_all(&path).unwrap();
        run(&["schedule", "off"], true, "schedule: remove");
        assert!(
            !path.exists(),
            "schedule off recreated the missing client home"
        );
        println!("{transcript}");
        if let Some(output) = std::env::var_os("OPEN_PACT_CLI_TRANSCRIPT") {
            std::fs::write(output, transcript).unwrap();
        }
    }

    const T: i64 = 1_000_000;

    /// Controls of the example manifest: `disk_encryption` has no grace, `firewall` one day,
    /// `unknown_grace` is seven days.
    fn lapsed(rows: &[(&str, &str, Option<i64>)]) -> Vec<String> {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let compliance = rows
            .iter()
            .map(|(id, value, _)| ((*id).to_owned(), *value == "full" || *value == "on"))
            .collect();
        let results = rows
            .iter()
            .map(|(id, value, _)| ((*id).to_owned(), (*value).into()))
            .collect();
        let state = State {
            first_failed: rows
                .iter()
                .filter_map(|(id, _, ago)| Some(((*id).to_owned(), T - (*ago)?)))
                .collect(),
            ..State::default()
        };
        lapsed_controls(&manifest, &compliance, &results, &state, T)
    }

    /// A removal that fails at grace expiry still asks for the claim, once per run of failures.
    /// `ca.pem` is a non-empty directory, so deleting it fails on every OS.
    #[test]
    fn a_failed_removal_at_grace_expiry_still_forces_the_claim_once() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        home.install_vpn_pair(b"CA", b"certificate").unwrap();
        std::fs::remove_file(home.file("ca.pem")).unwrap();
        std::fs::create_dir(home.file("ca.pem")).unwrap();
        std::fs::write(home.file("ca.pem").join("held"), b"x").unwrap();
        let vpn = places(Some(("1h", "5m")), None);
        // A recent answered claim, a control that has failed since before: no event came from the
        // compliance change itself.
        let state_dir = tempfile::tempdir().unwrap();
        let state_home = Home(state_dir.path().to_path_buf());
        let mut state = State {
            last_observed_compliance: Some(BTreeMap::from([("firewall".to_owned(), false)])),
            ..state(false, Some(10 * MIN), Some(10 * MIN), false)
        };
        assert_eq!(plan(&vpn, &state, Place::Vpn, T, 0).send, None);
        retire_certificate(&home, &state_home, &mut state, &["firewall".to_owned()]).unwrap();
        assert!(state.event_pending);
        assert_eq!(
            plan(&vpn, &state, Place::Vpn, T, 0).send,
            Some(Trigger::Event)
        );
        let log = std::fs::read_to_string(home.file(JOB_LOG)).unwrap();
        assert!(log.contains("Could not remove the VPN certificate"));
        // The claim went out; the next check fails to remove it the same way: no second claim.
        state.event_pending = false;
        retire_certificate(&home, &state_home, &mut state, &["firewall".to_owned()]).unwrap();
        assert!(!state.event_pending);
        // The deletion works later and the failure run is over.
        std::fs::remove_dir_all(home.file("ca.pem")).unwrap();
        retire_certificate(&home, &state_home, &mut state, &["firewall".to_owned()]).unwrap();
        assert!(!state.removal_failed);
    }

    /// The forced claim is saved before the deletion starts. A crash at any step of the
    /// deletion leaves it pending for the next run, which plans a claim at once.
    #[test]
    fn a_crash_during_the_removal_leaves_the_forced_claim_pending() {
        let vpn = places(Some(("1h", "5m")), None);
        let mut completed = false;
        for step in 1..=32 {
            let dir = tempfile::tempdir().unwrap();
            let home = Home(dir.path().join("fictional-home"));
            home.install_vpn_pair(b"CA one", b"certificate one")
                .unwrap();
            let state_dir = tempfile::tempdir().unwrap();
            let state_home = Home(state_dir.path().to_path_buf());
            // A recent answered claim and a control that has failed since before: no event came
            // from the compliance change itself.
            let mut state = State {
                last_observed_compliance: Some(BTreeMap::from([("firewall".to_owned(), false)])),
                ..state(false, Some(10 * MIN), Some(10 * MIN), false)
            };
            crate::INTERRUPT_AFTER.with(|left| left.set(Some(step)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                retire_certificate(&home, &state_home, &mut state, &["firewall".to_owned()])
            }));
            crate::INTERRUPT_AFTER.with(|left| left.set(None));
            // Only the saved state survives the crash. Recovery then finishes the deletion.
            let saved: State = state_home
                .read_json(STATE)
                .unwrap()
                .unwrap_or_else(|| panic!("step {step}: no state was saved"));
            assert!(saved.event_pending, "step {step}: the claim is pending");
            home.recover_vpn().unwrap();
            assert!(
                !home.vpn_removal_owed(),
                "step {step}: nothing left to delete"
            );
            assert_eq!(
                plan(&vpn, &saved, Place::Vpn, T, 0).send,
                Some(Trigger::Event),
                "step {step}: the next run sends the claim"
            );
            if result.is_ok() {
                completed = true;
                break;
            }
        }
        assert!(completed, "the removal never finished");
    }

    #[test]
    fn a_control_lapses_when_its_grace_has_ended() {
        const DAY: i64 = 86_400;
        // No grace: at once, even on the first check that saw it.
        assert_eq!(
            lapsed(&[("disk_encryption", "none", None)]),
            ["disk_encryption"]
        );
        assert_eq!(
            lapsed(&[("disk_encryption", "none", Some(0))]),
            ["disk_encryption"]
        );
        // One day of grace ends after the day, not at it.
        assert!(lapsed(&[("firewall", "off", None)]).is_empty());
        assert!(lapsed(&[("firewall", "off", Some(DAY - 1))]).is_empty());
        assert!(lapsed(&[("firewall", "off", Some(DAY))]).is_empty());
        assert_eq!(lapsed(&[("firewall", "off", Some(DAY + 1))]), ["firewall"]);
        // A result that cannot be read counts against `unknown_grace`, also on a no-grace control.
        assert!(lapsed(&[("firewall", "unknown", Some(7 * DAY))]).is_empty());
        assert_eq!(
            lapsed(&[("firewall", "unknown", Some(7 * DAY + 1))]),
            ["firewall"]
        );
        assert!(lapsed(&[("disk_encryption", "unknown", Some(60))]).is_empty());
        // A control that passes never lapses, and a control the manifest lacks is ignored.
        assert!(lapsed(&[("firewall", "on", Some(30 * DAY))]).is_empty());
        assert!(lapsed(&[("not_in_the_manifest", "off", Some(30 * DAY))]).is_empty());
        assert_eq!(
            lapsed(&[
                ("firewall", "off", Some(2 * DAY)),
                ("disk_encryption", "none", None),
                ("os_supported", "no", Some(DAY)),
            ]),
            ["disk_encryption", "firewall"]
        );
    }

    #[test]
    fn the_local_grace_starts_at_the_first_failure_and_resets_when_the_control_passes() {
        let mut state = State::default();
        let failing = |firewall| {
            BTreeMap::from([
                ("firewall".to_owned(), firewall),
                ("os_supported".to_owned(), false),
            ])
        };
        state.observe_failures(&failing(false), 100);
        state.observe_failures(&failing(false), 500);
        assert_eq!(
            state.first_failed["firewall"], 100,
            "the first failure stands"
        );
        state.observe_failures(&failing(true), 600);
        assert!(
            !state.first_failed.contains_key("firewall"),
            "a pass clears it"
        );
        state.observe_failures(&failing(false), 700);
        assert_eq!(state.first_failed["firewall"], 700);
        state.observe_failures(&BTreeMap::from([("firewall".to_owned(), false)]), 800);
        assert!(
            !state.first_failed.contains_key("os_supported"),
            "a control the manifest no longer requires is forgotten"
        );
    }

    fn probe() -> open_pact_core::Probe {
        open_pact_core::Probe {
            address: open_pact_core::ProbeAddress::try_from("10.0.0.1:443".to_owned()).unwrap(),
            name: None,
        }
    }

    fn interval(text: &str) -> open_pact_core::Interval {
        open_pact_core::Interval::try_from(text.to_owned()).unwrap()
    }

    /// `[schedule.vpn]` with these periods, and `[schedule.always]` when given.
    fn places(vpn: Option<(&str, &str)>, always: Option<&str>) -> Schedule {
        let vpn = vpn.map(|(send, check)| {
            let mut slot = open_pact_core::VpnSlot::new(probe(), interval(send));
            slot.check = CheckPeriod::try_from(check.to_owned()).unwrap();
            slot
        });
        Schedule::new(vpn, always.map(interval)).unwrap()
    }

    /// A state with the last answered attempt and the last check `ago` seconds before `T`.
    fn state(reconnect: bool, attempt: Option<i64>, check: Option<i64>, event: bool) -> State {
        State {
            vpn_up: true,
            reconnect_pending: reconnect,
            last_attempt: attempt.map(|ago| T - ago),
            last_check: check.map(|ago| T - ago),
            event_pending: event,
            ..State::default()
        }
    }

    const MIN: i64 = 60;

    #[test]
    fn next_due_text_reads_the_state_of_the_job_that_runs() {
        let vpn = places(Some(("10m", "5m")), None);
        let dir = tempfile::tempdir().unwrap();
        let state_home = Home(dir.path().to_path_buf());
        // No saved state: a new job. It checks at the next wake.
        let fresh = due_text(Ok(Home(state_home.0.clone())), &vpn);
        assert!(fresh.iter().any(|line| line.starts_with("Next check due")));
        // A state the job saved, with a check a moment ago, is the one that counts.
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        save(
            &state_home,
            STATE,
            &State {
                vpn_up: true,
                last_check: Some(now - MIN),
                last_attempt: Some(now - MIN),
                ..State::default()
            },
        )
        .unwrap();
        let lines = due_text(Ok(Home(state_home.0.clone())), &vpn);
        assert!(lines.iter().any(|line| line.starts_with("Last check:")));
        assert_ne!(lines, fresh);
        // A state that cannot be read is said so; it is not a new job.
        std::fs::write(state_home.file(STATE), b"{ not json").unwrap();
        let unreadable = due_text(Ok(Home(state_home.0.clone())), &vpn);
        assert_eq!(unreadable.len(), 1);
        assert!(unreadable[0].contains("cannot be read"), "{unreadable:?}");
        let missing = due_text(Err(anyhow::anyhow!("access denied")), &vpn);
        assert!(missing[0].contains("cannot be read"), "{missing:?}");
        assert!(missing[0].contains("access denied"));
    }

    /// `schedule status` and `accept` ask for the job's own state: a user job keeps it in the
    /// client home, and a SYSTEM job in the protected directory of Windows. The Windows lookup
    /// itself runs PowerShell and has no unit test.
    #[test]
    fn the_job_state_home_follows_who_runs_the_job() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        assert_eq!(
            job_state_home(&home, RunAs::User, &std::env::current_exe().unwrap())
                .unwrap()
                .0,
            schedule_home(&home.0, true).unwrap()
        );
        if crate::current_os().unwrap() != open_pact_core::Os::Windows {
            let vpn = places(Some(("10m", "5m")), None);
            let lines = next_due_text(
                &home,
                RunAs::System,
                &vpn,
                &std::env::current_exe().unwrap(),
            );
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("only on Windows"), "{lines:?}");
        }
    }

    #[test]
    fn next_due_says_when_the_job_will_check_and_send() {
        let vpn = places(Some(("10m", "5m")), None);
        let on_vpn = State {
            vpn_up: true,
            ..state(false, Some(4 * MIN), Some(2 * MIN), false)
        };
        // Check at 5 minutes after the last one (3 minutes from now); claim 10 minutes after the answer.
        assert_eq!(
            next_due(&vpn, &on_vpn, T),
            NextDue {
                check: Some(T + 3 * MIN),
                send: Some(T + 6 * MIN)
            }
        );
        // Nothing ran yet: both at the next wake.
        let fresh = State {
            vpn_up: true,
            ..State::default()
        };
        assert_eq!(
            next_due(&vpn, &fresh, T),
            NextDue {
                check: Some(T),
                send: Some(T)
            }
        );
        // Off the VPN with only a VPN slot: nothing falls due.
        let off = State::default();
        assert_eq!(
            next_due(&vpn, &off, T),
            NextDue {
                check: None,
                send: None
            }
        );
        let lines = next_due_lines(&vpn, &off, T);
        assert!(
            lines
                .iter()
                .all(|line| line.contains("none while the VPN does not answer")),
            "{lines:?}"
        );
        // A held event is due now.
        let event = state(false, Some(MIN), Some(MIN), true);
        assert_eq!(
            next_due(
                &vpn,
                &State {
                    vpn_up: true,
                    ..event
                },
                T
            )
            .send,
            Some(T)
        );
    }

    /// The job's times are written in UTC with whole seconds and a `Z`, as chrono wrote them.
    #[test]
    fn time_text_writes_whole_seconds_in_utc_and_names_an_unreadable_time() {
        assert_eq!(time_text(0), "1970-01-01T00:00:00Z");
        assert_eq!(time_text(1_794_906_000), "2026-11-17T09:00:00Z");
        assert_eq!(time_text(-1), "1969-12-31T23:59:59Z");
        assert_eq!(time_text(i64::MAX), "an unknown time");
    }

    #[test]
    fn the_next_due_lines_name_the_last_check_and_both_times() {
        let vpn = places(Some(("10m", "5m")), None);
        let on_vpn = State {
            vpn_up: true,
            ..state(false, Some(4 * MIN), Some(2 * MIN), false)
        };
        assert_eq!(
            next_due_lines(&vpn, &on_vpn, T),
            [
                format!("Last check: {}.", time_text(T - 2 * MIN)),
                format!("Next check due: {}.", time_text(T + 3 * MIN)),
                format!("Next claim due: {}.", time_text(T + 6 * MIN)),
            ]
        );
        let due_now = State {
            vpn_up: true,
            ..State::default()
        };
        assert_eq!(
            next_due_lines(&vpn, &due_now, T),
            [
                "Next check due: at the next wake, within a minute.".to_owned(),
                "Next claim due: at the next wake, within a minute.".to_owned(),
            ]
        );
    }

    #[test]
    fn plan_decides_checks_and_sends_from_the_schedule_place_and_state() {
        use Place::{Elsewhere, Vpn};
        let vpn = places(Some(("10m", "5m")), None);
        let vpn_every_minute = places(Some(("10m", "1m")), None);
        let both = places(Some(("10m", "5m")), Some("4h"));
        let always = places(None, Some("4h"));
        let flat_vpn = Schedule::legacy_vpn(probe(), interval("55m"));
        let flat_always = Schedule::legacy_always(interval("55m"));
        let go = |check, send| Plan { check, send };
        let idle = go(false, None);
        let rows: Vec<(&str, &Schedule, Place, State, i64, Plan)> = vec![
            // Off the VPN with only a VPN slot: nothing runs, whatever the state says.
            (
                "off the VPN",
                &vpn,
                Elsewhere,
                state(false, None, None, false),
                0,
                idle,
            ),
            (
                "off the VPN, event held",
                &vpn,
                Elsewhere,
                state(false, None, None, true),
                0,
                go(false, None),
            ),
            (
                "off the VPN, reconnect held",
                &vpn,
                Elsewhere,
                state(true, Some(99 * MIN), None, false),
                0,
                go(false, None),
            ),
            // A connect: check at once and send at once.
            (
                "connect, never sent",
                &vpn,
                Vpn,
                state(true, None, None, false),
                0,
                go(true, Some(Trigger::Connect)),
            ),
            (
                "connect, last answer 6 minutes ago",
                &vpn,
                Vpn,
                state(true, Some(6 * MIN), Some(6 * MIN), false),
                0,
                go(true, Some(Trigger::Connect)),
            ),
            // The flapping guard: an answer within five minutes holds the connect claim back, but the
            // first wake after the connect still checks.
            (
                "connect, last answer 3 minutes ago",
                &vpn,
                Vpn,
                state(true, Some(3 * MIN), None, false),
                0,
                go(true, None),
            ),
            (
                "connect, last answer 4m59s ago",
                &vpn,
                Vpn,
                state(true, Some(5 * MIN - 1), None, false),
                0,
                go(true, None),
            ),
            (
                "connect, last answer 5m ago",
                &vpn,
                Vpn,
                state(true, Some(5 * MIN), None, false),
                0,
                go(true, Some(Trigger::Connect)),
            ),
            // Steady state on the VPN.
            (
                "steady, nothing due",
                &vpn,
                Vpn,
                state(false, Some(4 * MIN), Some(4 * MIN), false),
                0,
                go(false, None),
            ),
            (
                "steady, check due",
                &vpn,
                Vpn,
                state(false, Some(4 * MIN), Some(5 * MIN), false),
                0,
                go(true, None),
            ),
            (
                "steady, interval due",
                &vpn,
                Vpn,
                state(false, Some(10 * MIN), Some(MIN), false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
            (
                "steady, 9m59s since the answer",
                &vpn,
                Vpn,
                state(false, Some(10 * MIN - 1), Some(MIN), false),
                0,
                go(false, None),
            ),
            // A result that got worse sends at once, and its checks run again.
            (
                "event",
                &vpn,
                Vpn,
                state(false, Some(MIN), Some(MIN), true),
                0,
                go(true, Some(Trigger::Event)),
            ),
            (
                "event beats connect",
                &vpn,
                Vpn,
                state(true, None, None, true),
                0,
                go(true, Some(Trigger::Event)),
            ),
            // The check period comes from the manifest, and Windows raises it to five minutes.
            (
                "check every minute, 59 s",
                &vpn_every_minute,
                Vpn,
                state(false, Some(MIN), Some(MIN - 1), false),
                0,
                go(false, None),
            ),
            (
                "check every minute, 60 s",
                &vpn_every_minute,
                Vpn,
                state(false, Some(MIN), Some(MIN), false),
                0,
                go(true, None),
            ),
            (
                "check every minute, Windows floor",
                &vpn_every_minute,
                Vpn,
                state(false, Some(MIN), Some(4 * MIN), false),
                300,
                go(false, None),
            ),
            (
                "check every minute, Windows floor reached",
                &vpn_every_minute,
                Vpn,
                state(false, Some(MIN), Some(5 * MIN), false),
                300,
                go(true, None),
            ),
            (
                "a clock that ran back checks",
                &vpn,
                Vpn,
                state(false, Some(MIN), Some(-5 * MIN), false),
                0,
                go(true, None),
            ),
            // Both slots: elsewhere checks every five minutes and sends on the always interval.
            (
                "both, elsewhere, nothing due",
                &both,
                Elsewhere,
                state(false, Some(MIN), Some(4 * MIN), false),
                0,
                go(false, None),
            ),
            (
                "both, elsewhere, check due",
                &both,
                Elsewhere,
                state(false, Some(MIN), Some(5 * MIN), false),
                0,
                go(true, None),
            ),
            (
                "both, elsewhere, interval due",
                &both,
                Elsewhere,
                state(false, Some(4 * 60 * MIN), Some(MIN), false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
            (
                "both, elsewhere, event",
                &both,
                Elsewhere,
                state(false, Some(MIN), Some(MIN), true),
                0,
                go(true, Some(Trigger::Event)),
            ),
            (
                "both, on the VPN, VPN interval",
                &both,
                Vpn,
                state(false, Some(10 * MIN), Some(MIN), false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
            (
                "both, on the VPN, connect",
                &both,
                Vpn,
                state(true, Some(60 * MIN), None, false),
                0,
                go(true, Some(Trigger::Connect)),
            ),
            // Always only: no probe, the place is always elsewhere.
            (
                "always, never sent",
                &always,
                Elsewhere,
                state(false, None, None, false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
            (
                "always, nothing due",
                &always,
                Elsewhere,
                state(false, Some(MIN), Some(MIN), false),
                0,
                go(false, None),
            ),
            // The flat 0.7 forms keep their interval gating: the connect claim waits for it.
            (
                "flat vpn, connect inside the interval",
                &flat_vpn,
                Vpn,
                state(true, Some(10 * MIN), None, false),
                0,
                go(true, None),
            ),
            (
                "flat vpn, connect after the interval",
                &flat_vpn,
                Vpn,
                state(true, Some(55 * MIN), None, false),
                0,
                go(true, Some(Trigger::Connect)),
            ),
            (
                "flat vpn, steady check",
                &flat_vpn,
                Vpn,
                state(false, Some(10 * MIN), Some(5 * MIN), false),
                0,
                go(true, None),
            ),
            (
                "flat vpn, off the VPN",
                &flat_vpn,
                Elsewhere,
                state(false, None, None, false),
                0,
                go(false, None),
            ),
            (
                "flat always, first wake",
                &flat_always,
                Elsewhere,
                state(false, None, None, false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
            (
                "flat always, between",
                &flat_always,
                Elsewhere,
                state(false, Some(10 * MIN), Some(MIN), false),
                0,
                go(false, None),
            ),
            (
                "flat always, at the interval",
                &flat_always,
                Elsewhere,
                state(false, Some(55 * MIN), Some(MIN), false),
                0,
                go(true, Some(Trigger::Periodic)),
            ),
        ];
        for (name, schedule, place, state, floor, expected) in rows {
            assert_eq!(plan(schedule, &state, place, T, floor), expected, "{name}");
        }
    }

    #[test]
    fn a_wake_with_nothing_due_is_idle_and_a_due_claim_always_checks() {
        let vpn = places(Some(("10m", "5m")), None);
        let quiet = plan(
            &vpn,
            &state(false, Some(MIN), Some(MIN), false),
            Place::Vpn,
            T,
            0,
        );
        assert!(quiet.idle());
        for send_due in [
            state(false, Some(10 * MIN), Some(MIN), false),
            state(false, Some(MIN), Some(MIN), true),
            state(true, None, Some(MIN), false),
        ] {
            let due = plan(&vpn, &send_due, Place::Vpn, T, 0);
            assert!(due.send.is_some() && due.check && !due.idle());
        }
    }

    #[test]
    fn a_connect_clears_the_last_check_so_the_first_wake_checks() {
        let mut state = State {
            last_check: Some(T),
            ..State::default()
        };
        state.observe(false);
        assert_eq!(state.last_check, Some(T), "off the VPN changes nothing");
        state.observe(true);
        assert!(state.reconnect_pending);
        assert_eq!(state.last_check, None);
        state.last_check = Some(T);
        state.observe(true);
        assert_eq!(state.last_check, Some(T), "staying connected is no connect");
    }

    /// The decisions the flat 0.7 VPN form made before `plan`: the old tests still hold them.
    impl State {
        fn due(&self, now: i64, interval: i64) -> Option<Trigger> {
            let schedule = open_pact_core::Schedule::legacy_vpn(
                open_pact_core::Probe {
                    address: open_pact_core::ProbeAddress::try_from("10.0.0.1:443".to_owned())
                        .unwrap(),
                    name: None,
                },
                open_pact_core::Interval::try_from(format!("{}m", interval / 60)).unwrap(),
            );
            let place = if self.vpn_up {
                Place::Vpn
            } else {
                Place::Elsewhere
            };
            plan(&schedule, self, place, now, 0).send
        }

        fn should_send(&self, now: i64, interval: i64) -> bool {
            self.vpn_up && self.interval_elapsed(now, interval)
        }
    }

    fn every_55_minutes_on_the_vpn(probe: &str) -> open_pact_core::Schedule {
        open_pact_core::Schedule::legacy_vpn(
            open_pact_core::Probe {
                address: open_pact_core::ProbeAddress::try_from(probe.to_owned()).unwrap(),
                name: None,
            },
            open_pact_core::Interval::try_from("55m".to_owned()).unwrap(),
        )
    }

    #[test]
    fn schedule_reconcile_covers_install_update_remove_and_retry() {
        let settings = Applied {
            run_as: RunAs::User,
            executable: PathBuf::from("/opt/example/client"),
            user_home: None,
        };
        let missing = Observed::default();
        let matching = Observed {
            exists: true,
            matches: true,
            ..Observed::default()
        };
        assert_eq!(reconcile(Some(&settings), None, &missing), Change::Install);
        assert_eq!(
            reconcile(Some(&settings), Some(&settings), &matching),
            Change::None
        );
        assert_eq!(
            reconcile(Some(&settings), Some(&settings), &missing),
            Change::Install
        );
        assert_eq!(reconcile(None, Some(&settings), &matching), Change::Remove);
        assert_eq!(reconcile(None, None, &missing), Change::None);
        assert_eq!(
            reconcile(
                None,
                None,
                &Observed {
                    leftovers: true,
                    ..Observed::default()
                }
            ),
            Change::Remove
        );
        for changed in [
            Applied {
                executable: PathBuf::from("/opt/example/other-client"),
                ..settings.clone()
            },
            Applied {
                run_as: RunAs::System,
                ..settings.clone()
            },
        ] {
            assert_eq!(
                reconcile(Some(&changed), Some(&settings), &matching),
                Change::Update
            );
        }
        assert_eq!(
            reconcile(
                Some(&settings),
                Some(&settings),
                &Observed {
                    matches: false,
                    ..matching
                }
            ),
            Change::Update
        );
    }

    const MACHINE: &str = r"C:\Program Files\open-pact-client\open-pact-client.exe";

    /// The task state of a task that wakes every minute and runs `actions`.
    fn task_state(actions: &[(&str, &str)]) -> WindowsTaskState {
        WindowsTaskState {
            enabled: true,
            triggers: 1,
            trigger_enabled: true,
            trigger_type: Some(1),
            repetition: Some(WAKE_ISO.into()),
            actions: actions
                .iter()
                .map(|(path, args)| ObservedAction {
                    path: (*path).into(),
                    args: (*args).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn windows_reconcile_repairs_disabled_or_wrong_triggers() {
        let settings = Applied {
            run_as: RunAs::User,
            executable: PathBuf::from("C:\\Program Files\\open-pact\\open-pact-client.exe"),
            user_home: None,
        };
        let applied = Some(&settings);
        let observed = |task: WindowsTaskState| Observed {
            exists: true,
            matches: true,
            windows_task: Some(task),
            ..Observed::default()
        };
        let disabled = |change: fn(&mut WindowsTaskState)| {
            let mut task = task_state(&[]);
            change(&mut task);
            reconcile(Some(&settings), applied, &observed(task))
        };
        assert_eq!(
            disabled(|task| task.trigger_enabled = false),
            Change::Update
        );
        assert_eq!(disabled(|task| task.trigger_type = Some(7)), Change::Update);
        assert_eq!(disabled(|task| task.enabled = false), Change::Update);
        assert_eq!(disabled(|task| task.triggers = 2), Change::Update);
        assert_eq!(disabled(|_| {}), Change::None);
    }

    #[test]
    fn a_five_minute_job_is_rewritten_for_the_one_minute_wake() {
        let settings = Applied {
            run_as: RunAs::User,
            executable: PathBuf::from("C:\\Program Files\\open-pact\\open-pact-client.exe"),
            user_home: None,
        };
        let task = |repetition: Option<&str>| Observed {
            exists: true,
            matches: true,
            windows_task: Some(WindowsTaskState {
                repetition: repetition.map(str::to_owned),
                ..task_state(&[])
            }),
            ..Observed::default()
        };
        for stale in [Some("PT5M"), Some("PT10M"), None] {
            assert_eq!(
                reconcile(Some(&settings), Some(&settings), &task(stale)),
                Change::Update,
                "{stale:?}"
            );
        }
        assert_eq!(
            reconcile(Some(&settings), Some(&settings), &task(Some("PT1M"))),
            Change::None
        );
    }

    /// What the observation script prints for a task: one compressed JSON object.
    fn observation(principal: &str, task: &WindowsTaskState) -> String {
        serde_json::json!({
            "exists": true,
            "principal": principal,
            "enabled": task.enabled,
            "triggers": task.triggers,
            "trigger_enabled": task.trigger_enabled,
            "trigger_type": task.trigger_type,
            "repetition": task.repetition,
            "actions": task
                .actions
                .iter()
                .map(|action| serde_json::json!({"path": action.path, "args": action.args}))
                .collect::<Vec<_>>(),
        })
        .to_string()
    }

    fn observed_task(principal: &str, task: &WindowsTaskState) -> Observed {
        let parsed = parse_windows_task(&observation(principal, task)).unwrap();
        Observed {
            exists: parsed.exists,
            system: parsed.system,
            windows_task: parsed.task,
            ..Observed::default()
        }
    }

    #[test]
    fn the_observation_output_reads_back_into_the_task_state() {
        let task = task_state(&[(MACHINE, "\"--home\" \"x\""), ("\"C:\\a b\\c.exe\"", "")]);
        let parsed = parse_windows_task(&observation("system", &task)).unwrap();
        assert!(parsed.exists && parsed.system);
        assert_eq!(parsed.task, Some(task));
        let user = parse_windows_task(
            r#"{"exists":true,"principal":"user","enabled":false,"triggers":0,"trigger_enabled":false,"trigger_type":null,"repetition":null,"actions":[]}"#,
        )
        .unwrap();
        assert!(user.exists && !user.system);
        assert_eq!(
            user.task.map(|task| (task.enabled, task.triggers)),
            Some((false, 0))
        );
        let missing = parse_windows_task(r#"{"exists":false}"#).unwrap();
        assert!(!missing.exists && missing.task.is_none());
        // Windows PowerShell 5.1 can write one action as the object itself.
        let one = parse_windows_task(
            r#"{"exists":true,"principal":"system","enabled":true,"triggers":1,"trigger_enabled":true,"trigger_type":1,"repetition":"PT1M","actions":{"path":"a.exe","args":"x"}}"#,
        )
        .unwrap();
        assert_eq!(one.task.unwrap().actions.len(), 1);
    }

    #[test]
    fn an_observation_that_is_not_one_complete_object_is_an_error() {
        for output in [
            "",
            "missing",
            "user\nmatches",
            r#"{"exists":true}"#,
            r#"{"exists":true,"principal":"nobody","enabled":true,"triggers":0,"trigger_enabled":false,"actions":[]}"#,
            r#"{"exists":true,"principal":"user","enabled":true,"triggers":0,"trigger_enabled":false,"actions":[]} {"exists":false}"#,
            r#"{"exists":false,"principal":"system","extra":1}"#,
        ] {
            assert!(parse_windows_task(output).is_err(), "{output}");
        }
    }

    #[test]
    fn a_task_cannot_write_its_own_principal_into_its_fields() {
        // A user's task whose arguments end in a line that says `system`: the old line format
        // read that line as the principal. Every text of the task is a JSON string now.
        let hostile = "--home h schedule run --system --user-home C:\\decoy\nsystem\nuser";
        let task = task_state(&[(MACHINE, hostile)]);
        let parsed = parse_windows_task(&observation("user", &task)).unwrap();
        assert!(!parsed.system);
        assert_eq!(parsed.task.unwrap().actions[0].args, hostile);
        let output = observation("user", &task_state(&[(MACHINE, hostile)]));
        assert_eq!(output.lines().count(), 1, "{output}");
    }

    #[test]
    fn a_task_with_a_control_character_or_no_machine_path_is_never_ours() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        let _listed = crate::machine::list_profiles(&[&profile]);
        let home = dir.path().join("pact");
        let args = machine_args(&home, &profile);
        let classify = |machine: &str, action: (&str, &str)| {
            observed_task("system", &task_state(&[action])).system_task(
                Path::new(machine),
                &home,
                Some(&profile),
            )
        };
        assert!(matches!(
            classify(MACHINE, (MACHINE, &args)),
            SystemTask::Ours { .. }
        ));
        let with_newline = format!("{args}\nsystem");
        assert!(matches!(
            classify(MACHINE, (MACHINE, &with_newline)),
            SystemTask::NotOurs { .. }
        ));
        let with_tab = format!("{MACHINE}\t");
        assert!(matches!(
            classify(MACHINE, (&with_tab, &args)),
            SystemTask::NotOurs { .. }
        ));
        // An empty path of the machine client equals an empty path of the action.
        assert!(matches!(
            classify("", ("", &args)),
            SystemTask::NotOurs { .. }
        ));
        // The text of the refusal shows a control character as `?`.
        let SystemTask::NotOurs { action } = classify(MACHINE, ("C:\\a\nb.exe", "")) else {
            panic!("not ours");
        };
        assert_eq!(action, "C:\\a?b.exe");
    }

    #[test]
    fn command_lines_split_like_command_line_to_argv() {
        for value in [
            "plain",
            "C:\\Users\\a b\\pact",
            "C:\\Users\\trailing\\",
            "quote\"inside",
            "back\\\\slash\\\"quote",
            "",
        ] {
            let line = [
                windows_arg("--home"),
                windows_arg(value),
                windows_arg("x y"),
            ]
            .join(" ");
            assert_eq!(
                split_windows_args(&line),
                ["--home", value, "x y"],
                "{value}"
            );
        }
        assert_eq!(split_windows_args("  a   b\tc "), ["a", "b", "c"]);
        assert_eq!(split_windows_args(""), Vec::<String>::new());
        assert_eq!(
            task_user_home(&format!(
                "{} {} {}",
                windows_arg("--system"),
                windows_arg("--user-home"),
                windows_arg("C:\\Users\\a b")
            )),
            Some("C:\\Users\\a b".to_owned())
        );
        assert_eq!(task_user_home("\"--system\""), None);
    }

    /// The arguments of the task that the machine client registers for `home` and `profile`.
    fn machine_args(home: &Path, profile: &Path) -> String {
        system_arguments(Path::new(MACHINE), home, profile).unwrap()
    }

    #[test]
    fn a_task_is_classified_by_its_principal_and_its_actions() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        let _listed = crate::machine::list_profiles(&[&profile]);
        let home = dir.path().join("pact");
        let args = machine_args(&home, &profile);
        let classify = |principal: &str, task: &WindowsTaskState| {
            observed_task(principal, task).system_task(Path::new(MACHINE), &home, Some(&profile))
        };
        let ours = task_state(&[(MACHINE, &args)]);

        assert_eq!(
            Observed::default().system_task(Path::new(MACHINE), &home, None),
            SystemTask::Missing
        );
        assert_eq!(
            classify("system", &ours),
            SystemTask::Ours {
                profile: Some(profile.clone()),
                current: true
            }
        );
        // The program comes back quoted, in any case, or with the extended-path prefix.
        for path in [
            format!("\"{MACHINE}\""),
            MACHINE.to_uppercase(),
            format!(r"\\?\{MACHINE}"),
        ] {
            assert!(
                matches!(
                    classify("system", &task_state(&[(&path, &args)])),
                    SystemTask::Ours { current: true, .. }
                ),
                "{path}"
            );
        }
        // No action, two actions and another program are not ours.
        for actions in [
            vec![],
            vec![(MACHINE, args.as_str()), (MACHINE, args.as_str())],
            vec![(r"C:\Windows\System32\cmd.exe", args.as_str())],
        ] {
            assert!(
                matches!(
                    classify("system", &task_state(&actions)),
                    SystemTask::NotOurs { .. }
                ),
                "{actions:?}"
            );
        }
        let SystemTask::NotOurs { action } = classify(
            "system",
            &task_state(&[(r"C:\Windows\System32\cmd.exe", "")]),
        ) else {
            panic!("not ours");
        };
        assert_eq!(action, r"C:\Windows\System32\cmd.exe");
        // Other arguments, a disabled task and a disabled trigger are ours and out of date.
        let other = machine_args(&home, &dir.path().join("elsewhere"));
        for task in [
            task_state(&[(MACHINE, &other)]),
            WindowsTaskState {
                enabled: false,
                ..ours.clone()
            },
            WindowsTaskState {
                trigger_enabled: false,
                ..ours.clone()
            },
            WindowsTaskState {
                repetition: Some("PT5M".into()),
                ..ours.clone()
            },
        ] {
            assert!(
                matches!(
                    classify("system", &task),
                    SystemTask::Ours { current: false, .. }
                ),
                "{task:?}"
            );
        }
        // A task that runs as a user is a user job, whatever it runs and carries: its profile is
        // never read.
        let decoy = task_state(&[(MACHINE, &machine_args(&home, Path::new(r"C:\decoy")))]);
        assert_eq!(classify("user", &decoy), SystemTask::User);
        assert_eq!(
            classify("user", &task_state(&[(r"C:\Windows\System32\cmd.exe", "")])),
            SystemTask::User
        );
    }

    #[test]
    fn only_a_valid_task_profile_counts() {
        let dir = tempfile::tempdir().unwrap();
        let _listed = crate::machine::list_profiles(&[dir.path()]);
        let home = dir.path().join("pact");
        let missing = dir.path().join("missing");
        let classify = |args: String| {
            observed_task("system", &task_state(&[(MACHINE, &args)])).system_task(
                Path::new(MACHINE),
                &home,
                None,
            )
        };
        assert_eq!(
            classify(machine_args(&home, &missing)),
            SystemTask::Ours {
                profile: None,
                current: false
            }
        );
        assert_eq!(
            classify(machine_args(&home, Path::new("relative"))),
            SystemTask::Ours {
                profile: None,
                current: false
            }
        );
        assert_eq!(
            classify(machine_args(&home, dir.path())),
            SystemTask::Ours {
                profile: Some(dir.path().to_path_buf()),
                current: true
            }
        );
    }

    #[test]
    fn only_a_system_install_reads_the_profile_list() {
        let dir = tempfile::tempdir().unwrap();
        let _listed = crate::machine::list_profiles(&[dir.path()]);
        let reads = || crate::machine::PROFILE_READS.with(std::cell::Cell::get);
        let before = reads();
        // Plain user-mode and removal commands start no PowerShell for a profile.
        assert_eq!(printable_profiles(false, None), (None, None));
        assert_eq!(printable_profiles(false, Some(dir.path())), (None, None));
        assert_eq!(reads(), before);
        let (explicit, caller) = printable_profiles(true, Some(dir.path()));
        assert_eq!(explicit.as_deref(), Some(dir.path()));
        assert_eq!(caller.as_deref(), Some(dir.path()));
        assert!(reads() > before);
        // Without `--user-home`, the profile of this account is the caller's, and `USERPROFILE`
        // is never read.
        assert_eq!(
            printable_profiles(true, None),
            (None, Some(dir.path().to_path_buf()))
        );
    }

    #[test]
    fn the_profile_comes_from_the_argument_then_the_task_then_userprofile() {
        let dir = tempfile::tempdir().unwrap();
        let (argument, task, own) = (
            dir.path().join("argument"),
            dir.path().join("task"),
            dir.path().join("own"),
        );
        for folder in [&argument, &task, &own] {
            std::fs::create_dir(folder).unwrap();
        }
        // Windows lists the three folders as profiles. A folder that it does not list is refused.
        let _listed = crate::machine::list_profiles(&[&own, &argument, &task]);
        let choose = |argument: Option<&Path>, task: Option<&Path>, own: Option<&Path>| {
            choose_profile(argument, task, own.map(Path::to_path_buf))
        };
        assert_eq!(
            choose(Some(&argument), Some(&task), Some(&own)).unwrap(),
            argument
        );
        assert_eq!(choose(None, Some(&task), Some(&own)).unwrap(), task);
        assert_eq!(choose(None, None, Some(&own)).unwrap(), own);
        // An invalid argument refuses, and so does an invalid or missing USERPROFILE.
        assert!(choose(Some(&dir.path().join("nope")), Some(&task), Some(&own)).is_err());
        assert!(choose(Some(Path::new("relative")), None, Some(&own)).is_err());
        assert!(choose(None, None, Some(&dir.path().join("nope"))).is_err());
        assert!(choose(None, None, None).is_err());
    }

    #[test]
    fn a_receipt_that_names_an_old_path_is_the_same_intent_for_a_system_job() {
        let system = |executable: &str| Applied {
            run_as: RunAs::System,
            executable: PathBuf::from(executable),
            user_home: Some(PathBuf::from("/profile")),
        };
        assert!(system("old").same_intent(&system(MACHINE)));
        assert!(!system(MACHINE).same_intent(&Applied {
            user_home: Some(PathBuf::from("/other")),
            ..system(MACHINE)
        }));
        let user = |executable: &str| Applied {
            run_as: RunAs::User,
            executable: PathBuf::from(executable),
            user_home: None,
        };
        assert!(!user("a").same_intent(&user("b")));
        assert!(user("a").same_intent(&user("a")));
        assert!(!user("a").same_intent(&system("a")));
        // The observed task, not the receipt, decides what changes.
        let observed = Observed {
            exists: true,
            matches: true,
            system: true,
            windows_task: Some(task_state(&[])),
            ..Observed::default()
        };
        let desired = system(MACHINE);
        assert_eq!(
            reconcile(Some(&desired), Some(&system("old")), &observed),
            Change::None
        );
        assert_eq!(
            reconcile(
                Some(&desired),
                Some(&Applied {
                    user_home: None,
                    ..system(MACHINE)
                }),
                &observed
            ),
            Change::Update
        );
    }

    const OLD_WAKE: &str = "<integer>300</integer>";
    const NEW_WAKE: &str = "<integer>60</integer>";

    /// A home that agreed to the signed schedule and a LaunchAgent file in `dir` that still has
    /// the five-minute wake an older client wrote.
    fn stale_launch_agent(dir: &Path) -> (Home, PathBuf, Job) {
        let home = enrolled_home_with_schedule(dir, Some(&vpn_table("127.0.0.1:1")));
        agree(&home);
        let job = Job::new(Path::new("/opt/open-pact/open-pact-client"), &home.0).unwrap();
        let plist = dir.join("agent.plist");
        std::fs::write(&plist, job.plist().replace(NEW_WAKE, OLD_WAKE)).unwrap();
        (home, plist, job)
    }

    /// What `observe` reads from the file on macOS, without `launchctl`.
    fn observed_file(plist: &Path, job: &Job) -> Result<Observed> {
        let stored = read_text_if_exists(plist)?;
        Ok(Observed {
            exists: stored.is_some(),
            matches: stored.as_deref() == Some(job.plist().as_str()),
            ..Observed::default()
        })
    }

    fn wake(
        home: &Home,
        plist: &Path,
        job: &Job,
        submitted: &std::cell::RefCell<Vec<String>>,
    ) -> Result<bool> {
        refresh_job_with(
            home,
            Path::new("/opt/open-pact/open-pact-client"),
            |_| observed_file(plist, job),
            |job| {
                macos_rewrite(job, plist, "gui/501", |args| {
                    submitted.borrow_mut().push(args.join(" "));
                    Ok(())
                })
            },
        )
    }

    #[test]
    fn a_wake_rewrites_a_five_minute_launch_agent_to_one_minute_and_twice_is_the_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        let submitted = std::cell::RefCell::new(Vec::new());
        assert!(wake(&home, &plist, &job, &submitted).unwrap());
        let rewritten = std::fs::read_to_string(&plist).unwrap();
        assert!(rewritten.contains(NEW_WAKE) && !rewritten.contains(OLD_WAKE));
        assert_eq!(rewritten, job.plist());
        assert_eq!(submitted.borrow().len(), 1);
        assert!(
            submitted.borrow()[0].contains(&format!("bootout 'gui/501/{}'", job.id)),
            "{:?}",
            submitted.borrow()
        );
        assert_eq!(read_applied(&home).unwrap().unwrap().run_as, RunAs::User);
        // The same version does not look again; a forgotten mark still finds nothing to change.
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());
        remove_if_exists(&home.file(JOB_REFRESH)).unwrap();
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());
        assert_eq!(std::fs::read_to_string(&plist).unwrap(), rewritten);
        assert_eq!(submitted.borrow().len(), 1);
    }

    #[test]
    fn a_wake_leaves_a_job_the_owner_turned_off_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        let mut config = DeviceConfig::load(&home).unwrap();
        config.auto_send = false;
        config.save(&home).unwrap();
        let submitted = std::cell::RefCell::new(Vec::new());
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());
        assert!(std::fs::read_to_string(&plist).unwrap().contains(OLD_WAKE));
        assert!(submitted.borrow().is_empty());
        assert!(!home.file(JOB_REFRESH).exists());
        assert!(!home.file(APPLIED).exists());
    }

    #[test]
    fn a_wake_does_not_widen_what_the_owner_agreed_to() {
        // No signed schedule, a SYSTEM choice and a vanished job all leave the file as it is.
        let submitted = std::cell::RefCell::new(Vec::new());
        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        enrolled_home_with_schedule(dir.path(), Some(""));
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        let mut config = DeviceConfig::load(&home).unwrap();
        config.run_as = RunAs::System;
        config.save(&home).unwrap();
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        std::fs::remove_file(&plist).unwrap();
        assert!(!wake(&home, &plist, &job, &submitted).unwrap());
        assert!(!plist.exists(), "a missing job is not installed by a wake");

        assert!(submitted.borrow().is_empty());
    }

    #[test]
    fn a_launch_agent_keeps_its_old_file_when_the_reload_cannot_be_queued() {
        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        let old = std::fs::read_to_string(&plist).unwrap();
        let failed = refresh_job_with(
            &home,
            Path::new("/opt/open-pact/open-pact-client"),
            |_| observed_file(&plist, &job),
            |job| macos_rewrite(job, &plist, "gui/501", |_| bail!("launchd refused")),
        );
        assert!(failed.is_err());
        assert_eq!(std::fs::read_to_string(&plist).unwrap(), old);
        let submitted = std::cell::RefCell::new(Vec::new());
        assert!(
            !wake(&home, &plist, &job, &submitted).unwrap(),
            "one attempt for each client version"
        );
    }

    #[test]
    fn a_failed_look_at_the_job_is_not_repeated_every_minute() {
        let dir = tempfile::tempdir().unwrap();
        let (home, plist, job) = stale_launch_agent(dir.path());
        let executable = Path::new("/opt/open-pact/open-pact-client");
        let first = refresh_job_with(
            &home,
            executable,
            |_| bail!("PowerShell is blocked"),
            |_| unreachable!("a job that was not read is not rewritten"),
        );
        assert!(
            first.is_err(),
            "the first failure reaches the caller to log"
        );
        let looked = std::cell::Cell::new(false);
        let second = refresh_job_with(
            &home,
            executable,
            |_| {
                looked.set(true);
                observed_file(&plist, &job)
            },
            |_| unreachable!(),
        );
        assert!(!second.unwrap());
        assert!(!looked.get(), "one attempt for each client version");
    }

    #[test]
    fn the_reload_helper_writes_its_output_to_the_job_log() {
        let job = Job::new(Path::new("/opt/o/client"), Path::new("/tmp/pact")).unwrap();
        let submitted = std::cell::RefCell::new(Vec::new());
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("a.plist");
        macos_rewrite(&job, &plist, "gui/501", |args| {
            submitted
                .borrow_mut()
                .extend(args.iter().map(|a| a.to_string()));
            Ok(())
        })
        .unwrap();
        let args = submitted.borrow();
        for flag in ["-o", "-e"] {
            let at = args.iter().position(|arg| arg == flag).unwrap();
            assert_eq!(args[at + 1], job.log);
        }
    }

    #[test]
    fn check_stays_silent_when_the_job_is_current_in_another_copy_of_the_client() {
        let other = Applied {
            run_as: RunAs::User,
            executable: PathBuf::from("/opt/homebrew/bin/open-pact-client"),
            user_home: None,
        };
        let here = Path::new("/Applications/Open Pact.app/open-pact-client");
        let current = |_: &Applied| {
            Ok(Observed {
                exists: true,
                matches: true,
                ..Observed::default()
            })
        };
        assert!(runs_another_current_copy(here, &other, current));
        // The other copy's own job is stale or unreadable: say nothing different from `status`.
        assert!(!runs_another_current_copy(here, &other, |_| Ok(Observed {
            exists: true,
            matches: false,
            ..Observed::default()
        })));
        assert!(!runs_another_current_copy(here, &other, |_| bail!("no")));
        // The recorded copy is this one: nothing is "another copy".
        assert!(!runs_another_current_copy(
            &other.executable,
            &other,
            current
        ));
    }

    #[test]
    fn the_reload_script_quotes_paths_for_the_shell() {
        assert_eq!(shell_quote("a'b c"), "'a'\"'\"'b c'");
        let job = Job::new(Path::new("/opt/o p/client"), Path::new("/tmp/it's home")).unwrap();
        let submitted = std::cell::RefCell::new(Vec::new());
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("it's.plist");
        macos_rewrite(&job, &plist, "gui/501", |args| {
            submitted
                .borrow_mut()
                .extend(args.iter().map(|a| a.to_string()));
            Ok(())
        })
        .unwrap();
        let args = submitted.borrow();
        assert_eq!(&args[..2], ["submit", "-l"]);
        let script = args.last().unwrap();
        assert!(script.contains("it'\"'\"'s.plist"), "{script}");
        assert!(script.ends_with(&format!("launchctl remove '{}.refresh'", job.id)));
    }

    #[test]
    fn check_names_the_command_that_fixes_an_outdated_user_job() {
        let home = Path::new("fixture-home");
        let outdated = JobInspection::from(JobStatus::Outdated);
        let line = outdated.job_fix(home).unwrap();
        assert!(
            line.starts_with("The scheduled job is out of date. Run `open-pact-client"),
            "{line}"
        );
        assert!(line.ends_with("schedule on`."), "{line}");
        for quiet in [
            JobStatus::Current,
            JobStatus::Missing,
            JobStatus::Absent,
            JobStatus::Leftover,
            JobStatus::SystemUnconfirmed,
        ] {
            assert_eq!(JobInspection::from(quiet).job_fix(home), None);
        }
    }

    fn system_inspection(
        job: JobStatus,
        machine: MachineClient,
        task: Option<SystemTask>,
        receipt: Option<&str>,
    ) -> JobInspection {
        let machine_state =
            crate::machine::machine_state(&machine, &crate::machine::running_version());
        JobInspection {
            job,
            system: Some(SystemInspection {
                machine,
                machine_state,
                task,
                receipt: receipt.map(PathBuf::from),
                task_id: "org.open-pact.report.0123456789abcdef".into(),
                query_error: None,
            }),
        }
    }

    fn present(version: &str) -> MachineClient {
        MachineClient::Present {
            version: semver::Version::parse(version).unwrap(),
        }
    }

    #[test]
    fn the_package_and_the_task_each_have_their_own_fix() {
        let home = Path::new("fixture-home");
        let current = env!("CARGO_PKG_VERSION");
        let ours = |current| {
            Some(SystemTask::Ours {
                profile: None,
                current,
            })
        };
        // A current machine client and a task that runs it need nothing.
        let fine = system_inspection(JobStatus::Current, present(current), ours(true), None);
        assert_eq!((fine.machine_fix(), fine.job_fix(home)), (None, None));
        // An outdated machine client gets the upgrade block and the restart sentence, and the task
        // still reports on its own.
        let outdated = system_inspection(JobStatus::Outdated, present("0.0.1"), ours(false), None);
        let machine = outdated.machine_fix().unwrap();
        assert!(machine.contains(
            "Upgrade it from an elevated Windows PowerShell 5.1 prompt (powershell.exe, not pwsh)"
        ));
        assert!(machine.contains("restart Windows"));
        assert!(
            outdated
                .job_fix(home)
                .unwrap()
                .contains("schedule on --system")
        );
        // A missing machine client gets the install block; a missing task then has no command of
        // its own, because the package line covers it.
        let missing = system_inspection(
            JobStatus::Missing,
            MachineClient::Missing,
            Some(SystemTask::Missing),
            None,
        );
        assert!(missing.machine_fix().unwrap().contains("msiexec.exe"));
        assert_eq!(missing.job_fix(home), None);
        let usable = system_inspection(
            JobStatus::Missing,
            present(current),
            Some(SystemTask::Missing),
            None,
        );
        assert!(
            usable
                .job_fix(home)
                .unwrap()
                .contains("schedule on --system")
        );
        // An unreadable machine client says so and gives no block.
        let unknown = system_inspection(
            JobStatus::Current,
            MachineClient::Unknown {
                reason: "probe failed".into(),
            },
            ours(true),
            None,
        );
        assert_eq!(
            unknown.machine_fix().unwrap(),
            "Cannot read the machine client: probe failed."
        );
        // An unprotected one never says to reinstall alone.
        let unprotected = system_inspection(
            JobStatus::Current,
            MachineClient::Unprotected {
                reason: "grants write".into(),
            },
            ours(true),
            None,
        );
        let text = unprotected.machine_fix().unwrap();
        assert!(text.contains("Ask IT, or uninstall the machine client and install it again"));
        // A task that is not ours gets the removal block, then the install block when needed, then
        // the machine client's command. The caller's own path never appears.
        let not_ours = system_inspection(
            JobStatus::NotOurs,
            MachineClient::Missing,
            Some(SystemTask::NotOurs {
                action: r"C:\Windows\System32\cmd.exe".into(),
            }),
            None,
        );
        let text = not_ours.job_fix(home).unwrap();
        let removal = text.find("schtasks.exe").unwrap();
        let install = text.find("Then:\n").unwrap();
        let command = text.find("Then run:").unwrap();
        assert!(removal < install && install < command, "{text}");
        assert!(text.contains("open-pact does not change it"));
        assert!(!text.contains("Remove-Item"));
        assert!(!text.contains(std::env::current_exe().unwrap().to_str().unwrap()));
    }

    #[test]
    fn a_standard_user_cannot_confirm_the_task_and_the_receipt_is_a_hint() {
        let home = Path::new("fixture-home");
        let machine = crate::machine::machine_path();
        let unconfirmed = |receipt: Option<&str>| {
            system_inspection(
                JobStatus::SystemUnconfirmed,
                present(env!("CARGO_PKG_VERSION")),
                None,
                receipt,
            )
            .job_fix(home)
            .unwrap()
        };
        let limitation = "SYSTEM job installation is unconfirmed. Ask IT to inspect the task from an elevated PowerShell prompt.";
        assert_eq!(unconfirmed(None), limitation);
        assert_eq!(unconfirmed(machine.to_str()), limitation);
        let other = unconfirmed(Some(r"C:\Program Files\open-pact\open-pact-client.exe"));
        assert!(other.contains("which is not the machine package"));
        assert!(other.contains("not confirmed"));
    }

    #[test]
    fn the_stop_text_never_names_the_caller_and_chooses_by_package_and_task() {
        let home = Path::new("fixture-home");
        let caller = std::env::current_exe().unwrap();
        let caller = caller.to_str().unwrap();
        for (state, not_ours) in [
            (MachineState::Current, false),
            (MachineState::Outdated, false),
            (MachineState::Missing, false),
            (MachineState::Unprotected, false),
            (MachineState::Unknown, false),
            (MachineState::Current, true),
        ] {
            let text = stop_text_for(home, state, not_ours);
            assert!(!text.contains(caller), "{state:?} {not_ours}: {text}");
            let command_only = !text.contains("schtasks.exe");
            assert_eq!(
                command_only,
                matches!(state, MachineState::Current | MachineState::Outdated) && !not_ours,
                "{state:?} {not_ours}: {text}"
            );
            assert!(command_only || !text.contains("Remove-Item"), "{text}");
        }
    }

    #[test]
    fn every_elevation_text_names_the_machine_client_or_the_install_block() {
        let home = Path::new("fixture-home");
        let caller = std::env::current_exe().unwrap();
        let caller = caller.to_str().unwrap();
        let machine = crate::machine::machine_path();
        let machine = machine.to_str().unwrap().to_owned();
        let current = present(env!("CARGO_PKG_VERSION"));
        for wanted in [
            Wanted::On(RunAs::System),
            Wanted::On(RunAs::User),
            Wanted::Off,
        ] {
            for client in [
                current.clone(),
                MachineClient::Missing,
                MachineClient::Unprotected { reason: "x".into() },
                MachineClient::Unknown { reason: "x".into() },
            ] {
                let text = system_retry_text(home, wanted, &client, None, true);
                assert!(!text.contains(caller), "{wanted:?} {client:?}: {text}");
                let usable = matches!(client, MachineClient::Present { .. });
                match (wanted, usable) {
                    (Wanted::On(RunAs::System), true) => {
                        assert!(text.contains("schedule on --system"), "{text}");
                    }
                    // Only an install block puts a verified machine client in place. A machine
                    // client that is unprotected or unreadable is never run by a line of the text.
                    (Wanted::On(RunAs::System), false) => {
                        let installs = matches!(client, MachineClient::Missing);
                        assert_eq!(text.contains("Then run:"), installs, "{client:?}: {text}");
                        assert!(
                            installs || !text.contains("schedule on --system"),
                            "{client:?}: {text}"
                        );
                        assert_eq!(
                            text.contains("msiexec.exe"),
                            !matches!(client, MachineClient::Unknown { .. }),
                            "{client:?}: {text}"
                        );
                    }
                    (_, true) => assert!(text.contains("schedule off"), "{text}"),
                    // Only the removal of a task that inspection found to be ours gets the
                    // block. A switch to user mode gets the package fix.
                    (Wanted::Off, false) => assert!(text.contains("schtasks.exe"), "{text}"),
                    (_, false) => assert!(!text.contains("schtasks.exe"), "{wanted:?}: {text}"),
                }
                // Without a task that inspection found, no request gets the removal block.
                let unfound = system_retry_text(home, wanted, &client, None, false);
                assert!(
                    usable
                        || wanted == Wanted::On(RunAs::System)
                        || !unfound.contains("schtasks.exe"),
                    "{wanted:?} {client:?}: {unfound}"
                );
                if usable {
                    assert!(text.contains(&machine) || machine.is_empty(), "{text}");
                }
            }
        }
        let with_profile = system_retry_text(
            home,
            Wanted::On(RunAs::System),
            &current,
            Some(Path::new("/owner's profile")),
            false,
        );
        assert!(
            with_profile.ends_with("--user-home '/owner''s profile'"),
            "{with_profile}"
        );
        let refusal = not_ours_text(home, Wanted::On(RunAs::System), "cmd.exe", &current, None);
        assert!(refusal.contains("runs cmd.exe, not the machine client"));
        assert!(refusal.contains("schtasks.exe") && refusal.contains("Then run:"));
        let off = not_ours_text(home, Wanted::Off, "cmd.exe", &current, None);
        assert!(off.contains("schtasks.exe") && !off.contains("Then run:"));
    }

    #[test]
    fn no_text_runs_the_machine_client_when_its_protection_check_did_not_pass() {
        let home = Path::new("fixture-home");
        let machine = crate::machine::machine_path();
        let machine = machine.to_str().unwrap().to_owned();
        let not_ours = || {
            Some(SystemTask::NotOurs {
                action: "cmd.exe".into(),
            })
        };
        let stale = || {
            Some(SystemTask::Ours {
                profile: None,
                current: false,
            })
        };
        for client in [
            MachineClient::Unprotected { reason: "x".into() },
            MachineClient::Unknown { reason: "x".into() },
        ] {
            for task in [
                Some(SystemTask::User),
                stale(),
                Some(SystemTask::Missing),
                not_ours(),
            ] {
                let inspection =
                    system_inspection(JobStatus::Outdated, client.clone(), task.clone(), None);
                // The task fix never invokes Q. An outdated task or a user's task says to repair the
                // package first.
                if let Some(fix) = inspection.job_fix(home) {
                    for change in ["schedule on --system", "schedule off"] {
                        let q = crate::machine::machine_command(
                            home,
                            change,
                            Path::new(&machine),
                            None,
                        );
                        assert!(!fix.contains(&q), "{client:?} {task:?}: {fix}");
                    }
                }
            }
            let user = system_inspection(
                JobStatus::Outdated,
                client.clone(),
                Some(SystemTask::User),
                None,
            );
            assert_eq!(user.job_fix(home).as_deref(), Some(PACKAGE_FIRST));
            let outdated = system_inspection(JobStatus::Outdated, client.clone(), stale(), None);
            assert_eq!(outdated.job_fix(home).as_deref(), Some(PACKAGE_FIRST));
            // A task that is not ours still gets its removal block, and no line after it runs Q.
            let text = system_inspection(JobStatus::NotOurs, client.clone(), not_ours(), None)
                .job_fix(home)
                .unwrap();
            assert!(
                text.contains("schtasks.exe") && !text.contains("Then run:"),
                "{client:?}: {text}"
            );
            // The text for turning the job on.
            let on = on_text_for(home, &client, None);
            assert!(
                !on.contains("Then run:") && !on.contains("schedule on --system"),
                "{client:?}: {on}"
            );
        }
        // A missing machine client gets an install block and then the command that runs it.
        let on = on_text_for(home, &MachineClient::Missing, None);
        assert!(
            on.contains("msiexec.exe")
                && on.contains("Then run:")
                && on.contains("schedule on --system")
        );
        // A usable one gets the command alone, outdated or current.
        for client in [present("0.0.1"), present(env!("CARGO_PKG_VERSION"))] {
            let on = on_text_for(home, &client, None);
            assert!(
                on.contains("schedule on --system") && !on.contains("Then run:"),
                "{on}"
            );
        }
        // The refusal for a task that is not ours offers the retry only after a usable or installed
        // machine client.
        for client in [
            MachineClient::Unprotected { reason: "x".into() },
            MachineClient::Unknown { reason: "x".into() },
        ] {
            let text = not_ours_text(home, Wanted::On(RunAs::System), "cmd.exe", &client, None);
            assert!(!text.contains("Then run:"), "{client:?}: {text}");
        }
    }

    #[test]
    fn the_retry_after_a_foreign_task_keeps_the_profile_the_owner_asked_for() {
        let home = Path::new("fixture-home");
        let profile = Path::new("/owner's profile");
        let text = not_ours_text(
            home,
            Wanted::On(RunAs::System),
            "cmd.exe",
            &present(env!("CARGO_PKG_VERSION")),
            Some(profile),
        );
        let retry = text.rsplit("Then run:\n").next().unwrap();
        assert!(retry.contains("schedule on --system"), "{retry}");
        assert!(
            retry.ends_with("--user-home '/owner''s profile'"),
            "{retry}"
        );
        let without = not_ours_text(
            home,
            Wanted::On(RunAs::System),
            "cmd.exe",
            &present(env!("CARGO_PKG_VERSION")),
            None,
        );
        assert!(!without.contains("--user-home"), "{without}");
    }

    #[test]
    fn local_revoked_status_and_install_name_the_same_job_for_any_spelling_of_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("pact");
        std::fs::create_dir(&home).unwrap();
        // The same folder, spelled with a detour. A system temp folder is often a link, so the
        // canonical spelling differs from the given one too.
        let detour = dir.path().join("elsewhere").join("..").join("pact");
        let installed = Job::new(
            Path::new("open-pact-client.exe"),
            &schedule_home(&detour, true).unwrap(),
        )
        .unwrap()
        .id;
        assert_eq!(os_job_id(&detour).unwrap(), installed);
        assert_eq!(os_job_id(&home).unwrap(), installed);
        // The raw spelling is a different hash: the bug that this guards.
        assert_ne!(task_id(&detour).unwrap(), installed);
        let quoted = format!("'{installed}'");
        for spelling in [&home, &detour] {
            let text = system_stop_text_unprobed(spelling);
            assert!(text.contains(&quoted), "{spelling:?}: {text}");
            assert_eq!(text, system_stop_text_unprobed(&home));
        }
    }

    #[test]
    fn a_failed_task_query_never_offers_the_caller_and_keeps_the_package_check() {
        let home = Path::new("fixture-home");
        let user_install = r"C:\Users\example\scoop\apps\open-pact\current\open-pact-client.exe";
        for client in [
            present(env!("CARGO_PKG_VERSION")),
            MachineClient::Missing,
            MachineClient::Unprotected { reason: "x".into() },
            MachineClient::Unknown { reason: "x".into() },
        ] {
            for (os, system_install) in [
                (open_pact_core::Os::Windows, true),
                (open_pact_core::Os::Windows, false),
                (open_pact_core::Os::Macos, true),
                (open_pact_core::Os::Linux, true),
            ] {
                let error = anyhow::anyhow!("access is denied");
                let text = inspect_failure_text(home, os, &client, system_install, &error);
                assert!(
                    text.starts_with("Cannot inspect the scheduled job: access is denied"),
                    "{text}"
                );
                assert!(!text.contains(user_install), "{text}");
                assert!(
                    !text.contains(std::env::current_exe().unwrap().to_str().unwrap()),
                    "{text}"
                );
                // The state is unknown: no text says to stop, turn off or remove the job, and no
                // text offers a command of another platform.
                assert!(
                    !text.contains("schedule off") && !text.contains("schedule on"),
                    "{os:?}: {text}"
                );
                assert!(!text.contains("schtasks.exe"), "{os:?}: {text}");
                let step = |needle: &str| text.contains(needle);
                match os {
                    open_pact_core::Os::Macos => {
                        assert!(step("launchctl print gui/$(id -u)/org.open-pact.report."));
                        assert!(!step("powershell") && !step("systemctl"), "{text}");
                    }
                    open_pact_core::Os::Linux => {
                        assert!(step("systemctl --user status org.open-pact.report."));
                        assert!(!step("PowerShell") && !step("launchctl"), "{text}");
                    }
                    open_pact_core::Os::Windows if !system_install => {
                        // A user job or a removal reads the task without the MSI, whatever the
                        // package state is.
                        assert!(step("Get-ScheduledTask -TaskName"), "{text}");
                        assert!(
                            !step("schedule status") && !step("msiexec") && !step("machine client"),
                            "{client:?}: {text}"
                        );
                    }
                    open_pact_core::Os::Windows => {
                        assert!(!step("launchctl") && !step("systemctl"), "{text}");
                        // The machine client reads the job only after its protection check passed.
                        assert_eq!(
                            step("schedule status"),
                            !matches!(
                                client,
                                MachineClient::Unprotected { .. } | MachineClient::Unknown { .. }
                            ),
                            "{client:?}: {text}"
                        );
                    }
                }
            }
        }
        // The task query failed after the package check: the report keeps the package state and
        // marks the task unconfirmed, with the reason.
        let dir = tempfile::tempdir().unwrap();
        let state_home = Home(dir.path().to_path_buf());
        let inspection = system_job_from(
            &state_home,
            MachineClient::Missing,
            true,
            Path::new(MACHINE),
            None,
            |_| bail!("access is denied"),
        )
        .unwrap();
        assert_eq!(inspection.machine_state(), Some(MachineState::Missing));
        assert_eq!(inspection.job, JobStatus::SystemUnconfirmed);
        assert!(inspection.machine_fix().unwrap().contains("msiexec.exe"));
        let fix = inspection.job_fix(&state_home.0).unwrap();
        assert!(
            fix.contains("could not be read (access is denied)"),
            "{fix}"
        );
        // A standard user never queries the task at all.
        let user = system_job_from(
            &state_home,
            MachineClient::Missing,
            false,
            Path::new(MACHINE),
            None,
            |_| panic!("a standard user cannot read the task"),
        )
        .unwrap();
        assert_eq!(user.job, JobStatus::SystemUnconfirmed);
    }

    #[test]
    fn a_damaged_state_file_stops_the_wake_and_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        std::fs::write(home.file(STATE), b"{not json").unwrap();
        let error = note_client_version(&home, &home).unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        assert_eq!(std::fs::read(home.file(STATE)).unwrap(), b"{not json");
        // A missing file starts empty, and the version is saved once.
        std::fs::remove_file(home.file(STATE)).unwrap();
        note_client_version(&home, &home).unwrap();
        let state: State = home.read_json(STATE).unwrap().unwrap();
        assert_eq!(
            state.client_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn schedule_status_describes_the_choice_before_it_looks_at_the_task() {
        let line = system_choice_line(Path::new(MACHINE));
        assert!(line.contains("meant to run the machine client"), "{line}");
        assert!(
            !line.contains("The job runs") && !line.contains("is installed"),
            "{line}"
        );
    }

    #[test]
    fn a_system_task_that_is_not_ours_stops_every_change() {
        let home = Path::new("fixture-home");
        let not_ours = SystemTask::NotOurs {
            action: "cmd.exe".into(),
        };
        for wanted in [
            Wanted::On(RunAs::System),
            Wanted::On(RunAs::User),
            Wanted::Off,
        ] {
            assert!(refuse_not_ours(home, wanted, &not_ours, None).is_err());
        }
        for task in [
            SystemTask::Missing,
            SystemTask::User,
            SystemTask::Ours {
                profile: None,
                current: false,
            },
        ] {
            assert!(refuse_not_ours(home, Wanted::Off, &task, None).is_ok());
        }
    }

    #[test]
    fn the_windows_observation_asks_for_the_one_minute_repeat() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let script = windows_observation_script(&job);
        // The script reads the interval; Rust compares it with the one-minute wake.
        assert!(script.contains("repetition = "), "{script}");
        assert!(script.contains("[string]$trigger.Repetition.Interval"));
        assert_eq!(WAKE_ISO, "PT1M");
        assert!(!script.contains("PT5M"));
        // Every action is listed, so a task with two or none reads as not ours.
        assert!(script.contains("$task.Definition.Actions | ForEach-Object"));
        // One JSON object, never lines of text.
        assert!(script.contains("ConvertTo-Json -Compress"));
        assert!(!script.contains("action_path=") && !script.contains("Write-Output 'system'"));
    }

    #[test]
    fn a_task_that_schtasks_just_created_matches_its_own_definition() {
        // What Task Scheduler returns for `schtasks /Create /TR` with the quoted command that
        // `schtasks_install` sends: the program keeps its quotes.
        let job = Job::new(
            Path::new("C:\\work\\open-pact-client.exe"),
            Path::new("C:\\Users\\a b\\pact"),
        )
        .unwrap();
        let expected = job
            .argv
            .iter()
            .skip(1)
            .map(|arg| windows_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let action = |path: &str, args: &str| ObservedAction {
            path: path.into(),
            args: args.into(),
        };
        let exe = "C:\\work\\open-pact-client.exe";
        assert!(observed_action_matches(
            &action(&format!("\"{exe}\""), &expected),
            exe,
            &expected
        ));
        assert!(observed_action_matches(
            &action(exe, &expected),
            exe,
            &expected
        ));
        assert!(observed_action_matches(
            &action("\"c:\\WORK\\open-pact-client.exe\"", &expected),
            exe,
            &expected
        ));
        // The home path in the arguments ignores case, as a Windows path does.
        assert!(observed_action_matches(
            &action(exe, &expected.replace("Users\\a b", "USERS\\A B")),
            exe,
            &expected
        ));
        assert!(!observed_action_matches(
            &action(&format!("\"{exe}\""), &expected),
            "C:\\other\\client.exe",
            &expected
        ));
        assert!(!observed_action_matches(
            &action(exe, "\"--home\" \"x\""),
            exe,
            &expected
        ));
    }

    #[test]
    fn the_words_of_a_task_compare_exactly_and_only_its_paths_ignore_case() {
        let expected = r#"--home "C:\Users\a\pact" schedule run --system --user-home "C:\Users\a""#;
        assert!(arguments_match(expected, expected));
        assert!(arguments_match(
            &expected.replace("Users\\a\\pact", "USERS\\A\\PACT"),
            expected
        ));
        // Clap refuses `schedule RUN`, so such a task is not current.
        assert!(!arguments_match(&expected.replace("run", "RUN"), expected));
        assert!(!arguments_match(
            &expected.replace("schedule", "Schedule"),
            expected
        ));
        assert!(!arguments_match(
            &expected.replace("--system", "--SYSTEM"),
            expected
        ));
        assert!(!arguments_match(&format!("{expected} --extra"), expected));
        assert!(!arguments_match("", expected));
    }

    #[test]
    fn limited_report_history_is_removed_and_counts_as_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        std::fs::write(home.file("reports.jsonl"), b"history\n").unwrap();
        std::fs::write(home.file("reports.jsonl.tmp"), b"partial\n").unwrap();

        assert!(home_schedule_has_leftovers(&home));
        remove_home_schedule_files(&home).unwrap();

        assert!(!home.file("reports.jsonl").exists());
        assert!(!home.file("reports.jsonl.tmp").exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_system_removal_does_not_delete_through_a_junction_at_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let root = PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\"));
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join(JOB_LOG), b"fictional log\n").unwrap();
        let home = root.join("home");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&home)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");

        let error = remove_protected_home_schedule_files(&Home(home)).unwrap_err();
        assert!(
            format!("{error:#}").contains("refuse the client home"),
            "{error:#}"
        );
        assert!(
            outside.join(JOB_LOG).exists(),
            "a file outside the home was deleted"
        );
    }

    #[test]
    fn system_state_removal_deletes_report_history() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("system-state");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join("reports.jsonl"), b"history\n").unwrap();
        std::fs::write(state.join("reports.jsonl.tmp"), b"partial\n").unwrap();

        remove_system_state_directory(&state).unwrap();

        assert!(!state.exists());
    }

    #[test]
    fn missing_home_keeps_the_install_task_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let home_path = dir.path().join("fictional-home");
        std::fs::create_dir(&home_path).unwrap();
        let install_home = schedule_home(&home_path, false).unwrap();
        let install_job = Job::new(Path::new("client"), &install_home).unwrap();
        std::fs::remove_dir(&home_path).unwrap();
        let uninstall_home = schedule_home(&home_path, true).unwrap();
        let uninstall_job = Job::new(Path::new("client"), &uninstall_home).unwrap();
        assert_eq!(install_home, uninstall_home);
        assert_eq!(install_job.id, uninstall_job.id);
        assert!(!home_path.exists());
    }

    fn jobs_before_and_after_home_removal() -> (Job, Job) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fictional-home");
        std::fs::create_dir(&path).unwrap();
        let install = Job::new(Path::new("client"), &schedule_home(&path, false).unwrap()).unwrap();
        std::fs::remove_dir(&path).unwrap();
        let uninstall =
            Job::new(Path::new("client"), &schedule_home(&path, true).unwrap()).unwrap();
        assert!(!path.exists());
        assert_eq!(install.id, uninstall.id);
        (install, uninstall)
    }

    #[test]
    fn launchd_label_uses_the_install_task_identifier() {
        let (install, uninstall) = jobs_before_and_after_home_removal();
        assert!(
            uninstall
                .plist()
                .contains(&format!("<string>{}</string>", install.id))
        );
    }

    #[test]
    fn systemd_names_use_the_install_task_identifier() {
        let (install, uninstall) = jobs_before_and_after_home_removal();
        assert!(
            uninstall
                .timer()
                .contains(&format!("Unit={}.service", install.id))
        );
    }

    #[test]
    fn schtasks_name_uses_the_install_task_identifier() {
        let (install, uninstall) = jobs_before_and_after_home_removal();
        assert_eq!(
            uninstall.schtasks_install(TaskRunAs::CurrentUser)[2],
            install.id
        );
    }

    #[test]
    fn windows_home_keeps_literal_percent_out_of_task_actions() {
        let error = validate_windows_home(Path::new(r"C:\Example%USERNAME%\pact")).unwrap_err();
        assert!(error.to_string().contains("choose a home path without %"));
        validate_windows_home(Path::new(r"C:\Example user\pact")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn localized_schtasks_failure_requires_elevation() {
        let output = std::process::Command::new("sh")
            .args(["-c", "echo 'CHYBA: Přístup byl odepřen.' >&2; exit 1"])
            .output()
            .unwrap();
        let error = command_result("schtasks.exe", output).unwrap_err();
        assert!(error.to_string().contains("run from an elevated prompt"));
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_distinguishes_denied_missing_and_existing_tasks() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let action = windows_uninstall_script(&job, false, Path::new(MACHINE));
        let setup = r#"
$script:deleted = $false
$script:failure = 5
$script:userId = 'EXAMPLE\user'
$script:program = Join-Path $env:TEMP 'open-pact-fictional-program-files'
function ProgramFilesPath { return $script:program }
function AssertProtected($path) {}
function RemovePendingDeletes($path, $strict = $false) {}
function New-Object {
    param([string]$ComObject)
    if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM creation' }
    $folder = [pscustomobject]@{}
    $folder | Add-Member ScriptMethod GetTask {
        param($id)
        if ($script:deleted) { throw [Runtime.InteropServices.COMException]::new('missing', -2147024894) }
        if ($script:failure -ne 0) { throw [Runtime.InteropServices.COMException]::new('Přístup byl odepřen', (0x80070000L + $script:failure - 0x100000000L)) }
        return [pscustomobject]@{ Name = $id; Definition = [pscustomobject]@{ Principal = [pscustomobject]@{ UserId = $script:userId } } }
    }
    $folder | Add-Member ScriptMethod DeleteTask { param($id,$flags); $script:deleted = $true }
    $folder | Add-Member ScriptMethod GetTasks { param($flags); return ,([pscustomobject]@{ Name = 'org.open-pact.report.other'; Definition = [pscustomobject]@{ Principal = [pscustomobject]@{ UserId = 'EXAMPLE\\user' } } }) }
    $service = [pscustomobject]@{ Folder = $folder }
    $service | Add-Member ScriptMethod Connect {}
    $service | Add-Member ScriptMethod GetFolder { param($path); return $this.Folder }
    return $service
}

"#;
        let checks = r#"$script:failure = 0
$script:userId = 'SYSTEM'
$caught = $false
try { & $action | Out-Null } catch { $caught = $_.Exception.Message -like '*schedule*' }
if (-not $caught -or $script:deleted) { throw 'limited uninstall did not refuse SYSTEM task' }
$script:userId = 'EXAMPLE\user'
foreach ($code in @(5,2,0)) {
    $script:failure = $code
    $script:deleted = $false
    $caught = $false
    try { & $action | Out-Null } catch { $caught = $true; Write-Output $_.Exception.Message }
    if ($code -eq 5 -and (-not $caught -or $script:deleted)) { throw 'denied query returned success or deleted' }
    if ($code -eq 2 -and ($caught -or $script:deleted)) { throw 'missing task did not converge' }
    if ($code -eq 0 -and ($caught -or -not $script:deleted)) { throw 'existing task not deleted' }
    Write-Output "query_code=$code deleted=$script:deleted caught=$caught"
}
"#;
        let script = format!("{setup}\n$action = {{\n{action}\n}}\n{checks}");
        let output = windows_powershell(&script).unwrap();
        assert!(output.contains("query_code=5 deleted=False caught=True"));
        assert!(output.contains("query_code=2 deleted=False caught=False"));
        assert!(output.contains("query_code=0 deleted=True caught=False"));
    }

    #[cfg(windows)]
    #[test]
    fn current_user_uninstall_ignores_an_admin_only_program_directory() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let action = windows_uninstall_script(&job, false, Path::new(MACHINE));
        let setup = r#"
$script:deleted = $false
$script:program = Join-Path $env:TEMP ('open-pact-fictional-program-' + [Guid]::NewGuid().ToString('N'))
$install = Join-Path $script:program 'open-pact'
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    [void]$acl.AddAccessRule($rule)
}
[IO.Directory]::CreateDirectory($install,$acl) | Out-Null
function ProgramFilesPath { return $script:program }
function AssertProtected($path) { throw 'current-user uninstall checked an admin-only path' }
function New-Object {
    param([string]$ComObject)
    if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM creation' }
    $folder = [pscustomobject]@{}
    $folder | Add-Member ScriptMethod GetTask { param($id); if ($script:deleted) { throw [Runtime.InteropServices.COMException]::new('missing', -2147024894) }; return [pscustomobject]@{ Name = $id; Definition = [pscustomobject]@{ Principal = [pscustomobject]@{ UserId = 'EXAMPLE\\user' } } } }
    $folder | Add-Member ScriptMethod DeleteTask { param($id,$flags); $script:deleted = $true }
    $folder | Add-Member ScriptMethod GetTasks { param($flags); return ,@() }
    $service = [pscustomobject]@{ Folder = $folder }
    $service | Add-Member ScriptMethod Connect {}
    $service | Add-Member ScriptMethod GetFolder { param($path); return $this.Folder }
    return $service
}
"#;
        let checks = r#"& $action | Out-Null
if (-not $script:deleted) { throw 'current-user task was not removed' }
Write-Output 'limited_uninstall_removed_task_without_protected_access'
"#;
        let script = format!("{setup}\n$action = {{\n{action}\n}}\n{checks}");
        assert_eq!(
            windows_powershell(&script).unwrap(),
            "limited_uninstall_removed_task_without_protected_access"
        );
    }

    #[test]
    fn no_script_gives_standard_users_a_right_on_a_protected_folder() {
        let install = windows_protected_paths_script("fixture-hash", "'machine.exe'");
        // The machine client's folder inherits Program Files. Nothing here adds a rule for it.
        for script in [
            install.as_str(),
            ASSERT_PROTECTED,
            PROTECTED_DIRECTORY,
            windows_existing_system_state_script("fixture-hash").as_str(),
        ] {
            assert!(!script.contains("S-1-5-32-545"));
            assert!(!script.contains("AllowUsersRead"));
            assert!(!script.contains("Copy-Item"));
        }
        // The install checks Program Files, the folder and the file before the state folders.
        let program = install
            .find("AssertProtected (Split-Path -Parent $folder)")
            .unwrap();
        let file = install.find("AssertProtected $machine").unwrap();
        assert!(program < file && file < install.find("ProtectedDirectory $data").unwrap());
        assert!(install.contains("$machine = 'machine.exe'"));
    }

    /// The tests that set the console interrupt flag take this lock, so they never overlap.
    static CONSOLE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A home with every file that a removal deletes.
    fn home_with_removable_files() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        for name in HOME_REMOVE_FILES {
            std::fs::write(home.file(name), b"fictional\n").unwrap();
        }
        (dir, home)
    }

    fn removable_files_remaining(home: &Home) -> Vec<&'static str> {
        HOME_REMOVE_FILES
            .iter()
            .copied()
            .filter(|name| home.file(name).exists())
            .collect()
    }

    #[test]
    fn a_ctrl_c_during_a_successful_system_removal_still_cleans_the_home() {
        let _console = CONSOLE_TEST
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (_dir, home) = home_with_removable_files();
        let error = finish_system_removal(&home, true, || {
            CONSOLE_INTERRUPT.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(error.is::<crate::Interrupted>());
        assert_eq!(removable_files_remaining(&home), Vec::<&str>::new());
    }

    #[test]
    fn a_failed_system_removal_keeps_the_home_files() {
        let _console = CONSOLE_TEST
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (_dir, home) = home_with_removable_files();
        let error = finish_system_removal(&home, true, || {
            CONSOLE_INTERRUPT.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(anyhow::anyhow!("fictional failure"))
        })
        .unwrap_err();
        assert!(error.is::<crate::Interrupted>());
        assert_eq!(
            removable_files_remaining(&home).len(),
            HOME_REMOVE_FILES.len()
        );

        let error =
            finish_system_removal(&home, true, || Err(anyhow::anyhow!("fictional failure")))
                .unwrap_err();
        assert_eq!(error.to_string(), "fictional failure");
        assert_eq!(
            removable_files_remaining(&home).len(),
            HOME_REMOVE_FILES.len()
        );
    }

    #[test]
    fn a_home_refusal_after_the_system_task_is_gone_names_the_plain_schedule_off() {
        let _console = CONSOLE_TEST
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (_dir, home) = home_with_removable_files();
        // A folder under a listed name fails its removal on every OS.
        let blocked = home.file(HOME_REMOVE_FILES[0]);
        std::fs::remove_file(&blocked).unwrap();
        std::fs::create_dir(&blocked).unwrap();
        let error = finish_system_removal(&home, true, || Ok(())).unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("the SYSTEM task is already removed"),
            "{text}"
        );
        assert!(
            text.contains(
                "Run `open-pact-client schedule off` again, with the same --home, to remove them."
            ),
            "{text}"
        );
    }

    #[test]
    fn a_system_removal_without_ctrl_c_cleans_the_home_and_succeeds() {
        let _console = CONSOLE_TEST
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (_dir, home) = home_with_removable_files();
        finish_system_removal(&home, true, || Ok(())).unwrap();
        assert_eq!(removable_files_remaining(&home), Vec::<&str>::new());

        let missing = Home(home.0.join("missing"));
        finish_system_removal(&missing, false, || Ok(())).unwrap();
        assert!(!missing.0.exists());
    }

    #[test]
    fn a_held_interrupt_ends_the_command_as_interrupted_and_nothing_else_does() {
        assert!(end_after_held_interrupt(false, Ok(())).is_ok());
        let failure = end_after_held_interrupt(false, Err(anyhow::anyhow!("fictional failure")));
        assert_eq!(failure.unwrap_err().to_string(), "fictional failure");
        for result in [Ok(()), Err(anyhow::anyhow!("fictional failure"))] {
            let error = end_after_held_interrupt(true, result).unwrap_err();
            assert!(error.is::<crate::Interrupted>());
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_console_handler_records_the_event_and_keeps_the_process_alive() {
        let _console = CONSOLE_TEST
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let hold = ConsoleInterruptHold::new();
        assert!(!hold.interrupted());
        // SAFETY: the handler only stores to an atomic.
        assert_eq!(unsafe { hold_console_interrupt(0) }, 1);
        assert!(hold.interrupted());
        drop(hold);
        assert!(!ConsoleInterruptHold::new().interrupted());
    }

    #[cfg(windows)]
    #[test]
    fn system_state_acl_reset_removes_existing_read_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = powershell_literal(dir.path().join("readable-state").to_str().unwrap());
        let script = format!(
            r#"{PROTECTED_DIRECTORY}
[IO.Directory]::CreateDirectory({path}) | Out-Null
$acl = [IO.Directory]::GetAccessControl({path})
$everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$rule = New-Object Security.AccessControl.FileSystemAccessRule($everyone,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
[void]$acl.AddAccessRule($rule)
[IO.Directory]::SetAccessControl({path},$acl)
ResetSystemStateDirectory {path}
$acl = [IO.Directory]::GetAccessControl({path})
$sids = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {{ $_.IdentityReference.Value }} | Sort-Object -Unique)
if (-not $acl.AreAccessRulesProtected) {{ throw 'state ACL inherits from its parent' }}
if (($sids -join ',') -ne 'S-1-5-18,S-1-5-32-544') {{ throw "unexpected state ACL principals: $($sids -join ',')" }}
Write-Output 'state_acl_reset_to_system_and_administrators'
"#
        );
        assert_eq!(
            windows_powershell(&script).unwrap(),
            "state_acl_reset_to_system_and_administrators"
        );
    }

    #[cfg(windows)]
    #[test]
    fn system_storage_refuses_non_admin_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = powershell_literal(dir.path().join("protected").to_str().unwrap());
        let script = format!(
            r#"{ASSERT_PROTECTED}{PROTECTED_DIRECTORY}
ProtectedDirectory {path}
AssertProtected {path}
$acl = [IO.Directory]::GetAccessControl({path})
$everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone,'Modify','Allow')))
[IO.Directory]::SetAccessControl({path},$acl)
try {{ AssertProtected {path}; throw 'unsafe ACL accepted' }} catch {{
    if ($_.Exception.Message -notlike '*non-admin principal*') {{ throw }}
}}
Write-Output 'refused'
"#
        );
        assert_eq!(windows_powershell(&script).unwrap(), "refused");
    }

    /// A probe that never answers, so native job runs in CI never send.
    #[cfg(any(target_os = "linux", windows))]
    const LOOPBACK_SCHEDULE: &str =
        "[schedule]\nmode = \"vpn\"\nvpn_probe = \"127.0.0.1:9\"\ninterval = \"55m\"";

    fn enrolled_home(dir: &Path) -> Home {
        enrolled_home_with_schedule(dir, None)
    }

    /// `schedule` replaces the demo manifest's `[schedule]` table; `Some("")` removes it.
    fn enrolled_home_with_schedule(dir: &Path, schedule: Option<&str>) -> Home {
        let home = Home(dir.to_path_buf());
        let key = crate::DeviceKey::load_or_create(dir, true).unwrap();
        let demo = include_str!("../../../examples/manifest.toml");
        let demo = match schedule {
            Some(table) => format!("{}\n{table}\n", &demo[..demo.find("\n[schedule]").unwrap()]),
            None => demo.to_owned(),
        };
        let manifest = demo
            .lines()
            .map(|line| {
                if line.starts_with("required =") {
                    "required = {}"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = open_pact_core::Manifest::parse(manifest.as_bytes()).unwrap();
        home.write("manifest.toml", manifest.as_bytes()).unwrap();
        home.write(
            "enrolment.json",
            &serde_json::to_vec(&crate::Enrolment {
                gateway: "https://gateway.example.org".into(),
                manifest: parsed.hash().clone(),
                device: open_pact_core::Pseudonym::of(&key.public_key()),
                salt: "fictional-review-fixture".into(),
                log_entries: None,
                last_status: None,
            })
            .unwrap(),
        )
        .unwrap();
        home
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Docker prepares a fictional home for native systemd user timer verification"]
    fn prepare_linux_schedule_home() {
        let path = PathBuf::from(std::env::var_os("OPEN_PACT_SCHEDULE_FIXTURE").unwrap());
        std::fs::create_dir_all(&path).unwrap();
        enrolled_home_with_schedule(&path, Some(LOOPBACK_SCHEDULE));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Windows CI prepares fictional homes for native CLI verification"]
    fn prepare_windows_schedule_homes() {
        let root = PathBuf::from(std::env::var_os("OPEN_PACT_SCHEDULE_FIXTURE").unwrap());
        for name in ["limited", "system", "missing", "retry"] {
            let path = root.join(name);
            std::fs::create_dir_all(&path).unwrap();
            enrolled_home_with_schedule(&path, Some(LOOPBACK_SCHEDULE));
        }
    }

    #[cfg(unix)]
    #[test]
    fn apply_command_preserves_shell_metacharacters() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home with 'quotes' $cash `false` ; & end");
        let command = apply_command(&home, "schedule off", &std::env::current_exe().unwrap());
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                &format!(
                    "set -- {command}; printf '%s\\n' \"$#\" \"$1\" \"$2\" \"$3\" \"$4\" \"$5\""
                ),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            [
                "5",
                "open-pact-client",
                "--home",
                home.to_str().unwrap(),
                "schedule",
                "off"
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn probe_timeout_kills_and_reaps_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "echo $$ > \"$PID_FILE\"; exec sleep 30"])
            .env("PID_FILE", &pid_file);
        let started = std::time::Instant::now();
        assert!(!probe_process(&mut command, Duration::from_millis(200)).await);
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_schedule_home_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().join("new-home"));
        let _guard = lock(&home).unwrap();
        assert_eq!(
            std::fs::metadata(home.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn clock_rollback_recovers_within_an_hour() {
        let mut state = State::default();
        state.observe(true);
        state.acknowledged(100_000, checks::EventMarkerReads::default());
        assert!(state.should_send(100_000 - 86_400 + 2 * 3600, 55 * 60));
    }

    #[cfg(unix)]
    #[test]
    fn saves_keep_config_and_state_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        save(&home, APPLIED, &"fictional-token").unwrap();
        assert_eq!(
            std::fs::metadata(home.file(APPLIED))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::set_permissions(home.file(APPLIED), std::fs::Permissions::from_mode(0o400))
            .unwrap();
        save(&home, APPLIED, &"fictional-token").unwrap();
        assert_eq!(
            std::fs::metadata(home.file(APPLIED))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        save(&home, STATE, &State::default()).unwrap();
        assert_eq!(
            std::fs::metadata(home.file(STATE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn job_log_keeps_the_last_two_files_of_bounded_size() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        job_log(&home, "first");
        assert!(
            std::fs::read_to_string(home.file(JOB_LOG))
                .unwrap()
                .ends_with(" first\n")
        );
        std::fs::write(home.file(JOB_LOG), vec![b'x'; JOB_LOG_LIMIT as usize]).unwrap();
        job_log(&home, "second");
        let current = std::fs::read_to_string(home.file(JOB_LOG)).unwrap();
        assert!(current.ends_with(" second\n") && current.lines().count() == 1);
        assert_eq!(
            std::fs::metadata(home.file("schedule.log.1"))
                .unwrap()
                .len(),
            JOB_LOG_LIMIT
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(home.file(JOB_LOG))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn systemd_executable_keeps_one_dollar_sign() {
        let job = Job::new(
            Path::new("/opt/client $cash %raw"),
            Path::new("/tmp/home $cash"),
        )
        .unwrap();
        assert!(
            job.service()
                .contains(r#"ExecStart="/opt/client $cash %%raw" "--home" "/tmp/home $$cash""#)
        );
    }

    #[test]
    fn send_decision_table_and_reconnect_retry() {
        let now = 100_000;
        for (up, pending, minutes, expected) in [
            (false, false, 55, false),
            (false, true, 55, false),
            (true, true, 1, false),
            (true, true, 55, true),
            (true, false, 54, false),
            (true, false, 55, true),
        ] {
            let state = State {
                vpn_up: up,
                reconnect_pending: pending,
                last_success: Some(now - minutes * 60),
                last_events: None,
                event_baseline: None,
                ..State::default()
            };
            assert_eq!(state.should_send(now, 55 * 60), expected);
        }
        let mut state = State::default();
        assert!(!state.should_send(now, 55 * 60));
        state.observe(true);
        assert!(state.should_send(now, 55 * 60));
        state.acknowledged(now, checks::EventMarkerReads::default());
        assert!(!state.should_send(now + 54 * 60, 55 * 60));
        assert!(state.should_send(now + 55 * 60, 55 * 60));
        state.observe(false);
        state.observe(true);
        assert!(
            !state.should_send(now + 60, 55 * 60),
            "a reconnect does not shorten the interval"
        );
        assert_eq!(state.due(now + 60, 55 * 60), None);
        assert_eq!(
            state.due(now + 55 * 60, 55 * 60),
            Some(Trigger::Connect),
            "the reconnect is sent once the interval has passed"
        );
        state.acknowledged(now + 120, checks::EventMarkerReads::default());
        assert!(!state.should_send(now + 121, 55 * 60));
        assert!(
            state.should_send(now - 1, 55 * 60),
            "clock rollback retries instead of suppressing reports"
        );
    }

    #[test]
    fn event_markers_send_only_for_new_events_while_vpn_is_up() {
        use checks::EventMarkerRead::{Read, Unknown};

        let reads = |security_log_cleared, antimalware_detection| checks::EventMarkerReads {
            security_log_cleared,
            antimalware_detection,
        };
        let previous = checks::EventMarkers {
            security_log_cleared: Some(100),
            antimalware_detection: Some(200),
        };
        let state = State {
            vpn_up: true,
            last_success: Some(500),
            last_events: Some(previous),
            ..State::default()
        };
        for (current, expected) in [
            (reads(Read(Some(101)), Read(Some(200))), true),
            (reads(Read(Some(100)), Read(Some(201))), true),
            (reads(Read(Some(100)), Read(Some(200))), false),
            (reads(Read(Some(99)), Read(Some(199))), false),
            (reads(Unknown, Unknown), false),
        ] {
            assert_eq!(state.new_events(current), expected);
        }

        let security_only = reads(Read(Some(101)), Unknown);
        assert!(state.new_events(security_only));
        let defender_only = reads(Unknown, Read(Some(201)));
        assert!(state.new_events(defender_only));

        let mut uninitialized = State {
            vpn_up: true,
            ..State::default()
        };
        let first_read = reads(Read(Some(100)), Unknown);
        assert!(!uninitialized.new_events(first_read));
        uninitialized.establish_baseline(first_read);
        assert_eq!(
            uninitialized.last_events.unwrap().security_log_cleared,
            Some(100)
        );
        assert_eq!(
            uninitialized.event_baseline,
            Some(EventBaseline {
                security_log_cleared: true,
                antimalware_detection: false,
            })
        );
        assert!(!uninitialized.new_events(reads(Unknown, Read(Some(200)))));
        uninitialized.establish_baseline(reads(Unknown, Read(Some(200))));
        assert!(!uninitialized.new_events(reads(Unknown, Read(Some(200)))));

        let offline = State {
            vpn_up: false,
            ..state
        };
        assert!(offline.new_events(reads(Read(Some(101)), Read(Some(200)))));
        assert_eq!(offline.due(600, 55 * 60), None);
        assert!(!offline.should_send(600, 55 * 60));
    }

    #[test]
    fn failed_send_keeps_event_markers_for_retry() {
        use checks::EventMarkerRead::{Read, Unknown};

        let previous = checks::EventMarkers {
            security_log_cleared: Some(100),
            antimalware_detection: Some(200),
        };
        let current = checks::EventMarkerReads {
            security_log_cleared: Read(Some(101)),
            antimalware_detection: Unknown,
        };
        let mut state = State {
            vpn_up: true,
            last_success: Some(500),
            last_events: Some(previous),
            ..State::default()
        };

        state.sent(false, 600, current, BTreeMap::new());

        assert_eq!(state.last_events, Some(previous));
        assert_eq!(state.last_success, Some(500));
        state.observe(true);
        assert!(state.new_events(current));
        state.acknowledged(700, current);
        assert_eq!(
            state.last_events,
            Some(checks::EventMarkers {
                security_log_cleared: Some(101),
                antimalware_detection: Some(200),
            }),
            "an unknown source keeps its acknowledged marker"
        );
        assert_eq!(state.last_success, Some(700));
    }

    #[test]
    fn trigger_decision_table() {
        for (up, reconnect, event, last, expected) in [
            (false, true, true, None, None),
            (true, true, true, Some(100), Some(Trigger::Event)),
            (true, false, true, Some(100), Some(Trigger::Event)),
            (true, true, false, Some(100), None),
            (true, true, false, Some(0), Some(Trigger::Connect)),
            (true, true, false, None, Some(Trigger::Connect)),
            (true, false, false, None, Some(Trigger::Periodic)),
            (true, false, false, Some(100), None),
            (true, false, false, Some(0), Some(Trigger::Periodic)),
        ] {
            let state = State {
                vpn_up: up,
                reconnect_pending: reconnect,
                event_pending: event,
                last_success: last,
                ..State::default()
            };
            assert_eq!(state.due(3300, 55 * 60), expected);
        }
    }

    #[test]
    fn compliance_trigger_decision_table_and_acknowledgment() {
        let map = |value| BTreeMap::from([("required_control".into(), value)]);
        for (previous, current, expected) in [
            (None, false, false),
            (Some(true), true, false),
            (Some(true), false, true),
            (Some(false), false, false),
            (Some(false), true, false),
        ] {
            let mut state = State {
                vpn_up: true,
                last_success: Some(100),
                last_compliance: previous.map(map),
                ..State::default()
            };
            state.observe_compliance(&map(current));
            assert_eq!(state.event_pending, expected);
            assert_eq!(state.due(101, 55 * 60), expected.then_some(Trigger::Event));
            state.sent(
                false,
                101,
                checks::EventMarkerReads::default(),
                map(current),
            );
            state.observe(true);
            assert_eq!(state.last_compliance, previous.map(map));
            assert_eq!(state.event_pending, expected);
            state.sent(true, 102, checks::EventMarkerReads::default(), map(current));
            assert_eq!(state.last_compliance, Some(map(current)));
            assert!(!state.event_pending);
        }
    }

    #[test]
    fn compliance_flip_after_acknowledged_failure_uses_recovery_observation() {
        let map = |value| BTreeMap::from([("required_control".into(), value)]);
        let mut state = State {
            vpn_up: true,
            last_success: Some(100),
            last_compliance: Some(map(true)),
            ..State::default()
        };

        state.observe_compliance(&map(false));
        assert_eq!(state.due(101, 55 * 60), Some(Trigger::Event));
        state.sent(true, 101, checks::EventMarkerReads::default(), map(false));
        assert!(!state.event_pending);

        state.observe_compliance(&map(true));
        assert_eq!(state.due(102, 55 * 60), None);
        state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        state.observe_compliance(&map(false));
        assert_eq!(state.due(103, 55 * 60), Some(Trigger::Event));
    }

    #[test]
    fn first_observed_compliance_sample_seeds_upgrade_baseline() {
        let mut state: State =
            serde_json::from_str(r#"{"vpn_up":true,"reconnect_pending":false,"last_success":100}"#)
                .unwrap();
        let compliant = BTreeMap::from([("required_control".into(), true)]);
        let failing = BTreeMap::from([("required_control".into(), false)]);

        state.observe_compliance(&compliant);
        assert_eq!(state.due(101, 55 * 60), None);
        state.observe_compliance(&failing);
        assert_eq!(state.due(102, 55 * 60), Some(Trigger::Event));
    }

    #[test]
    fn offline_events_survive_recovery_and_state_reload_until_connect_ack() {
        let mut state = State {
            last_success: Some(100),
            last_compliance: Some(BTreeMap::from([("control".into(), true)])),
            ..State::default()
        };
        state.establish_baseline(checks::EventMarkerReads {
            security_log_cleared: checks::EventMarkerRead::Read(Some(10)),
            antimalware_detection: checks::EventMarkerRead::Read(Some(20)),
        });
        for events in [
            checks::EventMarkerReads {
                security_log_cleared: checks::EventMarkerRead::Read(Some(11)),
                antimalware_detection: checks::EventMarkerRead::Unknown,
            },
            checks::EventMarkerReads {
                security_log_cleared: checks::EventMarkerRead::Unknown,
                antimalware_detection: checks::EventMarkerRead::Read(Some(21)),
            },
        ] {
            let mut pending: State =
                serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
            pending.event_pending |= pending.new_events(events);
            assert!(pending.event_pending);
            assert_eq!(pending.due(101, 55 * 60), None);
            pending.observe(true);
            assert_eq!(pending.due(102, 55 * 60), Some(Trigger::Event));
            pending.sent(false, 102, events, BTreeMap::new());
            assert!(pending.event_pending);
            assert_eq!(pending.last_events, state.last_events);
            pending.observe(true);
            pending.sent(true, 103, events, BTreeMap::new());
            assert!(!pending.event_pending);
        }
        state.observe_compliance(&BTreeMap::from([("control".into(), false)]));
        state.observe_compliance(&BTreeMap::from([("control".into(), true)]));
        assert!(state.event_pending);
        let mut restored: State =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(restored.due(101, 55 * 60), None);
        restored.observe(true);
        assert_eq!(restored.due(102, 55 * 60), Some(Trigger::Event));
    }

    #[test]
    fn old_state_without_event_markers_loads() {
        let state: State =
            serde_json::from_str(r#"{"vpn_up":true,"reconnect_pending":false,"last_success":123}"#)
                .unwrap();
        assert_eq!(state.last_success, Some(123));
        assert_eq!(state.last_events, None);
        assert_eq!(state.last_observed_compliance, None);
    }

    #[test]
    fn old_event_baseline_marks_both_sources_initialized() {
        let state: State = serde_json::from_str(
            r#"{"vpn_up":true,"last_events":{"security_log_cleared":100,"antimalware_detection":null}}"#,
        )
        .unwrap();
        assert_eq!(
            state.baseline(),
            EventBaseline {
                security_log_cleared: true,
                antimalware_detection: true,
            }
        );
    }

    fn job() -> Job {
        Job::new(
            Path::new("/opt/Example App/open-pact-client"),
            Path::new("/home/example/pact & data"),
        )
        .unwrap()
    }

    #[test]
    fn the_job_runs_the_executable_the_caller_names() {
        let executable = Path::new("/opt/example/open-pact-client");
        let desired = desired_job(Wanted::On(RunAs::User), executable, None)
            .unwrap()
            .unwrap();
        assert_eq!(desired.executable, executable);
        let job = Job::new(&desired.executable, Path::new("/home/example/pact")).unwrap();
        assert!(
            job.plist()
                .contains("<string>/opt/example/open-pact-client</string>")
        );
        assert!(
            job.service()
                .contains(r#"ExecStart="/opt/example/open-pact-client" "--home""#)
        );
        assert!(
            !job.plist()
                .contains(&*std::env::current_exe().unwrap().to_string_lossy())
        );
        assert!(
            desired_job(Wanted::Off, executable, None)
                .unwrap()
                .is_none()
        );
        assert!(desired_job(Wanted::On(RunAs::User), Path::new(""), None).is_err());
        // A SYSTEM job runs the machine client and reads the chosen profile.
        let system = desired_job(
            Wanted::On(RunAs::System),
            Path::new(MACHINE),
            Some(PathBuf::from("/profile")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(system.executable, Path::new(MACHINE));
        assert_eq!(system.user_home, Some(PathBuf::from("/profile")));
        let user = desired_job(
            Wanted::On(RunAs::User),
            executable,
            Some(PathBuf::from("/profile")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(user.user_home, None);
    }

    #[test]
    fn launchd_arguments_and_interval_are_encoded() {
        let log = Path::new("/home/example/pact & data").join(JOB_LOG);
        let plist = job().plist();
        assert!(plist.contains("<key>StartInterval</key><integer>60</integer>"));
        assert!(plist.contains("<string>/home/example/pact &amp; data</string>"));
        assert!(plist.contains("<string>schedule</string>\n<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(plist.contains(&format!(
                "<key>{key}</key><string>{}</string>",
                xml(&log.to_string_lossy())
            )));
        }
        assert_eq!(xml("<>'\"&"), "&lt;&gt;&apos;&quot;&amp;");
    }

    #[test]
    fn systemd_has_a_one_minute_timer_and_quotes_arguments() {
        assert!(job().timer().contains("OnUnitActiveSec=1min"));
        assert!(
            job()
                .timer()
                .contains(&format!("Unit={}.service", job().id))
        );
        assert!(job().service().contains(r#"ExecStart="/opt/Example App/open-pact-client" "--home" "/home/example/pact & data" "schedule" "run""#));
        let log = Path::new("/home/example/pact & data").join(JOB_LOG);
        for stream in ["StandardOutput", "StandardError"] {
            assert!(
                job()
                    .service()
                    .contains(&format!("{stream}=append:{}\n", log.to_string_lossy()))
            );
        }
        assert_eq!(systemd_arg("a%$\"\\b"), r#""a%%$$\"\\b""#);
    }

    #[test]
    fn windows_task_runs_every_minute_as_the_current_user() {
        let job = Job::new(
            Path::new(r"C:\Example App\open-pact-client.exe"),
            Path::new(r"C:\Example User\pact"),
        )
        .unwrap();
        assert_eq!(
            job.schtasks_install(TaskRunAs::CurrentUser),
            vec![
                "/Create",
                "/TN",
                job.id.as_str(),
                "/SC",
                "MINUTE",
                "/MO",
                "1",
                "/TR",
                r#""C:\Example App\open-pact-client.exe" "--home" "C:\Example User\pact" "schedule" "run""#,
                "/RL",
                "LIMITED",
                "/F",
            ]
        );
        assert_eq!(windows_arg("a\\"), "\"a\\\\\"");
        assert_eq!(windows_arg("a\"b"), "\"a\\\"b\"");
        assert!(Job::new(Path::new("/bin/client\nother"), Path::new("/home/example")).is_err());
    }

    #[test]
    fn windows_system_task_runs_every_minute_with_explicit_user_home() {
        let job = Job::new(
            Path::new(r"C:\Example App\open-pact-client.exe"),
            Path::new(r"C:\Example User\pact"),
        )
        .unwrap()
        .for_system(Path::new(r"C:\Users\example user"))
        .unwrap();
        assert_eq!(
            job.schtasks_install(TaskRunAs::System),
            vec![
                "/Create",
                "/TN",
                job.id.as_str(),
                "/SC",
                "MINUTE",
                "/MO",
                "1",
                "/TR",
                r#""C:\Example App\open-pact-client.exe" "--home" "C:\Example User\pact" "schedule" "run" "--system" "--user-home" "C:\Users\example user""#,
                "/RU",
                "SYSTEM",
                "/RL",
                "HIGHEST",
            ]
        );
    }

    #[test]
    fn system_task_install_is_refused_on_non_windows() {
        for os in [open_pact_core::Os::Macos, open_pact_core::Os::Linux] {
            let error = validate_system_install(true, os).unwrap_err();
            assert!(error.to_string().contains("available only on Windows"));
            validate_system_install(false, os).unwrap();
        }
        validate_system_install(true, open_pact_core::Os::Windows).unwrap();
    }

    #[tokio::test]
    async fn vpn_probe_connects_to_a_listening_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(
            vpn_up(
                &address.to_string(),
                None,
                &std::env::current_exe().unwrap()
            )
            .await
        );
        drop(listener);

        // A closed ephemeral port can be rebound by a parallel test; a bound socket that never
        // listens keeps the port reserved and refuses connections.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap();
        assert!(
            !vpn_up(
                &refused.to_string(),
                None,
                &std::env::current_exe().unwrap()
            )
            .await
        );
    }

    /// A certificate for `name` issued by a fictional CA. Returns the CA as a root that only a test
    /// may trust, and the server config that presents the certificate.
    fn tls_identity(name: &str) -> (reqwest::Certificate, std::sync::Arc<rustls::ServerConfig>) {
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fictional VPN CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let root = reqwest::Certificate::from_der(ca.der()).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .unwrap();
        (root, std::sync::Arc::new(config))
    }

    /// A TLS server that answers HTTP on every connection, with a certificate for `name`.
    fn serve_tls(name: &str) -> (std::net::SocketAddr, reqwest::Certificate) {
        use std::io::{Read, Write};
        let (root, config) = tls_identity(name);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut tcp) = stream else { continue };
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
                let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else {
                    continue;
                };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0_u8];
                    if tls.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                if head.ends_with(b"\r\n\r\n") {
                    let _ = tls.write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    let _ = tls.flush();
                }
            }
        });
        (address, root)
    }

    #[tokio::test]
    async fn named_probe_needs_a_certificate_for_its_name() {
        let (address, root) = serve_tls("vpn.example.org");
        assert!(named_up(address, "vpn.example.org", vec![root.clone()]).await);
        assert!(!named_up(address, "other.example.org", vec![root]).await);
        assert!(
            !named_up(address, "vpn.example.org", Vec::new()).await,
            "the fictional CA is trusted only through the test hook"
        );
        assert!(
            !vpn_up(
                &address.to_string(),
                Some("vpn.example.org"),
                &std::env::current_exe().unwrap()
            )
            .await,
            "the production probe does not trust the fictional CA"
        );
    }

    #[tokio::test]
    async fn named_probe_fails_on_plain_tcp_without_tls() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut tcp in listener.incoming().flatten() {
                let _ = tcp.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let (root, _) = tls_identity("vpn.example.org");
        assert!(!named_up(address, "vpn.example.org", vec![root]).await);
    }

    #[tokio::test]
    async fn event_trigger_uses_system_state_home() {
        let dir = tempfile::tempdir().unwrap();
        let home_path = dir.path().join("user-home");
        std::fs::create_dir_all(&home_path).unwrap();
        let home = enrolled_home(&home_path);
        let state_home = Home(
            dir.path()
                .join("ProgramData/open-pact/system/fictional-home"),
        );
        std::fs::create_dir_all(&home.0).unwrap();
        std::fs::create_dir_all(&state_home.0).unwrap();
        agree(&home);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = tokio::net::TcpSocket::new_v4().unwrap();
        refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut enrolment: crate::Enrolment = home.enrolment().unwrap();
        enrolment.gateway = format!("http://{}", refused.local_addr().unwrap());
        home.write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
            .unwrap();
        let policy = every_55_minutes_on_the_vpn(&listener.local_addr().unwrap().to_string());
        save(
            &state_home,
            STATE,
            &State {
                vpn_up: true,
                last_success: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
                ..State::default()
            },
        )
        .unwrap();
        let events = |timestamp| checks::EventMarkerReads {
            security_log_cleared: checks::EventMarkerRead::Read(Some(timestamp)),
            antimalware_detection: checks::EventMarkerRead::Unknown,
        };
        let authorization = ScheduleAuthorization {
            manifest_hash: home.enrolment().unwrap().manifest,
            schedule: policy.clone(),
            owner_consented: true,
            self_removal: false,
        };
        tick(
            &home,
            &state_home,
            None,
            &authorization,
            &std::env::current_exe().unwrap(),
            || events(100),
        )
        .await
        .unwrap();
        let baseline: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(
            baseline.last_events.unwrap().security_log_cleared,
            Some(100)
        );
        // The next check is not due yet, so a wake in between reads no markers at all.
        tick(
            &home,
            &state_home,
            None,
            &authorization,
            &std::env::current_exe().unwrap(),
            || events(101),
        )
        .await
        .unwrap();
        let unchanged: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(unchanged.last_events, baseline.last_events);
        assert!(!unchanged.event_pending);
        save(
            &state_home,
            STATE,
            &State {
                last_check: Some(baseline.last_check.unwrap() - 10 * 60),
                ..baseline.clone()
            },
        )
        .unwrap();
        let error = tick(
            &home,
            &state_home,
            None,
            &authorization,
            &std::env::current_exe().unwrap(),
            || events(101),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("/v1/manifest"), "{error:#}");
        let pending: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(pending.last_events, baseline.last_events);
        assert_eq!(pending.last_compliance, baseline.last_compliance);
        assert!(pending.event_pending);
        assert!(pending.new_events(events(101)));
        assert!(home.read_json::<State>(STATE).unwrap().is_none());
    }

    fn vpn_table(probe: &str) -> String {
        format!("[schedule]\nmode = \"vpn\"\nvpn_probe = \"{probe}\"\ninterval = \"55m\"")
    }

    fn agree(home: &Home) {
        let mut config = DeviceConfig::load(home).unwrap();
        config.auto_send = true;
        config.save(home).unwrap();
    }

    /// Points the enrolment at a port that refuses connections while the socket lives.
    fn unreachable_gateway(home: &Home) -> tokio::net::TcpSocket {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut enrolment: crate::Enrolment = home.enrolment().unwrap();
        enrolment.gateway = format!("http://{}", socket.local_addr().unwrap());
        home.write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
            .unwrap();
        socket
    }

    fn run_job() -> Command {
        Command::Run {
            system: false,
            user_home: None,
        }
    }

    #[tokio::test]
    async fn scheduled_run_persists_connectivity_and_keeps_failed_reconnect_due() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe = listener.local_addr().unwrap().to_string();
        enrolled_home_with_schedule(dir.path(), Some(&vpn_table(&probe)));
        let _gateway = unreachable_gateway(&home);
        agree(&home);
        save(
            &home,
            STATE,
            &State {
                vpn_up: false,
                reconnect_pending: false,
                last_success: Some(time::OffsetDateTime::now_utc().unix_timestamp() - 2 * 3600),
                last_events: None,
                event_baseline: None,
                ..State::default()
            },
        )
        .unwrap();
        assert!(
            run(&home, run_job(), &std::env::current_exe().unwrap())
                .await
                .is_err(),
            "the gateway is unreachable"
        );
        let connected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(connected.vpn_up);
        assert!(connected.reconnect_pending);
        assert!(connected.should_send(time::OffsetDateTime::now_utc().unix_timestamp(), 55 * 60));
        drop(listener);
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap().to_string();
        enrolled_home_with_schedule(dir.path(), Some(&vpn_table(&refused)));
        let _gateway = unreachable_gateway(&home);
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        let disconnected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(!disconnected.vpn_up);
        assert_eq!(disconnected.last_success, connected.last_success);
    }

    #[tokio::test]
    async fn schedule_on_is_refused_when_the_manifest_defines_no_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with_schedule(dir.path(), Some(""));
        assert!(home.signed_manifest().unwrap().body().schedule.is_none());
        let error = turn_on(&home, None, false, &std::env::current_exe().unwrap(), None)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("did not define automatic sending"),
            "{error:#}"
        );
        assert!(!home.file(device_config::FILE).exists());
        assert!(!home.file(APPLIED).exists());
    }

    #[tokio::test]
    async fn the_job_does_nothing_until_the_owner_agreed() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path());
        let _gateway = unreachable_gateway(&home);
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        assert!(!home.file(STATE).exists(), "no probe, no claim");
        assert!(!home.file(JOB_LOG).exists());
    }

    #[tokio::test]
    async fn the_job_does_nothing_when_the_signed_manifest_has_no_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with_schedule(dir.path(), Some(""));
        let _gateway = unreachable_gateway(&home);
        agree(&home);
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        assert!(!home.file(STATE).exists());
    }

    #[tokio::test]
    async fn hostname_probe_without_home() {
        const ADDRESS: &str = "OPEN_PACT_TEST_PROBE_ADDRESS";
        if let Ok(address) = std::env::var(ADDRESS) {
            assert!(std::env::var_os("HOME").is_none());
            let cli = crate::Invocation {
                home: None,
                insecure_dev: false,
                command: crate::Command::Schedule {
                    command: Command::Probe {
                        address,
                        name: None,
                    },
                },
            };
            assert_eq!(
                crate::run(cli, &std::env::current_exe().unwrap())
                    .await
                    .unwrap(),
                std::process::ExitCode::SUCCESS
            );
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "schedule::tests::hostname_probe_without_home",
                "--nocapture",
            ])
            .env_remove("HOME")
            .env(
                ADDRESS,
                format!("localhost:{}", listener.local_addr().unwrap().port()),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn dropping_guard_unlocks_even_with_an_inherited_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let guard = lock(&home).unwrap();
        let inherited = guard.0.try_clone().unwrap();
        assert!(lock(&home).is_err());
        drop(guard);
        assert!(lock(&home).is_ok());
        drop(inherited);
    }

    #[test]
    fn system_state_lock_allows_removal_of_the_locked_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state").join("fictional-hash");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join(STATE), "{}").unwrap();
        let home = Home(state.clone());
        let guard = lock_system_state(&home).unwrap();
        let error = lock_system_state(&home).err().unwrap();
        assert!(error.to_string().contains("retry this command"));
        std::fs::remove_dir_all(&state).unwrap();
        drop(guard);
        assert!(!state.exists());
        assert!(dir.path().join("state/fictional-hash.lock").exists());
    }

    #[test]
    fn a_state_lock_held_by_a_tick_is_awaited_and_then_taken() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().join("state").join("fictional-hash"));
        let mut tick = Some(lock_system_state(&home).unwrap());
        let mut sleeps = Vec::new();
        let taken = retry_while_state_in_use(
            SYSTEM_WAIT,
            SYSTEM_WAIT_STEP,
            |pause| {
                sleeps.push(pause);
                if sleeps.len() == 3 {
                    tick = None;
                }
            },
            || lock_system_state(&home),
        );
        assert!(taken.is_ok());
        assert_eq!(sleeps, vec![SYSTEM_WAIT_STEP; 3]);
        assert!(tick.is_none());
    }

    #[test]
    fn the_state_lock_wait_ends_at_its_budget_with_the_same_error() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().join("state").join("fictional-hash"));
        let _tick = lock_system_state(&home).unwrap();
        let mut slept = Duration::ZERO;
        let error = retry_while_state_in_use(
            SYSTEM_WAIT,
            SYSTEM_WAIT_STEP,
            |pause| slept += pause,
            || lock_system_state(&home),
        )
        .err()
        .unwrap();
        assert_eq!(slept, SYSTEM_WAIT);
        assert!(
            error
                .to_string()
                .contains("SYSTEM job state is in use; retry this command")
        );
    }

    #[test]
    fn another_lock_error_is_not_retried() {
        let mut calls = 0;
        let error = retry_while_state_in_use(
            SYSTEM_WAIT,
            SYSTEM_WAIT_STEP,
            |_| panic!("no wait for another error"),
            || -> Result<()> {
                calls += 1;
                bail!("cannot lock SYSTEM job state")
            },
        )
        .err()
        .unwrap();
        assert_eq!(calls, 1);
        assert!(error.to_string().contains("cannot lock"));
    }

    #[test]
    fn the_system_removal_ends_the_task_before_it_waits_for_the_state_lock() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let machine = Path::new(MACHINE);
        let end = windows_end_task_script(&job, false, machine);
        assert!(end.contains("IsSystemTask $task"));
        assert!(end.find("$task.Enabled = $false").unwrap() < end.find("$task.Stop(0)").unwrap());
        assert!(!windows_end_task_script(&job, true, machine).contains("$task.Stop"));
        assert!(end.find("'disabled'").unwrap() < end.find("$task.Enabled = $false").unwrap());
        assert!(!windows_end_task_script(&job, true, machine).contains("'disabled'"));
    }

    #[test]
    fn every_change_of_a_system_task_checks_who_runs_it_in_the_same_script() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let machine = Path::new(MACHINE);
        let literal = powershell_literal(MACHINE);
        // Stopping, removing and replacing each query the task again and check the principal and
        // the action before the first change. A SYSTEM task that is not ours is never changed.
        let end = windows_end_task_script(&job, false, machine);
        assert!(end.contains(&format!("$machine = {literal}")));
        assert!(end.contains("(IsSystemTask $task) -and (IsOurs $task $machine)"));
        assert!(end.find("IsOurs $task $machine").unwrap() < end.find("$task.Enabled").unwrap());
        let remove = windows_uninstall_script(&job, true, machine);
        assert!(remove.contains(&format!("$machine = {literal}")));
        assert!(
            remove.find("-not (IsOurs $task $machine)").unwrap()
                < remove.find("DeleteTask").unwrap()
        );
        let replace = windows_clear_for_system_script(&job, machine);
        assert!(replace.contains(&format!("$machine = {literal}")));
        assert!(
            replace.find("-not (IsOurs $task $machine)").unwrap()
                < replace.find("DeleteTask").unwrap()
        );
        // The limited removal still stops at a SYSTEM task before it changes anything.
        let limited = windows_uninstall_script(&job, false, machine);
        assert!(limited.find("if (-not $false)").unwrap() < limited.find("DeleteTask").unwrap());
        // A task with a group principal has no user id: it is not a SYSTEM task.
        let query = windows_task_query_script(&job);
        assert!(query.contains("[string]$task.Definition.Principal.UserId"));
        assert!(query.contains("if (-not $user) { return $false }"));
        // The same line of ownership holds the action: one action, the machine path, no control character.
        assert!(query.contains("$actions.Count -ne 1"));
        assert!(query.contains(r"[\x00-\x1f\x7f]"));
        // One path rule for both boundaries: the action and the machine path both lose a leading
        // \\?\ and compare without case, as `same_windows_path` does in Rust.
        assert!(query.contains(r"StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)"));
        assert!(query.contains("(NormalPath $path) -ieq (NormalPath $machine)"));
        assert!(!query.contains("$path -eq $machine"));
    }

    #[test]
    fn the_extended_spelling_of_the_machine_path_reaches_every_system_mutation() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        // A task that Task Scheduler returns with the extended prefix is the machine client's own
        // for the classifier (`a_task_is_classified_by_its_principal_and_its_actions`). Each
        // script that changes a SYSTEM task applies the same rule to the action and to Q, whichever
        // of the two carries the prefix.
        for machine in [MACHINE.to_owned(), format!(r"\\?\{MACHINE}")] {
            let machine = Path::new(&machine);
            let literal = powershell_literal(&machine.to_string_lossy());
            for script in [
                windows_uninstall_script(&job, true, machine),
                windows_clear_for_system_script(&job, machine),
                windows_end_task_script(&job, false, machine),
            ] {
                assert!(
                    script.contains(&format!("$machine = {literal}")),
                    "{script}"
                );
                assert!(script.contains("(NormalPath $path) -ieq (NormalPath $machine)"));
                assert!(script.contains("function NormalPath"));
                assert!(
                    script.find("function NormalPath").unwrap()
                        < script.find("function IsOurs").unwrap()
                );
            }
        }
        assert!(same_windows_path(
            Path::new(&format!(r"\\?\{MACHINE}")),
            Path::new(MACHINE)
        ));
    }

    #[test]
    fn a_user_job_is_registered_in_the_call_that_checks_for_a_system_task() {
        let job = Job::new(
            Path::new(r"C:\Users\a b\open-pact-client.exe"),
            Path::new(r"C:\Users\a b\pact"),
        )
        .unwrap();
        let args = job.schtasks_install(TaskRunAs::CurrentUser);
        let script = windows_register_user_script(&job, &args);
        // The query, the refusal and the create are one script: the refusal comes first.
        let query = script.find("$folder.GetTask(").unwrap();
        let refusal = script
            .find("if ($null -ne $task -and (IsSystemTask $task))")
            .unwrap();
        let create = script.find("[Diagnostics.Process]::Start($info)").unwrap();
        assert!(query < refusal && refusal < create);
        assert!(script.contains("a SYSTEM task for this home exists"));
        assert!(script.contains("schtasks.exe"));
        // The line that the script gives `schtasks` holds the same arguments, with the `/F` of a
        // user task, and parses back to them.
        let line = args
            .iter()
            .map(|arg| windows_command_line_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(split_windows_args(&line), args);
        assert!(script.contains(&format!("$info.Arguments = {}", powershell_literal(&line))));
        assert!(args.contains(&"/F".to_owned()) && args.contains(&"LIMITED".to_owned()));
        assert!(!script.contains("/RU"), "no principal is set: {script}");
    }

    #[test]
    fn a_system_task_is_created_without_force_after_the_old_one_is_gone() {
        let job = Job::new(Path::new(MACHINE), Path::new("fixture-home"))
            .unwrap()
            .for_system(Path::new("/profile"))
            .unwrap();
        let system = job.schtasks_install(TaskRunAs::System);
        assert!(!system.contains(&"/F".to_owned()), "{system:?}");
        let user = job.schtasks_install(TaskRunAs::CurrentUser);
        assert!(user.contains(&"/F".to_owned()), "{user:?}");
    }

    #[test]
    fn limited_uninstall_never_includes_protected_path_operations() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let script = windows_uninstall_script(&job, false, Path::new(MACHINE));
        for forbidden in [
            "ProgramFiles",
            "CommonApplicationData",
            "AssertProtected",
            "ResetSystemStateDirectory",
        ] {
            assert!(!script.contains(forbidden), "{forbidden}");
        }
        assert!(script.contains("schedule"));
    }

    #[test]
    fn state_is_persisted_and_commands_exclude_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let guard = lock(&home).unwrap();
        assert!(lock(&home).is_err());
        let mut state = State::default();
        state.observe(true);
        state.acknowledged(123, checks::EventMarkerReads::default());
        save(&home, STATE, &state).unwrap();
        let stored: State = home.read_json(STATE).unwrap().unwrap();
        assert!(stored.vpn_up);
        assert_eq!(stored.last_success, Some(123));
        assert!(!stored.reconnect_pending);
        drop(guard);
        assert!(lock(&home).is_ok());
    }

    #[tokio::test]
    async fn an_old_open_pact_toml_starts_nothing_and_is_noted_once_in_the_job_log() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path());
        let _gateway = unreachable_gateway(&home);
        std::fs::write(
            home.file(device_config::LEGACY_FILE),
            "[schedule]\nenabled = true\nrun_as = 'user'\nmode = 'vpn'\nvpn_probe = '127.0.0.1:1'\n",
        )
        .unwrap();
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        assert!(!home.file(STATE).exists(), "the old file starts no probe");
        let log = std::fs::read_to_string(home.file(JOB_LOG)).unwrap();
        assert_eq!(
            log.matches("open-pact.toml is ignored now").count(),
            1,
            "{log}"
        );
        assert!(log.contains("schedule on"), "{log}");
        assert!(home.file(device_config::LEGACY_FILE).exists());
    }

    #[test]
    fn the_interval_of_the_manifest_sets_the_periodic_claim() {
        let mut state = State::default();
        state.observe(true);
        state.acknowledged(1_000, checks::EventMarkerReads::default());
        assert!(!state.should_send(1_000 + 4 * 60, 5 * 60));
        assert!(state.should_send(1_000 + 5 * 60, 5 * 60));
        assert!(!state.should_send(1_000 + 5 * 60, 55 * 60));
        assert!(state.should_send(1_000 + 55 * 60, 55 * 60));
        assert_eq!(state.due(1_000 + 5 * 60, 5 * 60), Some(Trigger::Periodic));
        assert_eq!(state.due(1_000 + 5 * 60, 55 * 60), None);
    }

    #[test]
    fn alternating_probes_never_send_more_often_than_the_interval() {
        let interval = 55 * 60;
        let mut state = State::default();
        let mut now = 100_000;
        let mut sent = vec![];
        for round in 0..24 {
            state.observe(round % 2 == 0);
            if state.due(now, interval).is_some() {
                sent.push(now);
                state.sent(
                    true,
                    now,
                    checks::EventMarkerReads::default(),
                    BTreeMap::new(),
                );
            }
            now += 5 * 60;
        }
        assert!(sent.len() >= 2, "the periodic claim still goes: {sent:?}");
        for pair in sent.windows(2) {
            assert!(pair[1] - pair[0] >= interval, "{sent:?}");
        }
    }

    #[test]
    fn a_compliance_change_sends_at_once_even_after_a_reconnect() {
        let map = |value| BTreeMap::from([("required_control".into(), value)]);
        let mut state = State {
            vpn_up: true,
            last_success: Some(1_000),
            last_attempt: Some(1_000),
            last_compliance: Some(map(true)),
            ..State::default()
        };
        state.observe(false);
        state.observe(true);
        assert_eq!(state.due(1_060, 55 * 60), None);
        state.observe_compliance(&map(false));
        assert_eq!(state.due(1_120, 55 * 60), Some(Trigger::Event));
    }

    #[test]
    fn an_answer_without_a_verdict_counts_as_the_attempt() {
        let interval = 55 * 60;
        for outcome in [
            Outcome::NotSent(NotSent::Pending),
            Outcome::NotSent(NotSent::Revoked),
            Outcome::NotSent(NotSent::AcceptPending(open_pact_core::ManifestHash::of(
                b"fictional",
            ))),
            Outcome::Alarm("fictional alarm".into()),
        ] {
            let mut state = State {
                vpn_up: true,
                reconnect_pending: true,
                event_pending: true,
                ..State::default()
            };
            state.record(
                &outcome,
                10_000,
                checks::EventMarkerReads::default(),
                BTreeMap::new(),
            );
            assert_eq!(state.last_success, None, "nothing was accepted or denied");
            assert_eq!(state.due(10_000 + 5 * 60, interval), None);
            state.observe(false);
            state.observe(true);
            assert_eq!(
                state.due(10_000 + 10 * 60, interval),
                None,
                "a reconnect does not bring the next attempt closer"
            );
            assert_eq!(
                state.due(10_000 + interval, interval),
                Some(Trigger::Connect)
            );
        }
    }

    #[test]
    fn the_vpn_dropping_is_no_attempt() {
        let mut state = State {
            vpn_up: true,
            reconnect_pending: true,
            ..State::default()
        };
        state.record(
            &Outcome::NotSent(NotSent::OffVpn),
            10_000,
            checks::EventMarkerReads::default(),
            BTreeMap::new(),
        );
        assert!(!state.vpn_up && state.reconnect_pending);
        assert_eq!(state.last_attempt, None);
    }

    #[test]
    fn the_job_log_gets_one_line_per_state_change() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let mut state = State::default();
        let lines = |home: &Home| {
            std::fs::read_to_string(home.file(JOB_LOG))
                .unwrap_or_default()
                .lines()
                .count()
        };
        for _ in 0..3 {
            note_outcome(
                &home,
                &mut state,
                Trigger::Periodic,
                &Outcome::NotSent(NotSent::Revoked),
            );
        }
        assert_eq!(lines(&home), 1, "a revoked device is reported once");
        note_outcome(
            &home,
            &mut state,
            Trigger::Periodic,
            &Outcome::NotSent(NotSent::Pending),
        );
        assert_eq!(lines(&home), 2, "a new state is a new line");
        let denied = Outcome::Denied {
            reasons: vec!["firewall must be on".into()],
            changed: None,
        };
        for trigger in [Trigger::Connect, Trigger::Periodic, Trigger::Event] {
            note_outcome(&home, &mut state, trigger, &denied);
        }
        assert_eq!(lines(&home), 3, "the same denial is not repeated");
        note_outcome(
            &home,
            &mut state,
            Trigger::Periodic,
            &Outcome::NotSent(NotSent::OffVpn),
        );
        assert_eq!(lines(&home), 3, "an off-VPN run says nothing");
        note_outcome(
            &home,
            &mut state,
            Trigger::Periodic,
            &Outcome::Accepted { changed: None },
        );
        note_outcome(&home, &mut state, Trigger::Periodic, &denied);
        assert_eq!(
            lines(&home),
            4,
            "a denial after an acceptance is news again"
        );
    }

    #[tokio::test]
    async fn the_job_rotates_a_log_over_the_limit_at_the_start_of_each_run() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path());
        let _gateway = unreachable_gateway(&home);
        std::fs::write(home.file(JOB_LOG), vec![b'x'; JOB_LOG_LIMIT as usize + 1]).unwrap();
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(home.file("schedule.log.1"))
                .unwrap()
                .len(),
            JOB_LOG_LIMIT + 1
        );
        assert!(
            !home.file(JOB_LOG).exists(),
            "the next write starts a fresh log"
        );

        std::fs::write(home.file(JOB_LOG), b"short").unwrap();
        run(&home, run_job(), &std::env::current_exe().unwrap())
            .await
            .unwrap();
        assert_eq!(std::fs::read(home.file(JOB_LOG)).unwrap(), b"short");
        assert_eq!(
            std::fs::metadata(home.file("schedule.log.1"))
                .unwrap()
                .len(),
            JOB_LOG_LIMIT + 1,
            "a small log keeps the old copy as it is"
        );
    }

    #[test]
    fn a_system_run_accepts_only_a_home_that_resolves_to_itself() {
        let stored = Path::new(r"\\?\C:\Users\Example\pact");
        assert!(home_resolves_to_itself(stored, stored));
        assert!(home_resolves_to_itself(
            Path::new(r"C:\Users\Example\pact"),
            stored
        ));
        assert!(home_resolves_to_itself(
            stored,
            Path::new(r"\\?\c:\users\example\pact")
        ));
        for target in [
            r"\\?\C:\Windows\System32",
            r"\\?\C:\Users\Example\pact-other",
            r"\\?\C:\Users\Example\pact\inner",
        ] {
            assert!(
                !home_resolves_to_itself(stored, Path::new(target)),
                "{target}"
            );
            let error = require_home_without_link(stored, Path::new(target)).unwrap_err();
            assert!(error.to_string().contains("a link leads to"), "{error}");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_system_run_in_a_home_that_is_a_junction_fails_before_any_lock_exists() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let target = root.join("target");
        let home = root.join("home");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&home)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
        let error = run(
            &Home(home.clone()),
            Command::Run {
                system: true,
                user_home: Some(root.join("user")),
            },
            Path::new("open-pact-client.exe"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("a link leads to"), "{error:#}");
        assert_eq!(
            std::fs::read_dir(&target).unwrap().count(),
            0,
            "the run created a file in the junction target"
        );
        assert!(!home.join("claim.lock").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn an_elevated_schedule_off_in_a_home_that_is_a_junction_fails_before_any_lock_exists() {
        if windows_require_elevation().is_err() {
            // The link check of change_job runs only in an elevated process, the only one that
            // can reach SYSTEM state.
            eprintln!("skipped: change_job checks the home link only when elevated");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let target = root.join("target");
        let home = root.join("home");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&home)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
        let error = change_job(
            &Home(home.clone()),
            Wanted::Off,
            false,
            Path::new("open-pact-client.exe"),
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("a link leads to"), "{error:#}");
        assert_eq!(
            std::fs::read_dir(&target).unwrap().count(),
            0,
            "schedule off created a file in the junction target"
        );
        assert!(!home.join("claim.lock").exists());
    }

    #[tokio::test]
    async fn the_scan_runs_before_the_claim_lock_and_the_gateway_part_needs_it() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe = listener.local_addr().unwrap().to_string();
        let home = enrolled_home_with_schedule(dir.path(), Some(&vpn_table(&probe)));
        agree(&home);
        let _gateway = unreachable_gateway(&home);
        let repo = dir.path().join("work/app");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(
            repo.join(".git/config"),
            "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
        )
        .unwrap();
        let schedule = home
            .signed_manifest()
            .unwrap()
            .body()
            .schedule
            .clone()
            .unwrap();
        let authorization = ScheduleAuthorization {
            manifest_hash: home.enrolment().unwrap().manifest,
            schedule,
            owner_consented: true,
            self_removal: false,
        };

        let held = claim::try_lock(&home).unwrap().unwrap();
        tick(
            &home,
            &home,
            None,
            &authorization,
            &std::env::current_exe().unwrap(),
            checks::EventMarkerReads::default,
        )
        .await
        .unwrap();
        assert!(
            home.file("repo-scan.json").is_file(),
            "the scan finished while another command held the claim lock"
        );
        let state: State = home.read_json(STATE).unwrap().unwrap();
        assert_eq!(
            state.last_attempt, None,
            "the gateway part waited for the lock"
        );
        drop(held);

        let error = tick(
            &home,
            &home,
            None,
            &authorization,
            &std::env::current_exe().unwrap(),
            checks::EventMarkerReads::default,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("/v1/manifest"), "{error:#}");
        assert!(
            claim::try_lock(&home).unwrap().is_some(),
            "the job released the lock when its tick ended"
        );
    }
}
