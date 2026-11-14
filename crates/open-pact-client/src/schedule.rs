use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use open_pact_core::{ProbeName, SendPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::{self, NotSent, Outcome, ScanPolicy};
use crate::device_config::{self, DeviceConfig, RunAs};
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
];
const REPO_SCAN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const LOCK: &str = "report-schedule.lock";

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Install the job that sends claims by itself, as the signed manifest allows
    On {
        /// Windows only: run the job as SYSTEM. Needs an elevated PowerShell prompt
        #[arg(long, hide = !cfg!(windows), conflicts_with = "user")]
        system: bool,
        /// Windows only: run the job as the current user
        #[arg(long, hide = !cfg!(windows))]
        user: bool,
        /// Show what would change and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the job
    Off {
        /// Show what would change and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Show whether the job is installed and what the signed manifest allows
    Status,
    #[command(hide = true)]
    Run {
        #[arg(long)]
        system: bool,
        /// The profile whose repositories and `~` paths count, when the job does not run as that user
        #[arg(long)]
        user_home: Option<PathBuf>,
    },
    #[command(hide = true)]
    Probe {
        #[arg(long)]
        address: String,
        /// The DNS name that the probe's TLS certificate must carry
        #[arg(long)]
        name: Option<String>,
    },
}

enum Operation {
    Install {
        system: bool,
        user_home: Option<PathBuf>,
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

#[derive(Default, Serialize, Deserialize)]
struct State {
    vpn_up: bool,
    #[serde(default)]
    reconnect_pending: bool,
    last_success: Option<i64>,
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
        }
        self.vpn_up = vpn_up;
    }

    fn should_send(&self, now: i64, interval: i64) -> bool {
        self.vpn_up
            && (self.reconnect_pending
                || self
                    .last_success
                    .is_none_or(|last| now < last || now.saturating_sub(last) >= interval))
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

    fn due(&self, now: i64, interval: i64) -> Option<Trigger> {
        if !self.vpn_up {
            None
        } else if self.reconnect_pending {
            Some(Trigger::Connect)
        } else if self.event_pending {
            Some(Trigger::Event)
        } else if self.should_send(now, interval) {
            Some(Trigger::Periodic)
        } else {
            None
        }
    }

    fn acknowledged(&mut self, now: i64, events: checks::EventMarkerReads) {
        self.last_success = Some(now);
        self.reconnect_pending = false;
        self.merge_events(events);
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
pub(crate) async fn vpn_up(probe: &str, name: Option<&str>) -> bool {
    let Some(name) = name else {
        return tcp_up(probe).await;
    };
    if let Ok(address) = probe.parse::<std::net::SocketAddr>() {
        return named_up(address, name, Vec::new()).await;
    }
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
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

async fn tcp_up(probe: &str) -> bool {
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
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
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

impl Job {
    fn new(executable: &Path, home: &Path) -> Result<Self> {
        let id = format!(
            "org.open-pact.report.{}",
            &hex::encode(Sha256::digest(text(home)?.as_bytes()))[..16]
        );
        Ok(Self {
            id,
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
<key>StartInterval</key><integer>300</integer>
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
            "[Unit]\nDescription=Check VPN for open-pact claims every five minutes\n[Timer]\nOnStartupSec=1min\nOnUnitActiveSec=5min\nAccuracySec=1s\nUnit={}.service\n[Install]\nWantedBy=timers.target\n",
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
            "5".into(),
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
        args.push("/F".into());
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
        if program == "schtasks.exe" {
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
        remove_if_exists(&home.file(name))?;
    }
    Ok(())
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
                execute(
                    "schtasks.exe",
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
            }
            RegistrationAction::Uninstall => {
                windows_uninstall(job, false)?;
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

fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn windows_powershell(script: &str) -> Result<String> {
    let script =
        format!("[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false);\n{script}");
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .output()
        .context("start Windows scheduler helper")?;
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

const PROTECTED_DIRECTORY: &str = r#"
$ErrorActionPreference = 'Stop'
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
function ProgramFilesPath { [Environment]::GetFolderPath('ProgramFiles') }
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
function RemovePendingDeletes($path, $strict = $false) {
    if (-not [IO.Directory]::Exists($path)) { return }
    $failed = [Collections.Generic.List[string]]::new()
    $errorMode = if ($strict) { 'Stop' } else { 'SilentlyContinue' }
    Get-ChildItem -LiteralPath $path -Filter 'open-pact-client.exe.delete-*' -File -Force -ErrorAction $errorMode | ForEach-Object {
        try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { [void]$failed.Add($_.FullName) }
    }
    if ($strict -and $failed.Count -gt 0) { throw "could not remove SYSTEM binary leftovers: $($failed -join ', ')" }
}
function IsSystemTask($task) {
    $user = $task.Definition.Principal.UserId
    return @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -contains $user.ToUpperInvariant()
}
function QueueBinaryRemoval($binary) {
    if (-not ('OpenPactNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OpenPactNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "MoveFileExW")]
    private static extern bool MoveFileEx(string existing, string destination, int flags);
    public static bool QueueDelete(string existing) { return MoveFileEx(existing, null, 4); }
}
'@
    }
    $pending = "$binary.delete-$([Guid]::NewGuid().ToString('N'))"
    [IO.File]::Move($binary,$pending)
    if (-not [OpenPactNative]::QueueDelete($pending)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        try { [IO.File]::Move($pending,$binary) } catch {}
        throw (New-Object ComponentModel.Win32Exception($errorCode))
    }
}
"#;

fn windows_protected_paths(home: &Home, copy_binary: bool) -> Result<(PathBuf, PathBuf)> {
    let absolute = &home.0;
    validate_windows_home(absolute)?;
    let hash = hex::encode(Sha256::digest(text(absolute)?.as_bytes()));
    let source = powershell_literal(text(&std::env::current_exe()?)?);
    let script = windows_protected_paths_script(&hash, &source, copy_binary);
    let paths = windows_powershell(&script)?;
    let mut lines = paths.lines();
    let binary = PathBuf::from(lines.next().context("protected binary path missing")?);
    let state = PathBuf::from(lines.next().context("protected state path missing")?);
    if lines.next().is_some() {
        bail!("unexpected protected path output");
    }
    Ok((binary, state))
}

fn windows_protected_paths_script(hash: &str, source: &str, copy_binary: bool) -> String {
    format!(
        r#"{PROTECTED_DIRECTORY}
$program = ProgramFilesPath
AssertProtected $program
$install = Join-Path $program 'open-pact'
ProtectedDirectory $install
$binary = Join-Path $install 'open-pact-client.exe'
if (Test-Path -LiteralPath $binary) {{ AssertProtected $binary }}
if ({copy}) {{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 5 }}
    RemovePendingDeletes $install
    if ([IO.Path]::GetFullPath({source}) -ne $binary) {{ Copy-Item -LiteralPath {source} -Destination $binary -Force }}
    AssertProtected $binary
}}
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'open-pact'
ProtectedDirectory $data
$data = Join-Path $data 'system'
ProtectedDirectory $data
$data = Join-Path $data '{hash}'
ResetSystemStateDirectory $data
Write-Output $binary
Write-Output $data
"#,
        copy = if copy_binary { "$true" } else { "$false" },
    )
}

fn windows_task_query_script(job: &Job) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
function IsSystemTask($task) {{
    $user = $task.Definition.Principal.UserId
    return @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -contains $user.ToUpperInvariant()
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

fn windows_system_executable_script() -> String {
    format!(
        "{PROTECTED_DIRECTORY}\nWrite-Output (Join-Path (ProgramFilesPath) 'open-pact\\open-pact-client.exe')"
    )
}

fn windows_require_elevation() -> Result<()> {
    windows_powershell(windows_require_elevation_script())?;
    Ok(())
}

fn windows_uninstall_script(job: &Job, system: bool) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{query}
if (-not {system} -and $null -ne $task -and (IsSystemTask $task)) {{
    throw 'run `schedule on` or `schedule off` from an elevated prompt'
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
    )
}

fn windows_uninstall(job: &Job, system: bool) -> Result<()> {
    windows_powershell(&windows_uninstall_script(job, system))
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
        r#"{PROTECTED_DIRECTORY}
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

fn windows_cleanup_binary(job: &Job) -> Result<()> {
    let output = windows_powershell(&windows_cleanup_binary_script(job))?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

fn windows_cleanup_binary_script(job: &Job) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{PROTECTED_DIRECTORY}
{query}
$install = Join-Path (ProgramFilesPath) 'open-pact'
if (-not (Test-Path -LiteralPath $install)) {{ return }}
AssertProtected $install
$remaining = @($folder.GetTasks(1) | Where-Object {{ $_.Name.StartsWith('org.open-pact.report.') -and (IsSystemTask $_) }})
if ($remaining.Count -gt 0) {{
    Write-Output 'Kept the shared SYSTEM binary because another SYSTEM task remains.'
    return
}}
$failure = $null
try {{
    RemovePendingDeletes $install $true
    $binary = Join-Path $install 'open-pact-client.exe'
    if (Test-Path -LiteralPath $binary) {{
        AssertProtected $binary
        QueueBinaryRemoval $binary
        Write-Output 'The SYSTEM client binary is queued for removal at the next reboot.'
    }}
}} catch {{ $failure = $_.Exception.Message }}
$leftovers = @(Get-ChildItem -LiteralPath $install -Filter 'open-pact-client.exe*' -File -Force -ErrorAction Stop)
if ($leftovers.Count -gt 0) {{
    throw "SYSTEM files remain: $($leftovers.FullName -join ', '). $failure Retry the schedule command, or reboot for queued files."
}}
if ($null -ne $failure) {{ throw $failure }}
"#
    )
}

fn windows_system_uninstall(job: &Job, home: &Home) -> Result<()> {
    let state = windows_existing_system_state(&home.0)?;
    let _state_lock = state
        .as_ref()
        .map(|path| lock_system_state(&Home(path.clone())))
        .transpose()
        .context("SYSTEM uninstall stopped before task or binary cleanup")?;
    let mut failures = Vec::new();
    if let Err(error) = windows_uninstall(job, true) {
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
    if let Err(error) = windows_cleanup_binary(job) {
        failures.push(format!("{error:#}"));
    }
    if !failures.is_empty() {
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

/// Whether the policy lets the job send now. A policy without a VPN needs no probe.
async fn may_send(policy: &SendPolicy) -> bool {
    match policy {
        SendPolicy::Vpn { probe, name } => {
            vpn_up(probe.as_str(), name.as_ref().map(ProbeName::as_str)).await
        }
        SendPolicy::Always => true,
    }
}

/// One scheduled run: note whether the policy lets the job send, collect the results, and send a
/// claim when a trigger is due and the policy still lets the job send.
pub(crate) async fn tick(
    home: &Home,
    state_home: &Home,
    user_home: Option<&Path>,
    schedule: &open_pact_core::Schedule,
    read_events: impl FnOnce() -> checks::EventMarkerReads,
) -> Result<()> {
    let policy = &schedule.policy;
    let mut state: State = state_home.read_json(STATE)?.unwrap_or_default();
    state.observe(may_send(policy).await);
    save(state_home, STATE, &state)?;
    let prepared = claim::prepare(
        home,
        user_home,
        ScanPolicy::OlderThan(REPO_SCAN_INTERVAL),
        false,
    )
    .await?;
    let events = read_events();
    let compliance = prepared.compliance().clone();
    state.observe_compliance(&compliance);
    state.event_pending |= state.new_events(events);
    let now = chrono::Utc::now().timestamp();
    if let Some(trigger) = state.due(now, schedule.interval.as_secs()) {
        save(state_home, STATE, &state)?;
        let outcome = prepared.send(home, async || may_send(policy).await).await?;
        note_outcome(home, trigger, &outcome);
        state.sent(
            outcome.delivered(),
            chrono::Utc::now().timestamp(),
            events,
            compliance,
        );
    } else if !state.baseline().security_log_cleared || !state.baseline().antimalware_detection {
        state.establish_baseline(events);
    }
    save(state_home, STATE, &state)?;
    Ok(())
}

/// Tells the owner what only the owner can fix: a changed manifest, a denial, an alarm.
fn note_outcome(home: &Home, trigger: Trigger, outcome: &Outcome) {
    let command = crate::client_command(&home.0);
    let changed = |hash: &open_pact_core::ManifestHash| {
        job_log(home, &crate::manifest_change_notice(hash, &command));
    };
    match outcome {
        Outcome::Accepted { changed: hash, .. } => {
            if let Some(hash) = hash {
                changed(hash);
            }
        }
        Outcome::Denied {
            reasons,
            changed: hash,
        } => {
            job_log(
                home,
                &format!(
                    "The gateway denied the {} claim: {}. Run `{command} check` to see what to fix.",
                    trigger.name(),
                    reasons.join("; ")
                ),
            );
            if let Some(hash) = hash {
                changed(hash);
            }
        }
        Outcome::NotSent(NotSent::AcceptPending(hash)) => changed(hash),
        Outcome::NotSent(NotSent::Pending) => {
            job_log(
                home,
                "This device waits for IT approval. No claim was sent.",
            );
        }
        Outcome::NotSent(NotSent::Revoked) => {
            job_log(home, "IT revoked this device. No claim was sent.");
        }
        Outcome::NotSent(NotSent::OffVpn) => {}
        Outcome::Alarm(text) => job_log(
            home,
            &format!(
                "TRANSPARENCY LOG ALARM: {text}. Run `{command} check` and tell IT. No VPN certificate was installed."
            ),
        ),
    }
}

/// Appends a dated line to the job log. The log keeps the last two files of at most
/// `JOB_LOG_LIMIT` bytes each. A failed write is only reported: it must not stop the job.
fn job_log(home: &Home, line: &str) {
    if let Err(error) = append_job_log(home, line) {
        eprintln!(
            "warning: could not write {}: {error}",
            home.file(JOB_LOG).display()
        );
    }
}

fn append_job_log(home: &Home, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let path = home.file(JOB_LOG);
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= JOB_LOG_LIMIT) {
        std::fs::rename(&path, home.file("schedule.log.1"))?;
    }
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
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    )
}

const APPLIED: &str = "schedule-applied.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Applied {
    run_as: RunAs,
    executable: PathBuf,
    /// The profile a SYSTEM job reads. Only a SYSTEM job has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_home: Option<PathBuf>,
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

#[derive(Debug, Default)]
struct WindowsTaskState {
    trigger_enabled: bool,
    trigger_type: Option<i32>,
    protected_binary: Option<ProtectedBinaryState>,
}

#[derive(Debug)]
struct ProtectedBinaryState {
    exists: bool,
    matches_source: bool,
}

impl WindowsTaskState {
    fn matches_desired(&self, system: bool) -> bool {
        self.trigger_enabled
            && self.trigger_type == Some(1)
            && (!system
                || self
                    .protected_binary
                    .as_ref()
                    .is_some_and(|binary| binary.exists && binary.matches_source))
    }
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
            if Some(desired) != applied
                || !observed.matches
                || observed
                    .windows_task
                    .as_ref()
                    .is_some_and(|task| !task.matches_desired(desired.run_as == RunAs::System)) =>
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

fn windows_observation_script(
    job: &Job,
    executable: &Path,
    source_executable: &Path,
    expected_args: &str,
) -> Result<String> {
    let query = windows_task_query_script(job);
    Ok(format!(
        r#"function ProgramFilesPath {{ [Environment]::GetFolderPath('ProgramFiles') }}
{query}
if ($null -eq $task) {{ Write-Output 'missing'; return }}
if (IsSystemTask $task) {{ Write-Output 'system' }} else {{ Write-Output 'user' }}
$action = @($task.Definition.Actions)
$triggers = @($task.Definition.Triggers)
if ($triggers.Count -eq 1) {{
    Write-Output ("trigger_enabled=" + [int]$triggers[0].Enabled)
    Write-Output ("trigger_type=" + $triggers[0].Type)
}}
if (IsSystemTask $task) {{
    $protected = Join-Path (Join-Path (ProgramFilesPath) 'open-pact') 'open-pact-client.exe'
    $protectedExists = Test-Path -LiteralPath $protected -PathType Leaf
    Write-Output ("protected_exists=" + [int]$protectedExists)
    $protectedMatches = $protectedExists -and (Get-FileHash -LiteralPath $protected -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath {source} -Algorithm SHA256).Hash
    Write-Output ("protected_matches=" + [int]$protectedMatches)
}}
if ($action.Count -eq 1 -and $action[0].Path -eq {binary} -and $action[0].Arguments -eq {args} -and $task.Enabled -and $triggers.Count -eq 1 -and $triggers[0].Enabled -and $triggers[0].Type -eq 1 -and $triggers[0].Repetition.Interval -eq 'PT5M') {{ Write-Output 'matches' }}
"#,
        binary = powershell_literal(text(executable)?),
        args = powershell_literal(expected_args),
        source = powershell_literal(text(source_executable)?),
    ))
}

fn observe(home: &Home, desired: Option<&Applied>, inspect_protected: bool) -> Result<Observed> {
    let source_executable = desired
        .map(|settings| settings.executable.clone())
        .unwrap_or(std::env::current_exe()?);
    let executable = desired
        .map(|settings| settings.executable.clone())
        .unwrap_or(std::env::current_exe()?);
    let executable = if crate::current_os()? == open_pact_core::Os::Windows
        && desired.is_some_and(|settings| settings.run_as == RunAs::System)
    {
        PathBuf::from(windows_powershell(&windows_system_executable_script())?)
    } else {
        executable
    };
    let mut job = Job::new(&executable, &home.0)?;
    if let Some(settings) = desired
        && settings.run_as == RunAs::System
    {
        job = job.for_system(
            settings
                .user_home
                .as_deref()
                .context("a SYSTEM schedule needs the user home it reads")?,
        )?;
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
            let expected_args = job
                .argv
                .iter()
                .skip(1)
                .map(|arg| windows_arg(arg))
                .collect::<Vec<_>>()
                .join(" ");
            let script =
                windows_observation_script(&job, &executable, &source_executable, &expected_args)?;
            let output = windows_powershell(&script)?;
            let system = output.lines().any(|line| line == "system");
            let field = |name: &str| {
                output
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .and_then(|value| value.parse::<i32>().ok())
            };
            let windows_task = output
                .lines()
                .any(|line| line.starts_with("trigger_enabled="))
                .then(|| WindowsTaskState {
                    trigger_enabled: field("trigger_enabled=") == Some(1),
                    trigger_type: field("trigger_type="),
                    protected_binary: system.then(|| ProtectedBinaryState {
                        exists: field("protected_exists=") == Some(1),
                        matches_source: field("protected_matches=") == Some(1),
                    }),
                });
            let protected_leftovers = inspect_protected
                && (windows_existing_system_state(&home.0)?.is_some()
                    || windows_orphaned_binary(&job)?);
            Observed {
                exists: output.lines().next() != Some("missing"),
                matches: output.lines().any(|line| line == "matches")
                    && system == desired.is_some_and(|settings| settings.run_as == RunAs::System),
                system,
                leftovers: leftovers || protected_leftovers,
                protected_leftovers,
                windows_task,
            }
        }
    })
}

/// The exact command that makes `change` (such as `schedule off`) from an elevated prompt.
pub(crate) fn apply_command(home: &Path, change: &str) -> String {
    #[cfg(windows)]
    {
        format!(
            "& {} --home {} {change}",
            powershell_literal(
                &std::env::current_exe()
                    .unwrap_or_else(|_| PathBuf::from("open-pact-client.exe"))
                    .to_string_lossy()
            ),
            powershell_literal(&home.to_string_lossy())
        )
    }
    #[cfg(not(windows))]
    {
        format!(
            "open-pact-client --home '{}' {change}",
            home.to_string_lossy().replace('\'', "'\"'\"'")
        )
    }
}

fn needs_system_cleanup(requested_system: bool, removing: bool, observed: &Observed) -> bool {
    requested_system || observed.system || (removing && observed.protected_leftovers)
}

fn windows_orphaned_binary(job: &Job) -> Result<bool> {
    let output = windows_powershell(&windows_orphaned_binary_script(job))?;
    Ok(output == "leftovers")
}

fn windows_orphaned_binary_script(job: &Job) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{PROTECTED_DIRECTORY}
{query}
$remaining = @($folder.GetTasks(1) | Where-Object {{ $_.Name.StartsWith('org.open-pact.report.') -and (IsSystemTask $_) }})
if ($remaining.Count -gt 0) {{ return }}
$install = Join-Path (ProgramFilesPath) 'open-pact'
if (Test-Path -LiteralPath $install) {{
    AssertProtected $install
    if (@(Get-ChildItem -LiteralPath $install -Filter 'open-pact-client.exe*' -File -Force -ErrorAction Stop).Count -gt 0) {{ Write-Output 'leftovers' }}
}}
"#
    )
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

/// Installs, updates or removes the OS job so it matches `wanted`.
pub(crate) async fn change_job(home: &Home, wanted: Wanted, dry_run: bool) -> Result<()> {
    let home_exists = home.0.try_exists()?;
    let requested_system = wanted == Wanted::On(RunAs::System);
    let retry = wanted.command();
    let home = Home(schedule_home(&home.0, true)?);
    let desired = match wanted {
        Wanted::On(run_as) => Some(Applied {
            run_as,
            executable: std::env::current_exe()?,
            user_home: (run_as == RunAs::System)
                .then(|| {
                    std::env::var_os("USERPROFILE").map(PathBuf::from).context(
                        "USERPROFILE is not set; a SYSTEM job needs the profile whose repositories it scans",
                    )
                })
                .transpose()?,
        }),
        Wanted::Off => None,
    };
    let elevated =
        crate::current_os()? == open_pact_core::Os::Windows && windows_require_elevation().is_ok();
    if requested_system && !elevated {
        bail!(
            "Run this exact command from an elevated PowerShell prompt:\n{}",
            apply_command(&home.0, retry)
        );
    }
    let observed = observe(&home, desired.as_ref(), elevated)
        .with_context(|| format!("Cannot inspect the scheduled job. If access is denied, run this exact command from an elevated prompt:\n{}", apply_command(&home.0, retry)))?;
    let system = needs_system_cleanup(requested_system, desired.is_none(), &observed);
    if system && !elevated {
        bail!(
            "Run this exact command from an elevated PowerShell prompt:\n{}",
            apply_command(&home.0, retry)
        );
    }
    let _lock = if dry_run || !home_exists {
        None
    } else {
        Some(lock(&home)?)
    };
    let observed = if dry_run {
        observed
    } else {
        observe(&home, desired.as_ref(), elevated)?
    };
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
                operate(&home, Operation::Uninstall { system: true }, true).await?;
            }
            operate(
                &home,
                Operation::Install {
                    system: desired.run_as == RunAs::System,
                    user_home: desired.user_home.clone(),
                },
                true,
            )
            .await?;
            save(&home, APPLIED, desired)?;
        }
        Change::Remove => {
            operate(&home, Operation::Uninstall { system }, true).await?;
            remove_if_exists(&home.file(APPLIED))?;
        }
        Change::None => {}
    }
    Ok(())
}

/// `schedule on`: needs a manifest that defines automatic sending.
pub(crate) async fn turn_on(home: &Home, run_as: Option<RunAs>, dry_run: bool) -> Result<()> {
    let manifest = home.signed_manifest()?;
    let Some(schedule) = &manifest.body().schedule else {
        bail!(
            "The company did not define automatic sending in the manifest you signed, so the job cannot be turned on. Run `{} check` to send a claim by hand.",
            crate::client_command(&home.0)
        );
    };
    let mut config = DeviceConfig::load(home)?;
    let run_as = run_as.unwrap_or(config.run_as);
    validate_system_install(run_as == RunAs::System, crate::current_os()?)?;
    println!("{schedule}");
    change_job(home, Wanted::On(run_as), dry_run).await?;
    if !dry_run {
        let _claim_lock = claim::lock(home).await?;
        config = DeviceConfig::load(home)?;
        config.auto_send = true;
        config.run_as = run_as;
        config.save(home)?;
    }
    Ok(())
}

/// `schedule off`: removes the job and remembers the owner's no.
pub(crate) async fn turn_off(home: &Home, dry_run: bool) -> Result<()> {
    change_job(home, Wanted::Off, dry_run).await?;
    if !dry_run && home.0.is_dir() {
        let _claim_lock = claim::lock(home).await?;
        let mut config = DeviceConfig::load(home)?;
        if config.auto_send {
            config.auto_send = false;
            config.save(home)?;
        }
    }
    Ok(())
}

/// `schedule status`: the owner's choice, the company's policy and the state of the job.
async fn status(home: &Home) -> Result<()> {
    let config = DeviceConfig::load(home)?;
    match home.signed_manifest() {
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
        executable: std::env::current_exe().unwrap_or_default(),
        user_home: None,
    });
    if desired
        .as_ref()
        .is_some_and(|desired| desired.run_as == RunAs::System)
    {
        println!(
            "The job runs as SYSTEM. Run `schedule on --system` from an elevated prompt to change it."
        );
        return Ok(());
    }
    let schedule_home = Home(schedule_home(&home.0, true)?);
    let observed = observe(&schedule_home, desired.as_ref(), false)?;
    let applied = read_applied(&schedule_home)?;
    let command = crate::client_command(&home.0);
    println!(
        "{}",
        match reconcile(desired.as_ref(), applied.as_ref(), &observed) {
            Change::None if desired.is_some() => "The job is installed and current.".to_owned(),
            Change::None => "The job is not installed.".to_owned(),
            Change::Install => format!("The job is not installed. Run `{command} schedule on`."),
            Change::Update => format!("The job is out of date. Run `{command} schedule on`."),
            Change::Remove => format!(
                "A job from an earlier setup remains. Run `{command} schedule off` to remove it."
            ),
        }
    );
    if let Some(state) = schedule_home.read_json::<State>(STATE)?
        && let Some(last) = state.last_success
        && let Some(time) = chrono::DateTime::from_timestamp(last, 0)
    {
        println!(
            "Last claim the gateway answered: {}.",
            time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }
    Ok(())
}

pub(crate) async fn run(home: &Home, command: Command) -> Result<()> {
    match command {
        Command::On {
            system,
            user,
            dry_run,
        } => {
            let run_as = if system {
                Some(RunAs::System)
            } else {
                user.then_some(RunAs::User)
            };
            turn_on(home, run_as, dry_run).await
        }
        Command::Off { dry_run } => turn_off(home, dry_run).await,
        Command::Status => status(home).await,
        Command::Run { system, user_home } => {
            operate(home, Operation::Run { system, user_home }, false).await
        }
        Command::Probe { address, name } => probe_command(&address, name.as_deref()).await,
    }
}

/// One run of the job. The policy comes from the manifest the owner signed, never from a manifest
/// that waits for acceptance.
async fn run_tick(home: &Home, state_home: &Home, user_home: Option<&Path>) -> Result<()> {
    let command = crate::client_command(&home.0);
    if let Some(notice) = device_config::legacy_notice(home, device_config::Surface::Job, &command)
    {
        job_log(home, &notice);
    }
    if !DeviceConfig::load(home)?.auto_send {
        return Ok(());
    }
    let manifest = home.signed_manifest()?;
    let Some(schedule) = &manifest.body().schedule else {
        return Ok(());
    };
    tick(home, state_home, user_home, schedule, checks::event_markers).await
}

async fn operate(home: &Home, command: Operation, home_locked: bool) -> Result<()> {
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
        Some(windows_protected_paths(&home, system_install)?)
    } else {
        None
    };
    let state_home = protected_paths
        .as_ref()
        .map(|(_, state)| Home(state.clone()))
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
            let Some(_claim_lock) = claim::try_lock(&home)? else {
                return Ok(());
            };
            let result = run_tick(&home, &state_home, user_home.as_deref()).await;
            if let Err(error) = &result {
                job_log(&home, &format!("error: {error:#}"));
            }
            result?;
        }
        Operation::Install { system, user_home } => {
            home.enrolment()?;
            crate::DeviceKey::load(&home.0)?;
            if os == open_pact_core::Os::Windows {
                validate_windows_home(&home.0)?;
            }
            let (executable, install_state) = if system {
                let (binary, state) = protected_paths
                    .as_ref()
                    .context("SYSTEM install paths were not prepared")?;
                (binary.clone(), Home(state.clone()))
            } else {
                (std::env::current_exe()?, Home(home.0.clone()))
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
            }
            save(&install_state, STATE, &State::default())?;
            let run_as = if system {
                TaskRunAs::System
            } else {
                TaskRunAs::CurrentUser
            };
            register(&job, RegistrationAction::Install(run_as))?;
            println!(
                "Installed {}. The OS runs it every five minutes. It sends the same claim as `check`, as the signed manifest allows. It writes what needs your attention to {}.",
                job.id, job.log
            );
        }
        Operation::Uninstall { system } => {
            let job = Job::new(&std::env::current_exe()?, &home.0)?;
            if os == open_pact_core::Os::Windows {
                if system {
                    windows_system_uninstall(&job, &home)?;
                } else {
                    windows_uninstall(&job, false)?;
                    println!(
                        "SYSTEM leftovers, if any, are removed with `schedule off` from an elevated prompt."
                    );
                }
            } else {
                register(&job, RegistrationAction::Uninstall)?;
            }
            if home_exists {
                remove_home_schedule_files(&home)?;
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
            windows_protected_paths_script("fixture-hash", "'source.exe'", true),
            windows_task_query_script(&job),
            windows_uninstall_script(&job, false),
            windows_existing_system_state_script("fixture-hash"),
            windows_cleanup_binary_script(&job),
            windows_orphaned_binary_script(&job),
            windows_system_executable_script(),
            windows_observation_script(
                &job,
                Path::new("fixture.exe"),
                Path::new("source.exe"),
                "--system",
            )
            .unwrap(),
            windows_require_elevation_script().to_owned(),
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

    #[test]
    fn imperative_setup_commands_are_removed() {
        use clap::Parser;
        for args in [
            vec![
                "client",
                "schedule",
                "install",
                "--collector",
                "https://example.org",
            ],
            vec!["client", "schedule", "uninstall"],
            vec!["client", "report", "--collector", "https://example.org"],
            vec!["client", "report", "--dry-run"],
            vec!["client", "log", "reports"],
            vec!["client", "apply"],
            vec!["client", "finish"],
            vec!["client", "config", "example"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
        assert!(crate::Cli::try_parse_from(["client", "check", "--dry-run"]).is_ok());
        for args in [
            vec!["client", "schedule", "on"],
            vec!["client", "schedule", "on", "--dry-run"],
            vec!["client", "schedule", "off"],
            vec!["client", "schedule", "status"],
            vec!["client", "folders", "list"],
            vec!["client", "folders", "add", "~/work"],
            vec!["client", "folders", "remove", "~/work"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_ok());
        }
        assert!(
            crate::Cli::try_parse_from(["client", "schedule", "on", "--system", "--user"]).is_err()
        );
    }

    fn vpn(probe: &str) -> SendPolicy {
        SendPolicy::Vpn {
            probe: open_pact_core::ProbeAddress::try_from(probe.to_owned()).unwrap(),
            name: None,
        }
    }

    fn every_55_minutes(policy: SendPolicy) -> open_pact_core::Schedule {
        open_pact_core::Schedule {
            policy,
            interval: open_pact_core::Interval::try_from("55m".to_owned()).unwrap(),
        }
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

    #[test]
    fn windows_reconcile_repairs_disabled_or_wrong_triggers() {
        let settings = Applied {
            run_as: RunAs::User,
            executable: PathBuf::from("C:\\Program Files\\open-pact\\open-pact-client.exe"),
            user_home: None,
        };
        let applied = Some(&settings);
        let disabled = Observed {
            exists: true,
            matches: true,
            windows_task: Some(WindowsTaskState {
                trigger_enabled: false,
                trigger_type: Some(1),
                protected_binary: None,
            }),
            ..Observed::default()
        };
        assert_eq!(
            reconcile(Some(&settings), applied, &disabled),
            Change::Update
        );
        let wrong_type = Observed {
            windows_task: Some(WindowsTaskState {
                trigger_enabled: true,
                trigger_type: Some(7),
                protected_binary: None,
            }),
            ..disabled
        };
        assert_eq!(
            reconcile(Some(&settings), applied, &wrong_type),
            Change::Update
        );
    }

    #[test]
    fn windows_reconcile_repairs_missing_or_stale_system_binary() {
        let settings = Applied {
            run_as: RunAs::System,
            executable: PathBuf::from("C:\\example\\open-pact-client.exe"),
            user_home: Some(PathBuf::from("C:\\Users\\example")),
        };
        let applied = Some(&settings);
        for protected_binary in [
            ProtectedBinaryState {
                exists: false,
                matches_source: false,
            },
            ProtectedBinaryState {
                exists: true,
                matches_source: false,
            },
        ] {
            let observed = Observed {
                exists: true,
                matches: true,
                system: true,
                windows_task: Some(WindowsTaskState {
                    trigger_enabled: true,
                    trigger_type: Some(1),
                    protected_binary: Some(protected_binary),
                }),
                ..Observed::default()
            };
            assert_eq!(
                reconcile(Some(&settings), applied, &observed),
                Change::Update
            );
        }
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
        let action = windows_uninstall_script(&job, false);
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
        let action = windows_uninstall_script(&job, false);
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
    fn a_running_client_image_can_be_renamed() {
        const READY: &str = "OPEN_PACT_RENAME_READY";
        const STOP: &str = "OPEN_PACT_RENAME_STOP";
        if let (Ok(ready), Ok(stop)) = (std::env::var(READY), std::env::var(STOP)) {
            std::fs::write(ready, "ready").unwrap();
            while !Path::new(&stop).exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("open-pact-client.exe");
        let renamed = dir.path().join("open-pact-client.exe.delete-fictional");
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        let ready = dir.path().join("ready");
        let stop = dir.path().join("stop");
        let mut child = std::process::Command::new(&image)
            .args([
                "--exact",
                "schedule::tests::a_running_client_image_can_be_renamed",
                "--nocapture",
            ])
            .env(READY, &ready)
            .env(STOP, &stop)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child test process did not start");
        }
        if let Err(error) = std::fs::rename(&image, &renamed) {
            let _ = std::fs::write(&stop, "stop");
            let _ = child.wait();
            panic!("rename running client image: {error}");
        }
        let old_image_exists = image.exists();
        let renamed_image_exists = renamed.exists();
        std::fs::write(&stop, "stop").unwrap();
        let child_succeeded = child.wait().unwrap().success();
        assert!(!old_image_exists);
        assert!(renamed_image_exists);
        assert!(child_succeeded);
    }

    #[cfg(windows)]
    #[test]
    fn system_storage_refuses_non_admin_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = powershell_literal(dir.path().join("protected").to_str().unwrap());
        let script = format!(
            r#"{PROTECTED_DIRECTORY}
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
    const LOOPBACK_SCHEDULE: &str = "[schedule]\nmode = \"vpn\"\nvpn_probe = \"127.0.0.1:9\"\ninterval = \"55m\"";

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
        let command = apply_command(&home, "schedule off");
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
            (true, true, 1, true),
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
        assert!(state.should_send(now + 60, 55 * 60));
        state.observe(true);
        assert!(
            state.should_send(now + 120, 55 * 60),
            "failed first send must retry"
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
            (true, true, true, Some(100), Some(Trigger::Connect)),
            (true, false, true, Some(100), Some(Trigger::Event)),
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
            assert_eq!(pending.due(102, 55 * 60), Some(Trigger::Connect));
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
        assert_eq!(restored.due(102, 55 * 60), Some(Trigger::Connect));
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
    fn launchd_arguments_and_interval_are_encoded() {
        let plist = job().plist();
        assert!(plist.contains("<key>StartInterval</key><integer>300</integer>"));
        assert!(plist.contains("<string>/home/example/pact &amp; data</string>"));
        assert!(plist.contains("<string>schedule</string>\n<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(plist.contains(&format!(
                "<key>{key}</key><string>/home/example/pact &amp; data/schedule.log</string>"
            )));
        }
        assert_eq!(xml("<>'\"&"), "&lt;&gt;&apos;&quot;&amp;");
    }

    #[test]
    fn systemd_has_a_five_minute_timer_and_quotes_arguments() {
        assert!(job().timer().contains("OnUnitActiveSec=5min"));
        assert!(
            job()
                .timer()
                .contains(&format!("Unit={}.service", job().id))
        );
        assert!(job().service().contains(r#"ExecStart="/opt/Example App/open-pact-client" "--home" "/home/example/pact & data" "schedule" "run""#));
        for stream in ["StandardOutput", "StandardError"] {
            assert!(job().service().contains(&format!(
                "{stream}=append:/home/example/pact & data/schedule.log\n"
            )));
        }
        assert_eq!(systemd_arg("a%$\"\\b"), r#""a%%$$\"\\b""#);
    }

    #[test]
    fn windows_task_runs_every_five_minutes_as_the_current_user() {
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
                "5",
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
    fn windows_system_task_runs_every_five_minutes_with_explicit_user_home() {
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
                "5",
                "/TR",
                r#""C:\Example App\open-pact-client.exe" "--home" "C:\Example User\pact" "schedule" "run" "--system" "--user-home" "C:\Users\example user""#,
                "/RU",
                "SYSTEM",
                "/RL",
                "HIGHEST",
                "/F",
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
        assert!(vpn_up(&address.to_string(), None).await);
        drop(listener);

        // A closed ephemeral port can be rebound by a parallel test; a bound socket that never
        // listens keeps the port reserved and refuses connections.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap();
        assert!(!vpn_up(&refused.to_string(), None).await);
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
            !vpn_up(&address.to_string(), Some("vpn.example.org")).await,
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = tokio::net::TcpSocket::new_v4().unwrap();
        refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut enrolment: crate::Enrolment = home.enrolment().unwrap();
        enrolment.gateway = format!("http://{}", refused.local_addr().unwrap());
        home.write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
            .unwrap();
        let policy = every_55_minutes(vpn(&listener.local_addr().unwrap().to_string()));
        save(
            &state_home,
            STATE,
            &State {
                vpn_up: true,
                last_success: Some(chrono::Utc::now().timestamp()),
                ..State::default()
            },
        )
        .unwrap();
        let events = |timestamp| checks::EventMarkerReads {
            security_log_cleared: checks::EventMarkerRead::Read(Some(timestamp)),
            antimalware_detection: checks::EventMarkerRead::Unknown,
        };
        tick(&home, &state_home, None, &policy, || events(100))
            .await
            .unwrap();
        let baseline: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(
            baseline.last_events.unwrap().security_log_cleared,
            Some(100)
        );
        let error = tick(&home, &state_home, None, &policy, || events(101))
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
                last_success: Some(chrono::Utc::now().timestamp()),
                last_events: None,
                event_baseline: None,
                ..State::default()
            },
        )
        .unwrap();
        assert!(
            run(&home, run_job()).await.is_err(),
            "the gateway is unreachable"
        );
        let connected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(connected.vpn_up);
        assert!(connected.reconnect_pending);
        assert!(connected.should_send(chrono::Utc::now().timestamp(), 55 * 60));
        drop(listener);
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap().to_string();
        enrolled_home_with_schedule(dir.path(), Some(&vpn_table(&refused)));
        let _gateway = unreachable_gateway(&home);
        run(&home, run_job()).await.unwrap();
        let disconnected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(!disconnected.vpn_up);
        assert_eq!(disconnected.last_success, connected.last_success);
    }

    #[tokio::test]
    async fn schedule_on_is_refused_when_the_manifest_defines_no_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with_schedule(dir.path(), Some(""));
        assert!(home.signed_manifest().unwrap().body().schedule.is_none());
        let error = turn_on(&home, None, false).await.unwrap_err();
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
        run(&home, run_job()).await.unwrap();
        assert!(!home.file(STATE).exists(), "no probe, no claim");
        assert!(!home.file(JOB_LOG).exists());
    }

    #[tokio::test]
    async fn the_job_does_nothing_when_the_signed_manifest_has_no_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home_with_schedule(dir.path(), Some(""));
        let _gateway = unreachable_gateway(&home);
        agree(&home);
        run(&home, run_job()).await.unwrap();
        assert!(!home.file(STATE).exists());
    }

    #[tokio::test]
    async fn hostname_probe_without_home() {
        const ADDRESS: &str = "OPEN_PACT_TEST_PROBE_ADDRESS";
        if let Ok(address) = std::env::var(ADDRESS) {
            assert!(std::env::var_os("HOME").is_none());
            let cli = <crate::Cli as clap::Parser>::try_parse_from([
                "open-pact-client",
                "schedule",
                "probe",
                "--address",
                &address,
            ])
            .unwrap();
            assert_eq!(
                crate::run(cli).await.unwrap(),
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
    fn limited_uninstall_never_includes_protected_path_operations() {
        let job = Job::new(Path::new("client.exe"), Path::new("fixture-home")).unwrap();
        let script = windows_uninstall_script(&job, false);
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
        run(&home, run_job()).await.unwrap();
        run(&home, run_job()).await.unwrap();
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
}
