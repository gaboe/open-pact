use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Home, checks, report};

const CONFIG: &str = "report-schedule.json";
const STATE: &str = "report-state.json";
const LOCK: &str = "report-schedule.lock";

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Register a report job that checks VPN connectivity every five minutes
    Install {
        #[arg(long)]
        collector: String,
        #[arg(long)]
        vpn_probe: Option<String>,
        /// Run Windows checks as SYSTEM to read machine-wide settings
        #[arg(long)]
        system: bool,
    },
    /// Remove the report job, its configuration and report state
    Uninstall {
        /// Remove Windows SYSTEM state and the shared protected binary
        #[arg(long)]
        system: bool,
    },
    #[command(hide = true)]
    Run {
        #[arg(long)]
        system: bool,
    },
    #[command(hide = true)]
    Probe {
        #[arg(long)]
        address: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Config {
    collector: String,
    vpn_probe: String,
}

impl Config {
    fn new(collector: String, vpn_probe: Option<String>) -> Result<Self> {
        let url = report::collector_url(&collector)?;
        let vpn_probe = vpn_probe.unwrap_or_else(|| {
            format!(
                "{}:{}",
                url.host().unwrap(),
                url.port_or_known_default().unwrap()
            )
        });
        probe_address(&vpn_probe)?;
        Ok(Self {
            collector,
            vpn_probe,
        })
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

    fn should_send(&self, now: i64) -> bool {
        self.vpn_up
            && (self.reconnect_pending
                || self
                    .last_success
                    .is_none_or(|last| now < last || now.saturating_sub(last) >= 55 * 60))
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
        if let Some(previous) = &self.last_compliance
            && current
                .iter()
                .any(|(id, compliant)| !compliant && previous.get(id) == Some(&true))
        {
            self.event_pending = true;
        }
    }

    fn report_type(&self, now: i64) -> Option<report::ReportType> {
        if !self.vpn_up {
            None
        } else if self.reconnect_pending {
            Some(report::ReportType::Connect)
        } else if self.event_pending {
            Some(report::ReportType::Event)
        } else if self.should_send(now) {
            Some(report::ReportType::Periodic)
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

fn probe_address(raw: &str) -> Result<()> {
    let url =
        reqwest::Url::parse(&format!("tcp://{raw}")).context("VPN probe must be host:port")?;
    if url.host_str().is_none()
        || url.port().is_none()
        || !url.path().is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || raw.chars().any(char::is_whitespace)
    {
        bail!("VPN probe must be host:port, with brackets around IPv6 addresses");
    }
    Ok(())
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

pub(crate) async fn vpn_up(probe: &str) -> bool {
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

pub(crate) fn probe_blocking(address: &str) -> Result<()> {
    use std::net::{TcpStream, ToSocketAddrs};
    probe_address(address)?;
    for address in address.to_socket_addrs()? {
        if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok() {
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
            Err(error).context("SYSTEM report state is in use; retry this command")
        }
        Err(error) => Err(error).context(format!(
            "cannot lock SYSTEM report state at {}; run from an elevated prompt",
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

pub(crate) fn uninstall_command(home: &Path) -> String {
    let raw = home.to_string_lossy();
    #[cfg(windows)]
    let quoted = format!("'{}'", raw.replace('\'', "''"));
    #[cfg(not(windows))]
    let quoted = format!("'{}'", raw.replace('\'', "'\"'\"'"));
    format!("open-pact-client --home {quoted} schedule uninstall")
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
        })
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
</dict></plist>
"#,
            self.id
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
        format!(
            "[Unit]\nDescription=Open-pact signed status report\n[Service]\nType=oneshot\nExecStart={args}\n"
        )
    }

    fn timer(&self) -> String {
        format!(
            "[Unit]\nDescription=Check VPN for open-pact reports every five minutes\n[Timer]\nOnStartupSec=1min\nOnUnitActiveSec=5min\nAccuracySec=1s\nUnit={}.service\n[Install]\nWantedBy=timers.target\n",
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
            } else if timer.exists() || service.exists() {
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
    let script = format!(
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
    );
    let paths = windows_powershell(&script)?;
    let mut lines = paths.lines();
    let binary = PathBuf::from(lines.next().context("protected binary path missing")?);
    let state = PathBuf::from(lines.next().context("protected state path missing")?);
    if lines.next().is_some() {
        bail!("unexpected protected path output");
    }
    Ok((binary, state))
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

fn windows_require_elevation() -> Result<()> {
    windows_powershell(
        r#"$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run `schedule uninstall --system` from an elevated prompt'
}"#,
    )?;
    Ok(())
}

fn windows_uninstall_script(job: &Job, system: bool) -> String {
    let query = windows_task_query_script(job);
    format!(
        r#"{query}
if (-not {system} -and $null -ne $task -and (IsSystemTask $task)) {{
    throw 'run `schedule uninstall --system` from an elevated prompt'
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
        .context("run `schedule uninstall --system` from an elevated prompt")?;
    Ok(())
}

fn windows_existing_system_state(home: &Path) -> Result<Option<PathBuf>> {
    validate_windows_home(home)?;
    let hash = hex::encode(Sha256::digest(text(home)?.as_bytes()));
    let output = windows_powershell(&format!(
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
    ))?;
    Ok(if output.is_empty() {
        None
    } else {
        Some(PathBuf::from(output))
    })
}

fn windows_cleanup_binary(job: &Job) -> Result<()> {
    let query = windows_task_query_script(job);
    let output = windows_powershell(&format!(
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
    throw "SYSTEM files remain: $($leftovers.FullName -join ', '). $failure Retry schedule uninstall --system, or reboot for queued files."
}}
if ($null -ne $failure) {{ throw $failure }}
"#
    ))?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
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
        && let Err(error) = std::fs::remove_dir_all(&state)
    {
        failures.push(format!(
            "SYSTEM report state remains at {}: {error}",
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
        bail!("schedule install --system is available only on Windows");
    }
    Ok(())
}

async fn run_report(
    home: &Home,
    state_home: &Home,
    config: &Config,
    read_events: impl FnOnce() -> checks::EventMarkerReads,
) -> Result<()> {
    let mut state: State = state_home.read_json(STATE)?.unwrap_or_default();
    state.observe(vpn_up(&config.vpn_probe).await);
    save(state_home, STATE, &state)?;
    let events = read_events();
    let (snapshot, compliance) = report::prepare(home)?;
    state.observe_compliance(&compliance);
    state.event_pending |= state.new_events(events);
    let now = chrono::Utc::now().timestamp();
    if let Some(report_type) = state.report_type(now) {
        save(state_home, STATE, &state)?;
        let acknowledged = report::run_scheduled(
            home,
            &config.collector,
            &config.vpn_probe,
            snapshot,
            report_type,
        )
        .await?;
        state.sent(
            acknowledged,
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

pub(crate) async fn run(home: &Home, command: Command) -> Result<()> {
    let os = crate::current_os()?;
    if let Command::Install { system, .. } = &command
        && *system
    {
        validate_system_install(true, os)?;
    }
    let system_run = matches!(&command, Command::Run { system: true });
    if system_run {
        validate_system_install(true, os)?;
    }
    let uninstall = matches!(&command, Command::Uninstall { .. });
    let absolute = schedule_home(&home.0, uninstall)?;
    let home = Home(absolute);
    let system_install = matches!(&command, Command::Install { system: true, .. });
    if let Command::Install {
        collector,
        vpn_probe,
        system: true,
    } = &command
    {
        Config::new(collector.clone(), vpn_probe.clone())?;
        home.enrolment()?;
        crate::DeviceKey::load(&home.0)?;
        validate_windows_home(&home.0)?;
    }
    let system_uninstall = matches!(&command, Command::Uninstall { system: true });
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
    let _home_lock = if system_install {
        Some(lock(&home)?)
    } else {
        None
    };
    let _lock = if system_run || system_install {
        Some(lock_system_state(&state_home)?)
    } else if !uninstall || home_exists {
        Some(lock(&state_home)?)
    } else {
        None
    };
    match command {
        Command::Probe { .. } => unreachable!(),
        Command::Run { .. } => {
            let config: Config = home
                .read_json(CONFIG)?
                .context("report schedule is not installed")?;
            report::collector_url(&config.collector)?;
            probe_address(&config.vpn_probe)?;
            run_report(&home, &state_home, &config, checks::event_markers).await?;
        }
        Command::Install {
            collector,
            vpn_probe,
            system,
        } => {
            let config = Config::new(collector, vpn_probe)?;
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
                job.argv.push("--system".into());
            }
            save(&home, CONFIG, &config)?;
            save(&install_state, STATE, &State::default())?;
            let run_as = if system {
                TaskRunAs::System
            } else {
                TaskRunAs::CurrentUser
            };
            register(&job, RegistrationAction::Install(run_as))?;
            println!(
                "Installed {}. The OS checks VPN connectivity every five minutes.",
                job.id
            );
        }
        Command::Uninstall { system } => {
            let job = Job::new(&std::env::current_exe()?, &home.0)?;
            if os == open_pact_core::Os::Windows {
                if system {
                    windows_system_uninstall(&job, &home)?;
                } else {
                    windows_uninstall(&job, false)?;
                    println!(
                        "SYSTEM leftovers, if any, are removed with schedule uninstall --system from an elevated prompt."
                    );
                }
            } else {
                register(&job, RegistrationAction::Uninstall)?;
            }
            if home_exists {
                for name in [
                    CONFIG,
                    STATE,
                    "report-state.json.tmp",
                    "report-schedule.json.tmp",
                ] {
                    remove_if_exists(&home.file(name))?;
                }
            }
            if home_exists {
                println!("Removed {} and its report configuration and state.", job.id);
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
try { & $action | Out-Null } catch { $caught = $_.Exception.Message -like '*schedule uninstall --system*' }
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

    fn enrolled_home(dir: &Path) -> Home {
        let home = Home(dir.to_path_buf());
        let key = crate::DeviceKey::load_or_create(dir, true).unwrap();
        let manifest = include_str!("../../../examples/manifest.toml")
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

    #[cfg(windows)]
    #[test]
    #[ignore = "Windows CI prepares fictional homes for native CLI verification"]
    fn prepare_windows_schedule_homes() {
        let root = PathBuf::from(std::env::var_os("OPEN_PACT_SCHEDULE_FIXTURE").unwrap());
        for name in ["limited", "system", "missing", "retry"] {
            let path = root.join(name);
            std::fs::create_dir_all(&path).unwrap();
            enrolled_home(&path);
        }
    }

    #[tokio::test]
    async fn send_error_hides_collector_query_token() {
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let collector = format!(
            "https://{}/status?token=fictional-secret",
            listener.local_addr().unwrap()
        );
        drop(listener);
        let error = report::run(&home, &collector, false).await.unwrap_err();
        let logged = format!("error: {error:#}");
        println!("{logged}");
        assert!(logged.contains("send report to collector"), "{logged}");
        assert!(!logged.contains("fictional-secret"));
    }

    #[tokio::test]
    async fn vpn_disconnect_during_preparation_prevents_send() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let home = enrolled_home(dir.path());
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe_address = probe.local_addr().unwrap().to_string();
        let collector_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let collector = format!(
            "https://{}/status",
            collector_listener.local_addr().unwrap()
        );
        drop(collector_listener);
        let went_down = Arc::new(AtomicBool::new(false));
        let observed = went_down.clone();
        let close = std::thread::spawn(move || {
            let (stream, _) = probe.accept().unwrap();
            drop(stream);
            drop(probe);
            observed.store(true, Ordering::SeqCst);
        });
        save(
            &home,
            CONFIG,
            &Config {
                collector,
                vpn_probe: probe_address.clone(),
            },
        )
        .unwrap();
        let result = run(&home, Command::Run { system: false }).await;
        close.join().unwrap();
        assert!(went_down.load(Ordering::SeqCst));
        assert!(!vpn_up(&probe_address).await);
        assert!(result.is_ok(), "{result:?}");
        let state: State = home.read_json(STATE).unwrap().unwrap();
        assert!(!state.vpn_up);
        assert!(state.reconnect_pending);
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_command_preserves_shell_metacharacters() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home with 'quotes' $cash `false` ; & end");
        let command = uninstall_command(&home);
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
                "uninstall"
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
        assert!(state.should_send(100_000 - 86_400 + 2 * 3600));
    }

    #[cfg(unix)]
    #[test]
    fn saves_keep_config_and_state_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        save(&home, CONFIG, &"fictional-token").unwrap();
        assert_eq!(
            std::fs::metadata(home.file(CONFIG))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::set_permissions(home.file(CONFIG), std::fs::Permissions::from_mode(0o400))
            .unwrap();
        save(&home, CONFIG, &"fictional-token").unwrap();
        assert_eq!(
            std::fs::metadata(home.file(CONFIG))
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
            assert_eq!(state.should_send(now), expected);
        }
        let mut state = State::default();
        assert!(!state.should_send(now));
        state.observe(true);
        assert!(state.should_send(now));
        state.acknowledged(now, checks::EventMarkerReads::default());
        assert!(!state.should_send(now + 54 * 60));
        assert!(state.should_send(now + 55 * 60));
        state.observe(false);
        state.observe(true);
        assert!(state.should_send(now + 60));
        state.observe(true);
        assert!(state.should_send(now + 120), "failed first send must retry");
        state.acknowledged(now + 120, checks::EventMarkerReads::default());
        assert!(!state.should_send(now + 121));
        assert!(
            state.should_send(now - 1),
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
        assert_eq!(offline.report_type(600), None);
        assert!(!offline.should_send(600));
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
    fn report_type_decision_table() {
        for (up, reconnect, event, last, expected) in [
            (false, true, true, None, None),
            (
                true,
                true,
                true,
                Some(100),
                Some(report::ReportType::Connect),
            ),
            (
                true,
                false,
                true,
                Some(100),
                Some(report::ReportType::Event),
            ),
            (true, false, false, None, Some(report::ReportType::Periodic)),
            (true, false, false, Some(100), None),
            (
                true,
                false,
                false,
                Some(0),
                Some(report::ReportType::Periodic),
            ),
        ] {
            let state = State {
                vpn_up: up,
                reconnect_pending: reconnect,
                event_pending: event,
                last_success: last,
                ..State::default()
            };
            assert_eq!(state.report_type(3300), expected);
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
            assert_eq!(
                state.report_type(101),
                expected.then_some(report::ReportType::Event)
            );
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
            assert_eq!(pending.report_type(101), None);
            pending.observe(true);
            assert_eq!(pending.report_type(102), Some(report::ReportType::Connect));
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
        assert_eq!(restored.report_type(101), None);
        restored.observe(true);
        assert_eq!(restored.report_type(102), Some(report::ReportType::Connect));
    }

    #[test]
    fn old_state_without_event_markers_loads() {
        let state: State =
            serde_json::from_str(r#"{"vpn_up":true,"reconnect_pending":false,"last_success":123}"#)
                .unwrap();
        assert_eq!(state.last_success, Some(123));
        assert_eq!(state.last_events, None);
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
                r#""C:\Example App\open-pact-client.exe" "--home" "C:\Example User\pact" "schedule" "run""#,
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

    #[test]
    fn probe_requires_host_and_port() {
        for address in ["vpn.example.org:443", "127.0.0.1:1234", "[::1]:443"] {
            assert!(probe_address(address).is_ok(), "{address}");
        }
        for address in [
            "vpn.example.org",
            "example.org:443/path",
            "user@example.org:443",
            "example.org:443?x",
            "example.org:443#x",
            "bad host:443",
        ] {
            assert!(probe_address(address).is_err(), "{address}");
        }
    }

    #[tokio::test]
    async fn vpn_probe_connects_to_a_listening_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(vpn_up(&address.to_string()).await);
        drop(listener);

        // A closed ephemeral port can be rebound by a parallel test; a bound socket that never
        // listens keeps the port reserved and refuses connections.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap();
        assert!(!vpn_up(&refused.to_string()).await);
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
        let config = Config {
            collector: format!("https://{}/status", refused.local_addr().unwrap()),
            vpn_probe: listener.local_addr().unwrap().to_string(),
        };
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
        run_report(&home, &state_home, &config, || events(100))
            .await
            .unwrap();
        let baseline: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(
            baseline.last_events.unwrap().security_log_cleared,
            Some(100)
        );
        let error = run_report(&home, &state_home, &config, || events(101))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("send report to collector"),
            "{error:#}"
        );
        let pending: State = state_home.read_json(STATE).unwrap().unwrap();
        assert_eq!(pending.last_events, baseline.last_events);
        assert_eq!(pending.last_compliance, baseline.last_compliance);
        assert!(pending.event_pending);
        assert!(pending.new_events(events(101)));
        assert!(home.read_json::<State>(STATE).unwrap().is_none());
    }

    #[tokio::test]
    async fn scheduled_run_persists_connectivity_and_keeps_failed_reconnect_due() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe = listener.local_addr().unwrap().to_string();
        save(
            &home,
            CONFIG,
            &Config {
                collector: "https://collector.example.org/status".into(),
                vpn_probe: probe,
            },
        )
        .unwrap();
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
            run(&home, Command::Run { system: false }).await.is_err(),
            "no enrolment for report"
        );
        let connected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(connected.vpn_up);
        assert!(connected.reconnect_pending);
        assert!(connected.should_send(chrono::Utc::now().timestamp()));
        drop(listener);
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused = reserved.local_addr().unwrap().to_string();
        let mut config: Config = home.read_json(CONFIG).unwrap().unwrap();
        config.vpn_probe = refused;
        save(&home, CONFIG, &config).unwrap();
        assert!(
            run(&home, Command::Run { system: false }).await.is_err(),
            "no enrolment for local evaluation"
        );
        let disconnected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(!disconnected.vpn_up);
        assert_eq!(disconnected.last_success, connected.last_success);
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
    fn default_probe_uses_collector_host_and_port() {
        for (collector, expected) in [
            (
                "https://collector.example.org/status",
                "collector.example.org:443",
            ),
            (
                "https://collector.example.org:8443/status",
                "collector.example.org:8443",
            ),
            ("https://[::1]:8443/status", "[::1]:8443"),
        ] {
            let config = Config::new(collector.into(), None).unwrap();
            assert_eq!(config.vpn_probe, expected);
        }
        let config = Config::new(
            "https://collector.example.org/status".into(),
            Some("vpn.example.org:9443".into()),
        )
        .unwrap();
        assert_eq!(config.vpn_probe, "vpn.example.org:9443");
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
        assert!(script.contains("schedule uninstall --system"));
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
}
