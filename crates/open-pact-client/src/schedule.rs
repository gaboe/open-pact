use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Home, report};

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
    Uninstall,
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

    fn acknowledged(&mut self, now: i64) {
        self.last_success = Some(now);
        self.reconnect_pending = false;
    }
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

fn lock(home: &Home) -> Result<ScheduleLock> {
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(&home.0)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.file(LOCK))?;
    file.try_lock()
        .context("another schedule command is running")?;
    Ok(ScheduleLock(file))
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
                windows_uninstall(job)?;
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
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .context("start Windows scheduler helper")?;
    if !output.status.success() {
        bail!(
            "Windows scheduler helper failed with code {:?}; run from an elevated prompt. {}",
            output.status.code(),
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
    $acl = Get-Acl -LiteralPath $path
    $allowed = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw 'Protected path has a non-admin owner' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band 0xD0156) -and $allowed -notcontains $rule.IdentityReference.Value) {
            throw 'Protected path ACL grants write or modify to a non-admin principal'
        }
    }
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
"#;

fn windows_protected_paths(home: &Home, copy_binary: bool) -> Result<(PathBuf, PathBuf)> {
    let absolute = std::fs::canonicalize(&home.0)?;
    validate_windows_home(&absolute)?;
    let hash = hex::encode(Sha256::digest(text(&absolute)?.as_bytes()));
    let source = powershell_literal(text(&std::env::current_exe()?)?);
    let script = format!(
        r#"{PROTECTED_DIRECTORY}
$program = [Environment]::GetFolderPath('ProgramFiles')
AssertProtected $program
$install = Join-Path $program 'open-pact'
ProtectedDirectory $install
$binary = Join-Path $install 'open-pact-client.exe'
if (Test-Path -LiteralPath $binary) {{ AssertProtected $binary }}
if ({copy}) {{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 5 }}
    if ([IO.Path]::GetFullPath({source}) -ne $binary) {{ Copy-Item -LiteralPath {source} -Destination $binary -Force }}
    AssertProtected $binary
}}
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'open-pact'
ProtectedDirectory $data
$data = Join-Path $data 'system'
ProtectedDirectory $data
$data = Join-Path $data '{hash}'
ProtectedDirectory $data
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

fn windows_uninstall_script(job: &Job) -> String {
    format!(
        r#"{PROTECTED_DIRECTORY}
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
try {{ $task = $folder.GetTask({id}) }} catch {{
    $failure = $_.Exception
    while ($null -ne $failure.InnerException) {{ $failure = $failure.InnerException }}
    if (($failure.HResult -band 0xffff) -ne 2) {{ throw }}
    $task = $null
}}
if ($null -ne $task) {{ $folder.DeleteTask({id},0) }}
$remaining = @($folder.GetTasks(1) | Where-Object {{ $_.Name.StartsWith('org.open-pact.report.') }})
if ($remaining.Count -eq 0) {{
    $install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'open-pact'
    if (Test-Path -LiteralPath $install) {{
        AssertProtected $install
        $binary = Join-Path $install 'open-pact-client.exe'
        if (Test-Path -LiteralPath $binary) {{ AssertProtected $binary; Remove-Item -LiteralPath $binary -Force }}
    }}
}} else {{ Write-Output 'Kept the shared SYSTEM binary because another open-pact task remains.' }}
"#,
        id = powershell_literal(&job.id)
    )
}

fn windows_uninstall(job: &Job) -> Result<()> {
    let message = windows_powershell(&windows_uninstall_script(job))?;
    if !message.is_empty() {
        println!("{message}");
    }
    Ok(())
}

fn validate_system_install(system: bool, os: open_pact_core::Os) -> Result<()> {
    if system && os != open_pact_core::Os::Windows {
        bail!("schedule install --system is available only on Windows");
    }
    Ok(())
}

pub(crate) async fn run(home: &Home, command: Command) -> Result<()> {
    if let Command::Install { system, .. } = &command
        && *system
    {
        validate_system_install(true, crate::current_os()?)?;
    }
    let system_run = matches!(&command, Command::Run { system: true });
    let state_home = if system_run {
        validate_system_install(true, crate::current_os()?)?;
        Home(windows_protected_paths(home, false)?.1)
    } else {
        Home(home.0.clone())
    };
    let _lock = lock(&state_home)?;
    let absolute = std::fs::canonicalize(&home.0)?;
    let home = Home(absolute);
    match command {
        Command::Probe { .. } => unreachable!(),
        Command::Run { .. } => {
            let config: Config = home
                .read_json(CONFIG)?
                .context("report schedule is not installed")?;
            report::collector_url(&config.collector)?;
            probe_address(&config.vpn_probe)?;
            let mut state: State = state_home.read_json(STATE)?.unwrap_or_default();
            state.observe(vpn_up(&config.vpn_probe).await);
            save(&state_home, STATE, &state)?;
            if state.should_send(chrono::Utc::now().timestamp()) {
                if report::run_scheduled(&home, &config.collector, &config.vpn_probe).await? {
                    state.acknowledged(chrono::Utc::now().timestamp());
                } else {
                    state.observe(false);
                }
                save(&state_home, STATE, &state)?;
            }
        }
        Command::Install {
            collector,
            vpn_probe,
            system,
        } => {
            let config = Config::new(collector, vpn_probe)?;
            home.enrolment()?;
            crate::DeviceKey::load(&home.0)?;
            if crate::current_os()? == open_pact_core::Os::Windows {
                validate_windows_home(&home.0)?;
            }
            let (executable, install_state) = if system {
                let (binary, state) = windows_protected_paths(&home, true)?;
                (binary, Home(state))
            } else {
                (std::env::current_exe()?, Home(home.0.clone()))
            };
            if crate::current_os()? == open_pact_core::Os::Windows
                && text(&executable)?.contains('%')
            {
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
        Command::Uninstall => {
            let job = Job::new(&std::env::current_exe()?, &home.0)?;
            register(&job, RegistrationAction::Uninstall)?;
            for name in [
                CONFIG,
                STATE,
                "report-state.json.tmp",
                "report-schedule.json.tmp",
            ] {
                remove_if_exists(&home.file(name))?;
            }
            println!("Removed {} and its report configuration and state.", job.id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let action = windows_uninstall_script(&job);
        let setup = r#"
$script:deleted = $false
$script:failure = 5
function New-Object {
    param([string]$ComObject)
    if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM creation' }
    $folder = [pscustomobject]@{}
    $folder | Add-Member ScriptMethod GetTask {
        param($id)
        if ($script:failure -ne 0) { throw [Runtime.InteropServices.COMException]::new('Přístup byl odepřen', (0x80070000L + $script:failure - 0x100000000L)) }
        return [pscustomobject]@{ Name = $id }
    }
    $folder | Add-Member ScriptMethod DeleteTask { param($id,$flags); $script:deleted = $true }
    $folder | Add-Member ScriptMethod GetTasks { param($flags); return ,([pscustomobject]@{ Name = 'org.open-pact.report.other' }) }
    $service = [pscustomobject]@{ Folder = $folder }
    $service | Add-Member ScriptMethod Connect {}
    $service | Add-Member ScriptMethod GetFolder { param($path); return $this.Folder }
    return $service
}

"#;
        let checks = r#"foreach ($code in @(5,2,0)) {
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
    fn system_storage_refuses_non_admin_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = powershell_literal(dir.path().join("protected").to_str().unwrap());
        let script = format!(
            r#"{PROTECTED_DIRECTORY}
ProtectedDirectory {path}
AssertProtected {path}
$acl = Get-Acl -LiteralPath {path}
$everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone,'Modify','Allow')))
Set-Acl -LiteralPath {path} -AclObject $acl
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
        state.acknowledged(100_000);
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
            };
            assert_eq!(state.should_send(now), expected);
        }
        let mut state = State::default();
        assert!(!state.should_send(now));
        state.observe(true);
        assert!(state.should_send(now));
        state.acknowledged(now);
        assert!(!state.should_send(now + 54 * 60));
        assert!(state.should_send(now + 55 * 60));
        state.observe(false);
        state.observe(true);
        assert!(state.should_send(now + 60));
        state.observe(true);
        assert!(state.should_send(now + 120), "failed first send must retry");
        state.acknowledged(now + 120);
        assert!(!state.should_send(now + 121));
        assert!(
            state.should_send(now - 1),
            "clock rollback retries instead of suppressing reports"
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
        run(&home, Command::Run { system: false }).await.unwrap();
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
    fn state_is_persisted_and_commands_exclude_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let guard = lock(&home).unwrap();
        assert!(lock(&home).is_err());
        let mut state = State::default();
        state.observe(true);
        state.acknowledged(123);
        save(&home, STATE, &state).unwrap();
        let stored: State = home.read_json(STATE).unwrap().unwrap();
        assert!(stored.vpn_up);
        assert_eq!(stored.last_success, Some(123));
        assert!(!stored.reconnect_pending);
        drop(guard);
        assert!(lock(&home).is_ok());
    }
}
