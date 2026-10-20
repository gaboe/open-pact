use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
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
    },
    /// Remove the report job, its configuration and report state
    Uninstall,
    #[command(hide = true)]
    Run,
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

    fn should_send_events(&self, current: checks::EventMarkerReads) -> bool {
        if !self.vpn_up {
            return false;
        }
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

    fn acknowledged(&mut self, now: i64, events: checks::EventMarkerReads) {
        self.last_success = Some(now);
        self.reconnect_pending = false;
        self.merge_events(events);
    }

    fn sent(&mut self, acknowledged: bool, now: i64, events: checks::EventMarkerReads) {
        if acknowledged {
            self.acknowledged(now, events);
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

    fn schtasks_install(&self) -> Vec<String> {
        vec![
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
            "/RL".into(),
            "LIMITED".into(),
            "/F".into(),
        ]
    }
}

fn execute(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("start {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
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

fn register(job: &Job, install: bool) -> Result<()> {
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
            if install {
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
            if install {
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
        open_pact_core::Os::Windows => {
            if install {
                let args = job.schtasks_install();
                execute(
                    "schtasks.exe",
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
            } else {
                let exists = std::process::Command::new("schtasks.exe")
                    .args(["/Query", "/TN", &job.id])
                    .output()?
                    .status
                    .success();
                if exists {
                    execute("schtasks.exe", &["/Delete", "/TN", &job.id, "/F"])?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn run(home: &Home, command: Command) -> Result<()> {
    let _lock = lock(home)?;
    let absolute = std::fs::canonicalize(&home.0)?;
    let home = Home(absolute);
    match command {
        Command::Probe { .. } => unreachable!(),
        Command::Run => {
            let config: Config = home
                .read_json(CONFIG)?
                .context("report schedule is not installed")?;
            report::collector_url(&config.collector)?;
            probe_address(&config.vpn_probe)?;
            let mut state: State = home.read_json(STATE)?.unwrap_or_default();
            state.observe(vpn_up(&config.vpn_probe).await);
            save(&home, STATE, &state)?;
            let events = if state.vpn_up {
                checks::event_markers()
            } else {
                checks::EventMarkerReads::default()
            };
            let now = chrono::Utc::now().timestamp();
            if state.should_send(now) || state.should_send_events(events) {
                let acknowledged =
                    report::run_scheduled(&home, &config.collector, &config.vpn_probe).await?;
                state.sent(acknowledged, chrono::Utc::now().timestamp(), events);
                save(&home, STATE, &state)?;
            } else if !state.baseline().security_log_cleared
                || !state.baseline().antimalware_detection
            {
                state.establish_baseline(events);
                save(&home, STATE, &state)?;
            }
        }
        Command::Install {
            collector,
            vpn_probe,
        } => {
            let config = Config::new(collector, vpn_probe)?;
            home.enrolment()?;
            crate::DeviceKey::load(&home.0)?;
            let job = Job::new(&std::env::current_exe()?, &home.0)?;
            save(&home, CONFIG, &config)?;
            save(&home, STATE, &State::default())?;
            register(&job, true)?;
            println!(
                "Installed {}. The OS checks VPN connectivity every five minutes.",
                job.id
            );
        }
        Command::Uninstall => {
            let job = Job::new(&std::env::current_exe()?, &home.0)?;
            register(&job, false)?;
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
        let result = run(&home, Command::Run).await;
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
            assert_eq!(state.should_send_events(current), expected);
        }

        let security_only = reads(Read(Some(101)), Unknown);
        assert!(state.should_send_events(security_only));
        let defender_only = reads(Unknown, Read(Some(201)));
        assert!(state.should_send_events(defender_only));

        let mut uninitialized = State {
            vpn_up: true,
            ..State::default()
        };
        let first_read = reads(Read(Some(100)), Unknown);
        assert!(!uninitialized.should_send_events(first_read));
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
        assert!(!uninitialized.should_send_events(reads(Unknown, Read(Some(200)))));
        uninitialized.establish_baseline(reads(Unknown, Read(Some(200))));
        assert!(!uninitialized.should_send_events(reads(Unknown, Read(Some(200)))));

        let offline = State {
            vpn_up: false,
            ..state
        };
        assert!(!offline.should_send_events(reads(Read(Some(101)), Read(Some(200)))));
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

        state.sent(false, 600, current);

        assert_eq!(state.last_events, Some(previous));
        assert_eq!(state.last_success, Some(500));
        state.observe(true);
        assert!(state.should_send_events(current));
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
    fn windows_task_runs_every_five_minutes_with_separate_arguments() {
        let job = Job::new(
            Path::new(r"C:\Example App\open-pact-client.exe"),
            Path::new(r"C:\Example User\pact"),
        )
        .unwrap();
        let args = job.schtasks_install();
        assert!(args.windows(4).any(|a| a == ["/SC", "MINUTE", "/MO", "5"]));
        let tr = args.iter().position(|arg| arg == "/TR").unwrap();
        assert_eq!(
            args[tr + 1],
            r#""C:\Example App\open-pact-client.exe" "--home" "C:\Example User\pact" "schedule" "run""#
        );
        assert_eq!(windows_arg("a\\"), "\"a\\\\\"");
        assert_eq!(windows_arg("a\"b"), "\"a\\\"b\"");
        assert!(Job::new(Path::new("/bin/client\nother"), Path::new("/home/example")).is_err());
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
                last_events: None,
                event_baseline: None,
            },
        )
        .unwrap();
        assert!(
            run(&home, Command::Run).await.is_err(),
            "no enrolment for report"
        );
        let connected: State = home.read_json(STATE).unwrap().unwrap();
        assert!(connected.vpn_up);
        assert!(connected.reconnect_pending);
        assert!(connected.should_send(chrono::Utc::now().timestamp()));
        drop(listener);
        save(
            &home,
            CONFIG,
            &Config {
                collector: "https://collector.example.org/status".into(),
                vpn_probe: "127.0.0.1:1".into(),
            },
        )
        .unwrap();
        run(&home, Command::Run).await.unwrap();
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
