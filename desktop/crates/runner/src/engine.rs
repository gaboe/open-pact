//! The engine of the client app. It owns one tokio runtime, runs each call of the client library on
//! it, and keeps the log of what the app asked the library to do. A call never runs on the GPUI
//! thread, so a claim lock that a call holds never blocks the window.

use crate::ownership::{self, OtherCopy};
use crate::{Runner, args, client, find_on_path, tool_path};
use open_pact_client::Session;
use open_pact_client::status::Report;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// The CLI builds its runtime on a thread with 8 MiB, because the debug futures of the client
/// overflow the 1 MiB main stack of Windows. Every thread of the app's runtime gets the same.
pub const STACK_BYTES: usize = 8 * 1024 * 1024;

/// The progress loop of operation `mine` may write while that operation is the current one and
/// still runs. An older loop that finds a newer operation stops without writing.
pub fn owns_progress(current: u64, mine: u64, busy: bool) -> bool {
    busy && current == mine
}

/// How long a process that the app starts at launch may run before the app stops it.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// One call of the library, as the Terminal strip shows it. `result` is `None` while it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationEntry {
    pub operation: String,
    pub at: String,
    pub result: Option<Result<String, String>>,
}

/// What the app asked the library to do, in order: the operation, its time and its result.
#[derive(Clone, Default)]
pub struct OperationLog(Arc<Mutex<Vec<OperationEntry>>>);

impl OperationLog {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<OperationEntry>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn entries(&self) -> Vec<OperationEntry> {
        self.lock().clone()
    }

    /// Starts an entry and gives its place, for `finish`.
    pub fn begin(&self, operation: &str) -> usize {
        let mut entries = self.lock();
        entries.push(OperationEntry {
            operation: operation.to_owned(),
            at: crate::zone::to_local(time::OffsetDateTime::now_utc())
                .format(time::macros::format_description!(
                    "[hour]:[minute]:[second]"
                ))
                .expect("a time of day has this form"),
            result: None,
        });
        entries.len() - 1
    }

    pub fn finish(&self, place: usize, result: Result<String, String>) {
        if let Some(entry) = self.lock().get_mut(place) {
            entry.result = Some(result);
        }
    }

    /// An operation that is over already.
    pub fn record(&self, operation: &str, result: Result<String, String>) {
        let place = self.begin(operation);
        self.finish(place, result);
    }
}

/// The result of a call that runs on the runtime. The GPUI executor awaits it. A call that the
/// runtime dropped, such as one in flight when the app quits, is an error.
pub struct Reply<T>(oneshot::Receiver<Result<T, String>>);

impl<T> Future for Reply<T> {
    type Output = Result<T, String>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0)
            .poll(cx)
            .map(|received| received.unwrap_or_else(|_| Err("The background task stopped.".into())))
    }
}

/// The runtime, which stops without waiting. A runtime that is dropped waits for every blocking
/// call, such as a process, and the last engine is dropped on the GPUI thread when the window
/// closes. This one hands its threads off instead, and the process exit ends what still runs.
struct Background(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for Background {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("the runtime lives until it is dropped")
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

#[derive(Clone)]
pub struct Engine {
    runtime: Arc<Background>,
    pub log: OperationLog,
}

impl Engine {
    pub fn start() -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_stack_size(STACK_BYTES)
            .enable_all()
            .build()
            .map_err(|error| format!("Cannot start the background runtime: {error}"))?;
        Ok(Self {
            runtime: Arc::new(Background(Some(runtime))),
            log: OperationLog::default(),
        })
    }

    /// Runs `work` on the runtime and gives its result back through a oneshot channel that the GPUI
    /// executor can await. The log shows `operation` while it runs and `summary` of its value
    /// when it ends.
    pub fn call<T, F>(
        &self,
        operation: &str,
        summary: impl FnOnce(&T) -> String + Send + 'static,
        work: F,
    ) -> Reply<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, String>> + Send + 'static,
    {
        let log = self.log.clone();
        let place = log.begin(operation);
        let (sender, receiver) = oneshot::channel();
        self.runtime.spawn(async move {
            let result = work.await;
            log.finish(
                place,
                match &result {
                    Ok(value) => Ok(summary(value)),
                    Err(error) => Err(error.clone()),
                },
            );
            let _ = sender.send(result);
        });
        Reply(receiver)
    }
}

/// The session of this device. The library resolves the default home the way the command line
/// tool does, so the app and the OS job read and write the same files. `installed` is the
/// executable of the OS job.
pub fn session(installed: &Path) -> Result<Session, String> {
    Session::open(None, installed.to_path_buf()).map_err(|error| format!("{error:#}"))
}

/// Runs a blocking call, such as a process, on a thread that is not a runtime worker.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| error.to_string())?
}

/// What the app found when it opened: the device status, the other copies of the command line
/// tool, and a warning when something it tried did not work.
pub struct Opened {
    pub status: Report,
    pub others: Vec<OtherCopy>,
    pub warning: Option<String>,
}

impl Opened {
    /// The join continues when this device still has steps open, whether the app found the device
    /// on start or installed its command line tool first. Gives the automatic-sending choice to
    /// continue with.
    pub fn resume_join(&self) -> Option<bool> {
        crate::status_text::resume_join(&self.status)
    }
}

/// Whether the installed copy exists and matches the bundled one.
#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    /// There is no installed copy: the app asks before it installs one.
    Missing,
    Current,
    /// The installed copy was another version, and the app replaced it with the bundled one.
    Replaced,
}

/// The app owns the command line tool that the OS job runs, so the installed copy is always the
/// bundled one. A copy of another version is replaced; a missing one waits for the user's click.
pub fn refresh_installed(
    runner: &Runner,
    log: &OperationLog,
    bundled: &Path,
    installed: &Path,
) -> Result<Installed, String> {
    if !installed.is_file() {
        return Ok(Installed::Missing);
    }
    // A version check that hangs must not keep the app from ever showing its first screen.
    let runner = &runner.with_timeout(STARTUP_TIMEOUT);
    let wanted = client::version(runner, bundled)?;
    if client::version(runner, installed).is_ok_and(|found| found == wanted) {
        return Ok(Installed::Current);
    }
    let place = log.begin("Replace the installed command line tool");
    let result = client::install(runner, bundled, installed);
    log.finish(
        place,
        result
            .clone()
            .map(|()| format!("{} is now {wanted}", installed.display())),
    );
    result.map(|()| Installed::Replaced)
}

/// Every other command line tool on PATH. Homebrew is asked where it keeps the package, because
/// its links in `bin` point into its Cellar.
pub fn find_other_copies(runner: &Runner, installed: &Path, bundled: &Path) -> Vec<OtherCopy> {
    let mut roots = Vec::new();
    if find_on_path("brew").is_some()
        && let Ok(log) = runner
            .with_timeout(STARTUP_TIMEOUT)
            .run(Path::new("brew"), &args(&["--prefix", "open-pact"]))
    {
        let prefix = PathBuf::from(log.stdout.trim());
        if !prefix.as_os_str().is_empty() {
            roots.push(std::fs::canonicalize(&prefix).unwrap_or(prefix));
        }
    }
    ownership::other_copies(
        tool_path(),
        client::cli_name(),
        &[installed.to_path_buf(), bundled.to_path_buf()],
        &roots,
    )
}

/// Runs the removal command of `copy` and gives what it printed. Only the user's click calls it.
pub fn remove_copy(runner: &Runner, copy: &OtherCopy) -> Result<String, String> {
    let removal = ownership::removal(copy, crate::update::Platform::current());
    let log = runner
        .with_timeout(Duration::from_secs(300))
        .with_env(&removal.call.env)
        .run(Path::new(&removal.call.program), &removal.call.args)?;
    let output = format!("{}\n{}", log.stdout.trim(), log.stderr.trim());
    let output = output.trim();
    Ok(if output.is_empty() {
        "Done.".to_owned()
    } else {
        output.to_owned()
    })
}

/// Starts the installed copy elevated to install the SYSTEM job. The library cannot elevate, so
/// this is the one place where the app runs the command line tool as a process.
pub fn install_system_job(
    runner: &Runner,
    log: &OperationLog,
    installed: &Path,
    home: &Path,
) -> Result<(), String> {
    let place = log.begin("Schedule on --system (administrator)");
    let result = system_profile(std::env::var_os("USERPROFILE")).and_then(|profile| {
        let call = ownership::elevated_system_schedule(installed, home, &profile);
        runner
            .with_timeout(Duration::from_secs(300))
            .run(Path::new(&call.program), &call.args)
            .map(|_| ())
    });
    log.finish(
        place,
        result.clone().map(|()| {
            "The administrator process finished. The status shows whether the SYSTEM job is confirmed."
                .to_owned()
        }),
    );
    result
}

/// Starts this app again through the UAC prompt, for a join that needs administrator rights. The
/// caller quits this instance when it gets `Ok`. A cancelled prompt is an error with a plain text.
pub fn restart_elevated(runner: &Runner, exe: &Path) -> Result<(), String> {
    let call = ownership::elevated_restart(exe);
    runner
        .with_timeout(Duration::from_secs(300))
        .run(Path::new(&call.program), &call.args)
        .map(|_| ())
        .map_err(|error| {
            format!("The restart as administrator was cancelled or did not start: {error}")
        })
}

/// The profile whose repositories the SYSTEM job scans: the one of the user who runs the app.
fn system_profile(variable: Option<std::ffi::OsString>) -> Result<PathBuf, String> {
    variable
        .filter(|profile| !profile.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            "USERPROFILE is not set, so the SYSTEM job cannot know whose repositories it scans."
                .to_owned()
        })
}

/// The status of a device, and the two things the app does for the device it owns: it moves the
/// OS job to the installed copy, and it looks for other copies. `installed` is what the library
/// gets as the job executable.
pub async fn inspect(
    runner: Runner,
    log: OperationLog,
    bundled: PathBuf,
    installed: PathBuf,
) -> Result<Opened, String> {
    let session = session(&installed)?;
    let mut warning = None;
    let mut status = session.status(true).await.map_err(|e| format!("{e:#}"))?;
    let job = session.job_executable().ok().flatten();
    let consented = status.schedule.owner_consented == Some(true);
    let system = status.schedule.system_job;
    if ownership::job_needs_rewrite(job.as_deref(), &installed, consented, system) {
        let was = job
            .as_deref()
            .map(|job| job.display().to_string())
            .unwrap_or_default();
        let place = log.begin("Move the scheduled job to the installed command line tool");
        match session.schedule(true).await {
            Ok(()) => {
                log.finish(place, Ok(format!("{was} -> {}", installed.display())));
                status = session.status(true).await.map_err(|e| format!("{e:#}"))?;
            }
            Err(error) => {
                let text = format!("{error:#}");
                log.finish(place, Err(text.clone()));
                warning = Some(format!(
                    "The scheduled job still runs {was}, not the installed command line tool: {text}"
                ));
            }
        }
    }
    let others =
        tokio::task::spawn_blocking(move || find_other_copies(&runner, &installed, &bundled))
            .await
            .map_err(|e| e.to_string())?;
    Ok(Opened {
        status,
        others,
        warning,
    })
}

/// What the app does at start: the installed copy matches the bundled one, then `inspect`.
/// `None` means there is no installed copy yet.
pub async fn open(
    runner: Runner,
    log: OperationLog,
    bundled: PathBuf,
    installed: PathBuf,
) -> Result<Option<Opened>, String> {
    let (r, l, b, i) = (
        runner.clone(),
        log.clone(),
        bundled.clone(),
        installed.clone(),
    );
    let state = tokio::task::spawn_blocking(move || refresh_installed(&r, &l, &b, &i))
        .await
        .map_err(|e| e.to_string())??;
    if state == Installed::Missing {
        return Ok(None);
    }
    inspect(runner, log, bundled, installed).await.map(Some)
}

/// Installs the bundled copy, optionally puts its folder on PATH, then `inspect`.
pub async fn install(
    runner: Runner,
    log: OperationLog,
    bundled: PathBuf,
    installed: PathBuf,
    also_terminal: bool,
) -> Result<Opened, String> {
    let (r, l, b, i) = (
        runner.clone(),
        log.clone(),
        bundled.clone(),
        installed.clone(),
    );
    let terminal = tokio::task::spawn_blocking(move || {
        let place = l.begin("Install the command line tool");
        let result = client::install(&r, &b, &i);
        l.finish(place, result.clone().map(|()| i.display().to_string()));
        result?;
        Ok::<_, String>(if also_terminal {
            client::enable_terminal(&i).err().map(|error| {
                format!(
                    "The tool is installed, but Terminal setup failed: {error}. Add {} to your PATH by hand.",
                    i.parent().map(|p| p.display().to_string()).unwrap_or_default()
                )
            })
        } else {
            None
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    let mut opened = inspect(runner, log, bundled, installed).await?;
    opened.warning = terminal.or(opened.warning);
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_text::verdict_word;

    #[test]
    fn a_call_runs_on_the_runtime_and_the_log_shows_what_it_did() {
        let engine = Engine::start().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let cli = temp.path().join("open-pact-client");
        let reply = engine.call(
            "Status",
            |report: &Report| verdict_word(report.verdict).to_owned(),
            async move {
                let session = Session::open(Some(home), cli).map_err(|e| format!("{e:#}"))?;
                session.status(false).await.map_err(|e| format!("{e:#}"))
            },
        );
        let report = engine.runtime.block_on(reply).unwrap();
        let entries = engine.log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, "Status");
        assert_eq!(
            entries[0].result,
            Some(Ok(verdict_word(report.verdict).to_owned()))
        );
    }

    #[test]
    fn a_failed_call_is_an_error_in_the_reply_and_in_the_log() {
        let engine = Engine::start().unwrap();
        let reply = engine.call("Check", |_: &()| String::new(), async {
            Err::<(), _>("The gateway did not answer.".to_owned())
        });
        assert_eq!(
            engine.runtime.block_on(reply),
            Err("The gateway did not answer.".to_owned())
        );
        assert_eq!(
            engine.log.entries()[0].result,
            Some(Err("The gateway did not answer.".to_owned()))
        );
    }

    /// The debug futures of the client overflow the 1 MiB main stack of Windows, so a call runs on
    /// a thread with 8 MiB.
    #[test]
    fn a_call_has_a_stack_of_eight_mebibytes() {
        fn deep() -> u8 {
            let array = [7u8; 3 * 1024 * 1024];
            std::hint::black_box(&array)[array.len() - 1]
        }
        let engine = Engine::start().unwrap();
        let reply = engine.call("Deep", |_: &u8| String::new(), async { Ok(deep()) });
        assert_eq!(engine.runtime.block_on(reply), Ok(7));
    }

    /// Closing the window drops the last engine on the GPUI thread. A process that still runs
    /// on the runtime must not hold that thread.
    #[test]
    fn dropping_the_engine_does_not_wait_for_a_running_blocking_call() {
        let engine = Engine::start().unwrap();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = std::sync::mpsc::channel::<()>();
        engine.runtime.spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv_timeout(Duration::from_secs(10));
        });
        running.recv_timeout(Duration::from_secs(5)).unwrap();
        let before = std::time::Instant::now();
        drop(engine);
        let waited = before.elapsed();
        let _ = release.send(());
        assert!(
            waited < Duration::from_secs(3),
            "the drop waited {waited:?}"
        );
    }

    /// Open finishes and starts Resume join in one update, so `busy` is never false between
    /// them. Only the operation number tells the old progress loop that it is over.
    #[test]
    fn a_progress_loop_stops_when_its_operation_has_a_successor() {
        assert!(owns_progress(1, 1, true));
        assert!(!owns_progress(2, 1, true));
        assert!(owns_progress(2, 2, true));
        assert!(!owns_progress(2, 2, false));
    }

    #[test]
    fn the_system_profile_is_the_profile_of_the_app_user_and_never_a_guess() {
        assert_eq!(
            system_profile(Some(r"C:\Users\Fictional".into())),
            Ok(PathBuf::from(r"C:\Users\Fictional"))
        );
        assert!(system_profile(None).is_err());
        assert!(system_profile(Some("".into())).is_err());
    }

    /// An install of the command line tool continues the join of a device that is still open,
    /// as an open of the app does.
    #[test]
    fn an_opened_device_with_a_pending_approval_resumes_its_join() {
        use crate::samples;
        let mut status = samples::report(open_pact_client::status::Verdict::ActionNeeded, 0);
        status.approval.state = Some(open_pact_core::DeviceStatus::Pending);
        let opened = Opened {
            status,
            others: Vec::new(),
            warning: None,
        };
        assert_eq!(opened.resume_join(), Some(true));
        let settled = Opened {
            status: samples::report_good(),
            others: Vec::new(),
            warning: None,
        };
        assert_eq!(settled.resume_join(), None);
    }

    #[test]
    fn the_log_keeps_a_running_entry_until_it_finishes() {
        let log = OperationLog::default();
        let place = log.begin("Join");
        assert_eq!(log.entries()[0].result, None);
        log.finish(place, Ok("done".into()));
        assert_eq!(log.entries()[0].result, Some(Ok("done".into())));
    }
}
