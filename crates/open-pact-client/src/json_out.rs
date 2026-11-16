//! JSON output for the desktop apps. A command that runs under [`scope`] prints JSON on stdout and
//! nothing else: the text it would have printed goes to a small note buffer, so a failure can still
//! name its last message. Warnings on stderr stay as they are.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use open_pact_core::{ControlValue, ManifestHash, Pseudonym};
use serde::Serialize;
use serde_json::{Value, json};

/// The wizard step titles, for steps that never start.
const TITLES: [&str; 6] = [
    "Check the invitation",
    "Review and sign the manifest",
    "Enrol this device",
    "Wait for IT approval",
    "Set up this device",
    "First check and claim",
];

/// What the owner would have typed in step 5 of the wizard.
#[derive(Clone, Debug, Default)]
pub(crate) struct Answers {
    pub(crate) auto_send: bool,
    pub(crate) folders: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum StepState {
    Started,
    Done,
    Waiting,
    Skipped,
}

#[derive(Serialize)]
struct StepEvent<'a> {
    step: u8,
    title: &'a str,
    state: StepState,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<Value>,
}

#[derive(Serialize)]
struct ResultEvent<'a> {
    result: &'a str,
    device: &'a Pseudonym,
    manifest_hash: &'a ManifestHash,
}

#[derive(Serialize)]
struct ErrorDocument<'a> {
    error: &'a str,
}

/// One control of a sent claim: what the device reported and whether the manifest requires and
/// accepts it. `ok` is null for a control the manifest does not require on this system.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ControlReport {
    pub(crate) id: String,
    pub(crate) value: ControlValue,
    pub(crate) ok: Option<bool>,
}

/// The facts of a claim the gateway answered.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ClaimReport {
    pub(crate) sent_at: String,
    pub(crate) accepted: bool,
    pub(crate) warnings: Vec<String>,
    pub(crate) reasons: Vec<String>,
    pub(crate) controls: Vec<ControlReport>,
}

impl ClaimReport {
    pub(crate) fn new(
        sent_at: String,
        accepted: bool,
        warnings: Vec<String>,
        reasons: Vec<String>,
        results: &BTreeMap<String, ControlValue>,
        compliance: &BTreeMap<String, bool>,
    ) -> Self {
        ClaimReport {
            sent_at,
            accepted,
            warnings,
            reasons,
            controls: results
                .iter()
                .map(|(id, value)| ControlReport {
                    id: id.clone(),
                    value: value.clone(),
                    ok: compliance.get(id).copied(),
                })
                .collect(),
        }
    }
}

#[derive(Default)]
struct State {
    open: Option<(u8, String)>,
    /// The open step waits for someone else, so the run ending does not finish it.
    waiting: bool,
    claim: Option<ClaimReport>,
    notes: Vec<String>,
    partial: String,
    /// The first line that could not be written. The command fails when its output was lost.
    write_error: Option<String>,
}

pub(crate) struct Json {
    out: Mutex<Box<dyn Write + Send>>,
    state: Mutex<State>,
    pub(crate) answers: Answers,
}

tokio::task_local! {
    static JSON: Arc<Json>;
}

const MAX_NOTES: usize = 20;

impl Json {
    pub(crate) fn new(out: impl Write + Send + 'static, answers: Answers) -> Arc<Json> {
        Arc::new(Json {
            out: Mutex::new(Box::new(out)),
            state: Mutex::new(State::default()),
            answers,
        })
    }

    fn line(&self, value: &impl Serialize, pretty: bool) {
        if let Err(error) = self.write_line(value, pretty) {
            self.state.lock().unwrap().write_error.get_or_insert(error);
        }
    }

    fn write_line(&self, value: &impl Serialize, pretty: bool) -> Result<(), String> {
        let text = if pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        }
        .map_err(|error| format!("could not serialize the output: {error}"))?;
        let mut out = self.out.lock().unwrap();
        writeln!(out, "{text}")
            .and_then(|()| out.flush())
            .map_err(|error| format!("could not write the output: {error}"))
    }

    fn step_event(&self, step: u8, title: &str, state: StepState, detail: Option<Value>) {
        self.line(
            &StepEvent {
                step,
                title,
                state,
                detail,
            },
            false,
        );
    }

    fn close_open(&self, detail: Option<Value>) {
        let open = {
            let mut state = self.state.lock().unwrap();
            state.waiting = false;
            state.open.take()
        };
        if let Some((step, title)) = open {
            self.step_event(step, &title, StepState::Done, detail);
        }
    }
}

fn with<R>(f: impl FnOnce(&Json) -> R) -> Option<R> {
    JSON.try_with(|json| f(json)).ok()
}

/// Runs `future` with JSON output on.
pub(crate) async fn scope<F: Future>(json: Arc<Json>, future: F) -> F::Output {
    JSON.scope(json, future).await
}

/// A command runs under [`scope`]: its text output is not printed.
pub(crate) fn active() -> bool {
    with(|_| ()).is_some()
}

/// The answers a `join --json` run was given, when it runs.
pub(crate) fn answers() -> Option<Answers> {
    with(|json| json.answers.clone())
}

/// What a `println!` would have printed.
pub(crate) fn note_line(text: String) {
    with(|json| {
        let mut state = json.state.lock().unwrap();
        let line = std::mem::take(&mut state.partial) + &text;
        state.notes.push(line);
        if state.notes.len() > MAX_NOTES {
            state.notes.remove(0);
        }
    });
}

/// What a `print!` would have printed.
pub(crate) fn note_partial(text: String) {
    with(|json| json.state.lock().unwrap().partial.push_str(&text));
}

/// The last message the command would have printed, for a failure that has no error of its own.
pub(crate) fn last_note() -> Option<String> {
    with(|json| {
        let state = json.state.lock().unwrap();
        state
            .notes
            .iter()
            .rev()
            .flat_map(|note| note.lines().rev())
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    })
    .flatten()
}

/// Why a line of output was lost, if one was. A command that lost its output did not deliver its
/// result, so it must not exit with success.
pub(crate) fn write_failure() -> Option<String> {
    with(|json| json.state.lock().unwrap().write_error.clone()).flatten()
}

/// The exit code of a command that ran under [`scope`]: failure when its output was lost.
pub(crate) fn settle(code: ExitCode) -> ExitCode {
    match write_failure() {
        Some(error) => {
            let _ = writeln!(std::io::stderr(), "error: {error}");
            ExitCode::FAILURE
        }
        None => code,
    }
}

/// Prints one JSON document.
pub(crate) fn document(value: &impl Serialize) {
    with(|json| json.line(value, true));
}

/// Prints `{"error": ...}`.
pub(crate) fn error(text: &str) {
    with(|json| json.line(&ErrorDocument { error: text }, false));
}

/// Step `step` starts. The step that is still open ends first.
pub(crate) fn step_started(step: u8, title: &str) {
    with(|json| {
        json.close_open(None);
        json.state.lock().unwrap().open = Some((step, title.to_owned()));
        json.step_event(step, title, StepState::Started, None);
    });
}

/// The open step waits for someone else; `detail` says for what.
pub(crate) fn step_waiting(detail: Value) {
    with(|json| {
        let open = {
            let mut state = json.state.lock().unwrap();
            state.waiting = state.open.is_some();
            state.open.clone()
        };
        if let Some((step, title)) = open {
            json.step_event(step, &title, StepState::Waiting, Some(detail));
        }
    });
}

/// Step `step` ends, if it is the open one.
pub(crate) fn step_done(step: u8, detail: Option<Value>) {
    with(|json| {
        let is_open = json
            .state
            .lock()
            .unwrap()
            .open
            .as_ref()
            .is_some_and(|(open, _)| *open == step);
        if is_open {
            json.close_open(detail);
        }
    });
}

/// These steps do not run, for example because the device is enrolled already.
pub(crate) fn steps_skipped(steps: &[u8]) {
    with(|json| {
        for &step in steps {
            json.step_event(
                step,
                TITLES[usize::from(step) - 1],
                StepState::Skipped,
                None,
            );
        }
    });
}

pub(crate) fn set_claim(report: ClaimReport) {
    with(|json| json.state.lock().unwrap().claim = Some(report));
}

pub(crate) fn claim() -> Option<ClaimReport> {
    with(|json| json.state.lock().unwrap().claim.clone()).flatten()
}

/// Ends the open step, unless it waits for someone else, and prints the last line of a
/// `join --json`.
pub(crate) fn finish(result: &str, device: &Pseudonym, manifest_hash: &ManifestHash) {
    with(|json| {
        if json.state.lock().unwrap().waiting {
            json.state.lock().unwrap().open = None;
        } else {
            json.close_open(None);
        }
        json.line(
            &ResultEvent {
                result,
                device,
                manifest_hash,
            },
            false,
        );
    });
}

/// The error of a command that failed: the line, and a failure exit code.
pub(crate) fn failed(error_text: &str) -> ExitCode {
    error(error_text);
    ExitCode::FAILURE
}

/// A claim the gateway did not receive: the `detail` of step 6.
pub(crate) fn not_sent_detail(reason: &str) -> Value {
    json!({ "sent": false, "reason": reason })
}

/// Stops the process after a Ctrl-C, with the exit code 130.
pub(crate) fn exit_interrupted() -> ! {
    error("interrupted");
    std::process::exit(130)
}

#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// A writer whose bytes a test reads back.
    #[derive(Clone, Default)]
    pub(crate) struct Capture(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        /// Every line as a JSON value.
        pub(crate) fn lines(&self) -> Vec<serde_json::Value> {
            self.text()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }
}
