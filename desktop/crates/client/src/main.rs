#![cfg_attr(windows, windows_subsystem = "windows")]

use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputState},
    switch::Switch,
};
use open_pact_client::{
    AcceptPreview, ClaimReport, JoinChoices, JoinPreview, JoinStep, Session, StepState,
    WAITING_FOR_JOB, status::Report,
};
use open_pact_core::{DeviceStatus, Schedule};
use runner::{
    Runner, client,
    desktop::*,
    engine::{self, Engine, Opened, Reply, owns_progress},
    ownership::{self, OtherCopy},
    status_text::*,
    text::*,
    update::{self, Platform, UpdateState},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
enum Screen {
    Install,
    Invitation,
    Review(Arc<JoinPreview>),
    /// A new join on Windows needs an elevated process; the app offers to restart as administrator.
    NeedsAdmin,
    Joining(Vec<JoinStep>),
    Status(Arc<Report>),
    Changed(Arc<AcceptPreview>),
}

enum Operation {
    Open,
    Install(bool),
    Preview(String),
    Join(String, Vec<String>, bool),
    /// Starts this app again through the UAC prompt, then quits this instance.
    Restart,
    Status,
    Check,
    Changes,
    Accept,
    Schedule(bool),
    UpdateCli(String),
    RemoveCopy(OtherCopy),
}

enum Outcome {
    /// `None`: there is no installed command line tool yet.
    Opened(Option<Opened>),
    Installed(Opened),
    Preview(JoinPreview),
    Status(Report),
    Joined(Report, Option<ClaimReport>),
    /// The join stopped before it sent anything: it needs an elevated process.
    NeedsElevation,
    /// The administrator copy of the app started.
    Restarted,
    Check(ClaimReport, Report),
    Changes(AcceptPreview),
    Removed(String, Vec<OtherCopy>),
}

impl Outcome {
    /// The result column of the operation log.
    fn summary(&self) -> String {
        let opened = |opened: &Opened| {
            format!(
                "{}, other copies of the command line tool: {}",
                verdict_word(opened.status.verdict),
                opened.others.len()
            )
        };
        match self {
            Self::Opened(None) => "the command line tool is not installed yet".into(),
            Self::Opened(Some(found)) | Self::Installed(found) => opened(found),
            Self::Preview(preview) => format!(
                "{}, company key {}",
                preview.company.name,
                if preview.company.matches_invitation {
                    "matches"
                } else {
                    "does not match"
                }
            ),
            Self::Status(status) | Self::Joined(status, _) => verdict_word(status.verdict).into(),
            Self::NeedsElevation => "needs an administrator; nothing was sent".into(),
            Self::Restarted => "the administrator copy of the app started".into(),
            Self::Check(check, _) if check.accepted => "accepted".into(),
            Self::Check(check, _) => format!("denied: {}", check.reasons.join("; ")),
            Self::Changes(changes) => format!("{} changes", changes.changes.len()),
            Self::Removed(output, _) => output.lines().next().unwrap_or_default().to_owned(),
        }
    }
}

struct AppView {
    engine: Engine,
    runner: Runner,
    bundled: PathBuf,
    /// The command line tool this app installed. The OS job runs it, and the library gets it as
    /// the job executable.
    installed: PathBuf,
    screen: Screen,
    invitation: Entity<InputState>,
    folders: Vec<Entity<InputState>>,
    automatic: bool,
    also_terminal: bool,
    busy: bool,
    /// The number of the operation in flight, or the last one. Each operation's progress loop
    /// belongs to its own number, because `busy` alone is false and true again within one update
    /// when a finished operation starts its successor.
    operation: u64,
    error: Option<String>,
    terminal: bool,
    all_controls: bool,
    last_check: Option<ClaimReport>,
    /// The step events of the call in flight, such as the wait for the scheduled job.
    steps: Vec<JoinStep>,
    /// Command line tools on PATH that this app did not install, and the output of the removal.
    others: Vec<OtherCopy>,
    removal_output: Option<String>,
    /// The device runs its scheduled job as SYSTEM. Only an elevated process can install it.
    system_job: bool,
    /// Fixtures set this RFC 3339 time. The app uses the real clock.
    clock: Option<String>,
    update: UpdateState,
}

impl AppView {
    fn new(
        screen: Screen,
        engine: Engine,
        runner: Runner,
        bundled: PathBuf,
        installed: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        Self {
            engine,
            runner,
            bundled,
            installed,
            screen,
            invitation: cx.new(|cx| InputState::new(window, cx).placeholder("opi1:…")),
            folders: Vec::new(),
            automatic: false,
            also_terminal: true,
            busy: false,
            operation: 0,
            error: None,
            terminal: false,
            all_controls: false,
            last_check: None,
            steps: Vec::new(),
            others: Vec::new(),
            removal_output: None,
            system_job: false,
            clock: None,
            update: UpdateState::None,
        }
    }

    /// Sends one operation to the runtime. The step events of the call go to `steps`, which the
    /// window reads while the call runs.
    fn start_call(&self, operation: Operation, steps: Arc<Mutex<Vec<JoinStep>>>) -> Reply<Outcome> {
        let engine = self.engine.clone();
        let runner = self.runner.clone();
        let bundled = self.bundled.clone();
        let installed = self.installed.clone();
        let log = engine.log.clone();
        let on_step = move || {
            let steps = steps.clone();
            move |step: JoinStep| steps.lock().unwrap_or_else(|e| e.into_inner()).push(step)
        };
        let system_job = self.system_job;
        match operation {
            Operation::Open => engine.call("Open", Outcome::summary, async move {
                engine::open(runner, log, bundled, installed)
                    .await
                    .map(Outcome::Opened)
            }),
            Operation::Install(also_terminal) => {
                engine.call("Install", Outcome::summary, async move {
                    engine::install(runner, log, bundled, installed, also_terminal)
                        .await
                        .map(Outcome::Installed)
                })
            }
            Operation::Preview(invitation) => {
                engine.call("Join preview", Outcome::summary, async move {
                    let session = engine::session(&installed)?;
                    session
                        .join_preview(&invitation)
                        .await
                        .map(Outcome::Preview)
                        .map_err(|e| format!("{e:#}"))
                })
            }
            Operation::Join(invitation, folders, auto_send) => engine.call(
                if invitation.is_empty() {
                    "Resume join"
                } else {
                    "Join"
                },
                Outcome::summary,
                async move {
                    let session = engine::session(&installed)?;
                    let choices = JoinChoices {
                        software_key: false,
                        no_wait: false,
                        auto_send,
                        folders: folders.into_iter().map(PathBuf::from).collect(),
                    };
                    let cancel = std::future::pending::<()>();
                    let joined = if invitation.is_empty() {
                        session.resume_join(choices, cancel, on_step()).await
                    } else {
                        session.join(&invitation, choices, cancel, on_step()).await
                    };
                    let joined = match joined {
                        Ok(joined) => joined,
                        Err(error) if error.is::<open_pact_client::NeedsElevation>() => {
                            return Ok(Outcome::NeedsElevation);
                        }
                        Err(error) => return Err(format!("{error:#}")),
                    };
                    let status = status_of(&session).await?;
                    Ok(Outcome::Joined(status, joined.claim))
                },
            ),
            Operation::Restart => {
                engine.call("Restart as administrator", Outcome::summary, async move {
                    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                    engine::blocking(move || engine::restart_elevated(&runner, &exe)).await?;
                    Ok(Outcome::Restarted)
                })
            }
            Operation::Status => engine.call("Status", Outcome::summary, async move {
                status_of(&engine::session(&installed)?)
                    .await
                    .map(Outcome::Status)
            }),
            Operation::Check => engine.call("Check", Outcome::summary, async move {
                let session = engine::session(&installed)?;
                let check = session
                    .check_with(on_step())
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                let status = status_of(&session).await?;
                Ok(Outcome::Check(check, status))
            }),
            Operation::Changes => engine.call("Accept preview", Outcome::summary, async move {
                let session = engine::session(&installed)?;
                session
                    .accept_preview()
                    .await
                    .map(Outcome::Changes)
                    .map_err(|e| format!("{e:#}"))
            }),
            Operation::Accept => engine.call("Accept", Outcome::summary, async move {
                let session = engine::session(&installed)?;
                session
                    .accept_with(on_step())
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                status_of(&session).await.map(Outcome::Status)
            }),
            Operation::Schedule(enabled) => engine.call(
                if enabled {
                    "Schedule on"
                } else {
                    "Schedule off"
                },
                Outcome::summary,
                async move {
                    let session = engine::session(&installed)?;
                    if enabled && cfg!(windows) && system_job {
                        let (runner, log, installed) = (runner, log, installed.clone());
                        let home = session.home().to_path_buf();
                        engine::blocking(move || {
                            engine::install_system_job(&runner, &log, &installed, &home)
                        })
                        .await?;
                    } else {
                        session
                            .schedule(enabled)
                            .await
                            .map_err(|e| format!("{e:#}"))?;
                    }
                    status_of(&session).await.map(Outcome::Status)
                },
            ),
            Operation::UpdateCli(line) => engine.call(
                "Update the command line tool",
                Outcome::summary,
                async move {
                    let call = update::shell_invocation(Platform::current(), &line);
                    let run = runner.clone();
                    engine::blocking(move || update::run(&run, &call)).await?;
                    status_of(&engine::session(&installed)?)
                        .await
                        .map(Outcome::Status)
                },
            ),
            Operation::RemoveCopy(copy) => {
                engine.call("Remove another copy", Outcome::summary, async move {
                    let (run, target) = (runner.clone(), copy);
                    let output =
                        engine::blocking(move || engine::remove_copy(&run, &target)).await?;
                    let others = engine::blocking(move || {
                        Ok(engine::find_other_copies(&runner, &installed, &bundled))
                    })
                    .await?;
                    Ok(Outcome::Removed(output, others))
                })
            }
        }
    }

    fn run(&mut self, operation: Operation, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.operation += 1;
        let mine = self.operation;
        self.error = None;
        self.removal_output = None;
        self.steps.clear();
        if matches!(operation, Operation::Join(..)) {
            self.screen = Screen::Joining(Vec::new());
        }
        let progress = Arc::new(Mutex::new(Vec::<JoinStep>::new()));
        let incoming = progress.clone();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let Ok(keep_running) = this.update(cx, |this, cx| {
                    if !owns_progress(this.operation, mine, this.busy) {
                        return false;
                    }
                    let steps = incoming.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    if steps != this.steps {
                        if let Screen::Joining(events) = &mut this.screen {
                            *events = steps.clone();
                        }
                        this.steps = steps;
                        cx.notify();
                    }
                    true
                }) else {
                    break;
                };
                if !keep_running {
                    break;
                }
            }
        })
        .detach();
        let reply = self.start_call(operation, progress);
        cx.spawn(async move |this, cx| {
            let result = reply.await;
            let _ = this.update(cx, |this, cx| {
                this.busy = false;
                this.finish(result, cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn finish(&mut self, result: Result<Outcome, String>, cx: &mut Context<Self>) {
        match result {
            Ok(Outcome::Opened(None)) => self.screen = Screen::Install,
            // An install goes on like an open: a device with join steps still open resumes them.
            Ok(Outcome::Opened(Some(opened))) | Ok(Outcome::Installed(opened)) => {
                let resume = opened.resume_join();
                let warning = opened.warning.clone();
                self.adopt(opened);
                if let Some(automatic) = resume {
                    self.run(Operation::Join(String::new(), Vec::new(), automatic), cx);
                    // Starting an operation clears the error; the warning of the open stays.
                    self.error = self.error.take().or(warning);
                }
            }
            Ok(Outcome::Preview(preview)) => {
                self.automatic = false;
                self.folders.clear();
                self.screen = Screen::Review(Arc::new(preview));
            }
            Ok(Outcome::Status(status)) => self.show_status(status),
            Ok(Outcome::Joined(status, claim)) => {
                // A denied first claim is a result, not a failure: show which checks failed.
                if let Some(claim) = claim {
                    self.all_controls |= !claim.accepted;
                    self.last_check = Some(claim);
                }
                self.show_status(status);
            }
            Ok(Outcome::NeedsElevation) => self.screen = Screen::NeedsAdmin,
            // The administrator copy runs now: this instance has nothing left to do.
            Ok(Outcome::Restarted) => cx.quit(),
            Ok(Outcome::Check(check, status)) => {
                // A denied claim is a result, not a failure: show which checks failed.
                if !check.accepted {
                    self.all_controls = true;
                }
                self.last_check = Some(check);
                self.show_status(status);
            }
            Ok(Outcome::Changes(changes)) => self.screen = Screen::Changed(Arc::new(changes)),
            Ok(Outcome::Removed(output, others)) => {
                self.removal_output = Some(output);
                self.others = others;
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// The device status that the app found when it opened, with the other copies of the tool.
    fn adopt(&mut self, opened: Opened) {
        self.others = opened.others;
        self.error = opened.warning;
        self.show_status(opened.status);
    }

    fn show_status(&mut self, status: Report) {
        self.system_job =
            status.schedule.job_status == Some(open_pact_client::JobStatus::SystemUnconfirmed);
        self.screen = if status.approval.state.is_none() && status.manifest.is_none() {
            Screen::Invitation
        } else {
            Screen::Status(Arc::new(status))
        };
    }

    /// One notice about another command line tool, with the exact command that removes it.
    fn copies_view(&self, cx: &mut Context<Self>) -> Option<Div> {
        if self.others.is_empty() && self.removal_output.is_none() {
            return None;
        }
        let mut view = column().gap_2();
        if let Some(copy) = self.others.first().cloned() {
            let removal = ownership::removal(&copy, Platform::current());
            view = view
                .child(banner(
                    format!(
                        "Another open-pact command line tool is on this computer: {}. The scheduled job runs only the copy this app installed, {}. Remove the other copy so that it cannot run by itself.",
                        copy.path.display(),
                        self.installed.display()
                    ),
                    BLUE_INK,
                    BLUE_WASH,
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(div().flex_1().min_w_0().child(runs("runs", removal.shown)))
                        .child(
                            Button::new("remove-copy")
                                .label("Remove")
                                .small()
                                .disabled(self.busy)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run(Operation::RemoveCopy(copy.clone()), cx)
                                })),
                        ),
                );
        }
        if let Some(output) = &self.removal_output {
            view = view
                .child(note("Output of the removal"))
                .child(code(output.clone()));
        }
        Some(view)
    }

    fn button(
        &self,
        id: &'static str,
        text: &'static str,
        operation: impl Fn(&Self, &App) -> Operation + 'static,
        primary: bool,
        cx: &Context<Self>,
    ) -> Button {
        let button = Button::new(id)
            .label(text)
            .disabled(self.busy)
            .on_click(cx.listener(move |this, _, _, cx| {
                let operation = operation(this, cx);
                this.run(operation, cx);
            }));
        if primary { button.primary() } else { button }
    }

    fn action(
        &self,
        id: &'static str,
        text: &'static str,
        operation: impl Fn(&Self, &App) -> Operation + 'static,
        cx: &Context<Self>,
    ) -> Button {
        self.button(id, text, operation, true, cx)
    }

    fn content(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        match self.screen.clone() {
            Screen::Install => {
                let version = self
                    .runner
                    .logs()
                    .into_iter()
                    .find(|entry| entry.args == ["--version"])
                    .map(|entry| entry.stdout.trim().to_owned())
                    .unwrap_or_else(|| "Bundled command line tool".into());
                let location = if cfg!(windows) {
                    "%LOCALAPPDATA%\\open-pact\\open-pact-client.exe"
                } else {
                    "~/.local/bin/open-pact-client"
                };
                column()
                    .child(title("Set up open-pact on this computer"))
                    .child(div().text_color(rgb(INK_2)).child("The scheduled check runs a small command line tool that comes with this app. The app puts it in a fixed place so the check keeps working when you move or update the app, and keeps it up to date. No other copy runs the check."))
                    .child(table()
                        .child(row("Command line tool", div().font_family(mono()).text_size(px(13.)).child(location)))
                        .child(row("Version", version)))
                    .child(column().gap_1()
                        .child(Checkbox::new("also-terminal").label("Also use it in Terminal").checked(self.also_terminal).disabled(self.busy)
                            .on_click(cx.listener(|this, checked: &bool, _, cx| { this.also_terminal = *checked; cx.notify(); })))
                        .child(note("Adds the folder to your PATH. You can skip this. Open a new Terminal after installation.").pl(px(26.))))
                    .child(actions().child(self.action("install", "Install and continue", |this, _| Operation::Install(this.also_terminal), cx)))
                    .child(runs("copies the bundled tool, then runs", "open-pact-client --version"))
            }
            Screen::Invitation => column()
                .child(title("Join your company"))
                .child(div().text_color(rgb(INK_2)).child("Paste the invitation line that IT sent you. It starts with opi1: and works once, for 72 hours."))
                .child(column().gap_1p5().child(label("Invitation")).child(Input::new(&self.invitation)))
                .child(actions().child(self.action("continue", "Continue", |this, cx| Operation::Preview(this.invitation.read(cx).value().to_string()), cx))),
            Screen::Review(preview) => {
                if self.folders.is_empty() {
                    self.folders = preview.folders.iter().map(|folder| cx.new(|cx| InputState::new(window, cx).default_value(folder.to_string_lossy().into_owned()))).collect();
                }
                let matches = preview.company.matches_invitation;
                let key_color = rgb(if matches { 0x2e7d4f } else { BAD });
                let shown = if self.all_controls { usize::MAX } else { 5 };
                let mut checks = table();
                for control in preview.controls.iter().take(shown) {
                    checks = checks.child(row(control.title.clone(), control.requirement.clone()));
                }
                if preview.controls.len() > 5 && !self.all_controls {
                    checks = checks.child(row(note(format!("and {} more", preview.controls.len() - 5)), ghost("show-all", "Show all").on_click(cx.listener(|this, _, _, cx| { this.all_controls = true; cx.notify(); }))));
                }
                let mut view = column().gap(px(14.)).child(title(format!("{} asks to check this device", preview.company.name)))
                    .child(div().flex().flex_wrap().items_center().gap_2().text_size(px(13.)).text_color(key_color)
                        .child(div().font_weight(FontWeight::BOLD).child(if matches { "✓" } else { "!" }))
                        .child("Company key")
                        .child(div().px(px(7.)).py(px(2.)).rounded(px(5.)).bg(rgb(if matches { 0xe5f2ea } else { BAD_WASH })).font_family(mono()).text_size(px(12.)).child(preview.company.key_fingerprint.clone()))
                        .child(if matches { "matches your invitation" } else { "does not match your invitation" }))
                    .child(checks)
                    .child(note(format!("Sent to the company: {}.", preview.disclosed_metadata.join(", "))));
                if !self.folders.is_empty() {
                    view = view.child(column().gap_1p5().child(label("Folders to scan")).children(self.folders.iter().map(Input::new)));
                }
                view.child(column().gap_1()
                        .child(Checkbox::new("automatic").label("Send results automatically").checked(self.automatic).disabled(preview.schedule.is_none() || self.busy)
                            .on_click(cx.listener(|this, checked: &bool, _, cx| { this.automatic = *checked; cx.notify(); })))
                        .child(note(preview.schedule.as_ref().map(schedule_text).unwrap_or_else(|| "No automatic sending schedule.".into())).pl(px(26.))))
                    .child(actions()
                        .child(Button::new("cancel").label("Cancel").disabled(self.busy).on_click(cx.listener(|this, _, _, cx| { this.screen = Screen::Invitation; cx.notify(); })))
                        .child(self.action("join", "Sign and join", |this, cx| Operation::Join(this.invitation.read(cx).value().to_string(), this.folders.iter().map(|p| p.read(cx).value().to_string()).collect(), this.automatic), cx).disabled(self.busy || !matches)))
            }
            Screen::NeedsAdmin => column().gap(px(14.))
                .child(title("Administrator rights are needed"))
                .child(div().text_color(rgb(INK_2)).child("Joining a Windows computer needs administrator rights, so that the device key goes into the TPM and the scheduled job runs as SYSTEM. Nothing was sent. Restart the app as administrator, then paste the invitation again."))
                .child(actions()
                    .child(Button::new("back").label("Cancel").disabled(self.busy).on_click(cx.listener(|this, _, _, cx| { this.error = None; this.screen = Screen::Invitation; cx.notify(); })))
                    .child(self.action("restart-admin", "Restart as administrator", |_, _| Operation::Restart, cx))),
            Screen::Joining(events) => column().gap(px(14.)).child(title("Joining your company"))
                .child(column().gap_4().children(events.iter().map(step_view)))
                .child(note("Closing the window is safe. Reopen it to check saved status."))
                .child(actions().child(self.action("reload", "Refresh status", |_, _| Operation::Status, cx))),
            Screen::Status(status) => {
                if status.approval.state == Some(DeviceStatus::Revoked) {
                    return column().child(verdict(Tone::Bad, "IT removed this device", "Ask IT if this is a mistake."));
                }
                let head = headline(&status);
                let mut view = column().child(verdict(head.tone, head.heading, head.detail));
                if let Some(cli) = &status.update {
                    let (text, command) = update::cli_notice(&cli.latest, cli.command);
                    let command = command.map(str::to_owned);
                    view = view.child(div().flex().items_start().gap_4().py(px(10.)).border_b_1().border_color(rgb(RULE_2))
                        .child(div().flex().flex_col().flex_1().min_w_0().gap_1()
                            .child(div().font_weight(FontWeight::SEMIBOLD).child(text))
                            .when_some(command.clone(), |item, command| item.child(runs("runs", command))))
                        .when_some(command, |row, command| row.child(div().flex_none().child(
                            Button::new("cli-update").label("Update").small().disabled(self.busy)
                                .on_click(cx.listener(move |this, _, _, cx| this.run(Operation::UpdateCli(command.clone()), cx)))))));
                }
                if !status.issues.is_empty() {
                    view = view.child(div().flex().flex_col().children(status.issues.iter().enumerate().map(|(i, issue)| {
                        let shown = issue_view_local(issue, self.clock.as_deref());
                        let button = shown.action.map(|action| {
                            Button::new(("issue-action", i)).label(action.label()).small().disabled(self.busy)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    let operation = match action {
                                        IssueAction::InstallJob => Operation::Schedule(true),
                                        IssueAction::TurnOffJob => Operation::Schedule(false),
                                        IssueAction::Retry => Operation::Status,
                                        IssueAction::Review => Operation::Changes,
                                    };
                                    this.run(operation, cx);
                                }))
                        });
                        div().flex().items_start().gap_4().py(px(10.)).border_b_1().border_color(rgb(RULE_2))
                            .child(div().flex().flex_col().flex_1().min_w_0().gap_0p5()
                                .child(div().font_weight(FontWeight::SEMIBOLD).child(shown.title))
                                .when_some(shown.fix, |item, fix| item.child(div().text_size(px(14.)).text_color(rgb(INK_2)).child(fix)))
                                .when_some(shown.note, |item, text| item.child(note(text))))
                            .when_some(button, |row, button| row.child(div().flex_none().child(button)))
                    })));
                }
                let consented = status.schedule.owner_consented == Some(true);
                let last_result = status.last_claim.as_ref().map(|claim| format!("{} · {}", readable_local(&claim.response_at), claim.response)).unwrap_or_else(|| "None saved yet".into());
                let scheduled = status.schedule.last_scheduled_claim.as_ref().map(|claim| {
                    [Some(readable_local(&claim.answered_at)), claim.response.clone()].into_iter().flatten().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" · ")
                });
                let signed = status.manifest.as_ref().map(|m| m.signed.to_string());
                let agreement = status.manifest.as_ref().and_then(|m| agreement_text(&m.agreement));
                if let Some(check) = self.last_check.as_ref().filter(|check| !check.accepted) {
                    view = view.child(rejection_panel(check));
                }
                view = view
                    .child(actions().child(Button::new("checks").label(if self.all_controls { "Hide every check" } else { "Show every check" }).on_click(cx.listener(|this, _, _, cx| { this.all_controls = !this.all_controls; cx.notify(); })))
                        .child(self.action("check", "Check now", |_, _| Operation::Check, cx)))
                    .child(table()
                        .child(div().flex().items_center().justify_between().gap_4().py(px(9.)).border_b_1().border_color(rgb(RULE_2))
                            .child(div().flex_none().child("Send results automatically"))
                            .child(div().flex().items_center().justify_end().gap_3().min_w_0()
                                .child(div().min_w_0().text_right().text_color(rgb(INK_2)).child(status.schedule.policy.clone()))
                                .child(div().flex_none().child(Switch::new("schedule").checked(consented).disabled(self.busy).on_click(cx.listener(|this, checked: &bool, _, cx| this.run(Operation::Schedule(*checked), cx)))))))
                        .child(row("Last result", last_result.clone()))
                        .when_some(scheduled.filter(|text| !text.is_empty() && *text != last_result), |view, text| view.child(row("Last scheduled result", text)))
                        .child(row("Approval", approval_text(status.approval.state.map(approval_word), status.approval.live)))
                        .child(row("Scheduled job", {
                            let raw = status.schedule.job.clone();
                            div().flex().items_center().gap_3().child(job_text(&raw))
                                .when(job_needs_install(&raw) || (cfg!(windows) && self.system_job), |value| value.child(Button::new("install-job").label(if self.system_job { "Install job (administrator)" } else { "Install job" }).small().disabled(self.busy)
                                    .on_click(cx.listener(|this, _, _, cx| this.run(Operation::Schedule(true), cx)))))
                        }))
                        .child(row("What is checked", div().flex().flex_col().items_end().gap_1()
                            .child(div().flex().items_center().gap_2().child("Signed by you").when_some(signed, |line, hash| line.child(hash_chip(&hash))))
                            .when_some(agreement, |col, text| col.child(note(text))))));
                if self.all_controls {
                    view = view.child(label("Every check"));
                    let mut every = table();
                    if let Some(check) = &self.last_check {
                        for control in &check.controls {
                            let (name, value, ok) = result_control(control);
                            every = every.child(row(name, div().text_color(rgb(if ok { 0x2e7d4f } else { BAD })).child(value)));
                        }
                    } else if let Some(claim) = status.last_claim.as_ref() {
                        for (id, value) in &claim.results { every = every.child(row(humanize(id), value.to_string())); }
                    }
                    view = view.child(every);
                    for limitation in &status.limitations { view = view.child(note(limitation.clone())); }
                }
                view.child(div().flex().gap_1()
                        .child(self.button("refresh", "Refresh status", |_, _| Operation::Status, false, cx).ghost().small())
                        .child(self.button("changes", "Review changes", |_, _| Operation::Changes, false, cx).ghost().small()))
            }
            Screen::Changed(changes) => {
                let mut list = table();
                for change in &changes.changes {
                    let before = change.before.clone().unwrap_or_default();
                    list = list.child(row(change.id.clone(), div().flex().gap_2()
                        .child(duration_text(change.after.as_deref().unwrap_or("removed")))
                        .child(div().text_color(rgb(MUTED)).child(if before.is_empty() { "new".to_owned() } else { format!("was {}", duration_text(&before)) }))));
                }
                column().child(verdict(Tone::Info, "Your company changed what is checked", "Review and sign the new list to keep sending results."))
                    .child(list)
                    .when(changes.schedule_widened, |view| view.child(note("Signing turns automatic sending off until you turn it on again, because the schedule widened.")))
                    .child(actions().child(self.button("later", "Later", |_, _| Operation::Status, false, cx)).child(self.action("accept", "Review and sign", |_, _| Operation::Accept, cx)))
            }
        }
    }
}

/// The reasons the company gave for not accepting the last check: a headline, then one row per
/// reason with its measured value, its requirement, and its grace.
fn rejection_panel(check: &ClaimReport) -> Div {
    let sent = runner::text::readable_local(&check.sent_at);
    let rows = check.reasons.iter().map(|reason| {
        let row = runner::rejection::reason_row(
            reason,
            open_pact_core::timestamp::parse_rfc3339(&check.sent_at),
            runner::zone::to_local,
        );
        let readable = row.detail.is_some();
        div()
            .flex()
            .items_start()
            .gap_3()
            .px_4()
            .py(px(10.))
            .border_t_1()
            .border_color(rgb(RULE_2))
            .child(
                div()
                    .flex_none()
                    .w(px(12.))
                    .mt(px(7.))
                    .flex()
                    .justify_center()
                    .child(dot(BAD).size(px(8.))),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(
                        div()
                            .when(readable, |name| name.font_weight(FontWeight::SEMIBOLD))
                            .when(!readable, |name| {
                                name.text_size(px(14.)).text_color(rgb(INK_2))
                            })
                            .child(row.name),
                    )
                    .when_some(row.detail, |item, detail| {
                        item.child(
                            div()
                                .text_size(px(14.))
                                .text_color(rgb(INK_2))
                                .child(detail),
                        )
                    }),
            )
            .when_some(row.grace, |line, grace| {
                let tone = match grace {
                    runner::rejection::GraceState::Ended => Tone::Bad,
                    runner::rejection::GraceState::EndsAt(_) => Tone::Warn,
                };
                line.child(pill(grace.text(), tone).flex_none())
            })
    });
    div()
        .flex()
        .flex_col()
        .rounded(px(10.))
        .border_1()
        .border_color(rgb(RULE))
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .px_4()
                .py_3()
                .child(dot(BAD))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .child(
                            div()
                                .text_size(px(16.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .child("The company did not accept the last check"),
                        )
                        .child(note(if check.reasons.is_empty() {
                            format!("Sent {sent}. The company gave no reason. Tell IT.")
                        } else {
                            format!("Sent {sent}. Fix these, then press Check now.")
                        })),
                ),
        )
        .children(rows)
}

fn step_view(event: &JoinStep) -> Div {
    let done = event.state == StepState::Done;
    let text = event.title.clone();
    let detail = step_detail(event.detail.as_ref());
    let icon = if done {
        div()
            .size(px(18.))
            .flex_none()
            .mt(px(2.))
            .rounded_full()
            .bg(rgb(0x2e7d4f))
            .flex()
            .items_center()
            .justify_center()
            .text_color(rgb(0xffffff))
            .text_size(px(11.))
            .font_weight(FontWeight::BOLD)
            .child("✓")
    } else {
        div()
            .size(px(18.))
            .flex_none()
            .mt(px(2.))
            .rounded_full()
            .border_2()
            .border_color(rgb(BLUE))
    };
    div().flex().gap_3().items_start().child(icon).child(
        column()
            .gap_0p5()
            .child(div().font_weight(FontWeight::SEMIBOLD).child(text))
            .when(!detail.is_empty(), |view| view.child(note(detail))),
    )
}

fn schedule_text(schedule: &Schedule) -> String {
    let line = schedule.to_string();
    let line = line.strip_prefix("Automatic claims: ").unwrap_or(&line);
    let mut letters = line.chars();
    let first = letters
        .next()
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_default();
    format!(
        "{first}{}. You can turn it off later.",
        letters.as_str().trim_end_matches('.')
    )
}

/// The device status with the online parts, as the status screen shows it.
async fn status_of(session: &Session) -> Result<Report, String> {
    session.status(true).await.map_err(|e| format!("{e:#}"))
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = self.content(window, cx);
        // One readable column, centred, so a wide or full-screen window does not stretch lines.
        let mut page = column().w_full().max_w(px(960.)).gap_4();
        if let Some(copies) = self.copies_view(cx) {
            page = page.child(copies);
        }
        page = page.child(content);
        if self.busy {
            let waiting = self.steps.iter().any(|step| step.title == WAITING_FOR_JOB);
            page = page.child(note(if waiting {
                "Waiting for the scheduled job…"
            } else {
                "Working…"
            }));
        }
        if let Some(error) = &self.error {
            page = page.child(banner(error.clone(), BAD, BAD_WASH));
        }
        let banner = update_banner(
            &self.update,
            cx.listener(|this, _, _, cx| {
                let runner = this.runner.clone();
                start_update(&mut this.update, cx, runner, |view| &mut view.update);
            }),
        );
        let page = div()
            .id("client")
            .flex()
            .flex_col()
            .items_center()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_7()
            .child(page);
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .children(banner)
            .child(page)
            .child(terminal_drawer_with(
                self.terminal,
                || operations(&self.engine.log, &self.runner),
                cx.listener(|this, _, _, cx| {
                    this.terminal = !this.terminal;
                    cx.notify();
                }),
            ))
    }
}

fn main() {
    runner::zone::read_start_offset();
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    if let Some(output) = std::env::var_os("OPEN_PACT_SHOTS") {
        snapshots(PathBuf::from(output));
        return;
    }
    runner::tool_path();
    let runner = Runner::default();
    let engine = Engine::start().expect("the background runtime");
    let bundled = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|path| client::bundled_path(&path))
        .unwrap_or_else(|_| PathBuf::from(client::cli_name()));
    // The OS job runs the installed copy, never a copy on PATH.
    let installed = client::installed_path().unwrap_or_else(|_| bundled.clone());
    launch("open-pact", 520., 680., move |window, cx| {
        cx.new(|cx| {
            let mut app = AppView::new(
                Screen::Install,
                engine,
                runner,
                bundled,
                installed,
                window,
                cx,
            );
            app.run(Operation::Open, cx);
            let runner = app.runner.clone();
            watch_updates(cx, runner, |view: &mut AppView| &mut view.update);
            app
        })
    });
}

#[cfg(all(feature = "snapshot", target_os = "macos"))]
fn snapshots(output: PathBuf) {
    use runner::samples;
    let step = |step: u8, title: &str, state: StepState| JoinStep {
        step,
        title: title.into(),
        state,
        detail: None,
    };
    let mut revoked = samples::report(open_pact_client::status::Verdict::ActionNeeded, 2);
    revoked.approval.state = Some(DeviceStatus::Revoked);
    let status = || samples::report(open_pact_client::status::Verdict::ActionNeeded, 2);
    let copy = OtherCopy::new(
        "/opt/fictional/bin/open-pact-client".into(),
        ownership::Source::Homebrew,
    );
    for (name, screen) in [
        ("client-0-install", Screen::Install),
        ("client-1-invitation", Screen::Invitation),
        (
            "client-2-review",
            Screen::Review(Arc::new(samples::preview())),
        ),
        (
            "client-3-joining",
            Screen::Joining(vec![
                step(1, "Signed and enrolled", StepState::Done),
                step(5, "Approved", StepState::Done),
                step(6, "Running the first check", StepState::Started),
            ]),
        ),
        ("client-3-needs-admin", Screen::NeedsAdmin),
        ("client-4-action", Screen::Status(Arc::new(status()))),
        (
            "client-5-good",
            Screen::Status(Arc::new(samples::report_good())),
        ),
        (
            "client-6-changed",
            Screen::Changed(Arc::new(samples::changes())),
        ),
        ("client-7-revoked", Screen::Status(Arc::new(revoked))),
        ("client-8-denied", Screen::Status(Arc::new(status()))),
        ("client-8-denied-1512", Screen::Status(Arc::new(status()))),
        ("client-8-denied-2560", Screen::Status(Arc::new(status()))),
        (
            "client-9-actions",
            Screen::Status(Arc::new(samples::report_needs_action())),
        ),
        (
            "client-9-actions-2560",
            Screen::Status(Arc::new(samples::report_needs_action())),
        ),
        (
            "client-a-vpn-only",
            Screen::Status(Arc::new(samples::report_vpn_only())),
        ),
        (
            "client-b-update",
            Screen::Status(Arc::new(samples::report_with_update(Some(
                "brew upgrade open-pact-client",
            )))),
        ),
        (
            "client-c-update-bundled",
            Screen::Status(Arc::new(samples::report_with_update(None))),
        ),
        ("client-d-other-copy", Screen::Status(Arc::new(status()))),
        ("client-e-waiting", Screen::Status(Arc::new(status()))),
        ("client-f-operations", Screen::Status(Arc::new(status()))),
    ] {
        let (width, height) = match name {
            "client-9-actions" | "client-a-vpn-only" => (1100., 980.),
            _ if name.ends_with("-1512") => (1512., 982.),
            _ if name.ends_with("-2560") => (2560., 1440.),
            _ => (520., 740.),
        };
        snapshot(&output, name, width, height, |window, cx| {
            cx.new(|cx| {
                    let mut app = AppView::new(
                        screen,
                        Engine::start().expect("the background runtime"),
                        Runner::default(),
                        "open-pact-client".into(),
                        "open-pact-client".into(),
                        window,
                        cx,
                    );
                    app.clock = Some("2026-11-16T15:00:00Z".into());
                    if name.starts_with("client-b") || name.starts_with("client-c") {
                        app.update = UpdateState::Available("0.1.1".into());
                    }
                    if name.starts_with("client-8-denied") {
                        app.last_check = Some(samples::denied_check());
                        app.all_controls = true;
                    }
                    if name == "client-d-other-copy" {
                        app.others = vec![copy.clone()];
                    }
                    if name == "client-f-operations" {
                        app.terminal = true;
                        let log = &app.engine.log;
                        log.record("Open", Ok("action needed, other copies of the command line tool: 1".into()));
                        log.record(
                            "Move the scheduled job to the installed command line tool",
                            Ok("/opt/fictional/bin/open-pact-client -> /Users/fictional/.local/bin/open-pact-client".into()),
                        );
                        log.record("Check", Err("The gateway did not answer.".into()));
                        log.begin("Status");
                    }
                    if name == "client-e-waiting" {
                        app.busy = true;
                        app.steps = vec![step(0, WAITING_FOR_JOB, StepState::Waiting)];
                    }
                    app
                })
        });
    }
}
