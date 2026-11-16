#![cfg_attr(windows, windows_subsystem = "windows")]

use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputState},
    switch::Switch,
};
use runner::{
    Runner,
    client::{self, Changes, Check, Client, JoinEvent, Preview, Screen, Status},
    desktop::*,
    text::*,
    update::{self, Platform, UpdateState},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

enum Operation {
    Open,
    Install(bool),
    Preview(String),
    Join(String, Vec<String>, bool),
    Status,
    Check,
    Changes,
    Accept,
    Schedule(bool),
    UpdateCli(String),
}

enum Outcome {
    Open(Option<PathBuf>, Option<Status>),
    Installed(PathBuf, Status, Option<String>),
    Preview(Preview),
    Status(Status),
    Check(Check, Status),
    Changes(Changes),
}

struct AppView {
    client: Client,
    bundled: PathBuf,
    screen: Screen,
    invitation: Entity<InputState>,
    folders: Vec<Entity<InputState>>,
    automatic: bool,
    also_terminal: bool,
    busy: bool,
    error: Option<String>,
    terminal: bool,
    all_controls: bool,
    last_check: Option<Check>,
    /// Fixtures set this RFC 3339 time. The app uses the real clock.
    clock: Option<String>,
    update: UpdateState,
}

impl AppView {
    fn new(
        screen: Screen,
        client: Client,
        bundled: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        Self {
            client,
            bundled,
            screen,
            invitation: cx.new(|cx| InputState::new(window, cx).placeholder("opi1:…")),
            folders: Vec::new(),
            automatic: false,
            also_terminal: true,
            busy: false,
            error: None,
            terminal: false,
            all_controls: false,
            last_check: None,
            clock: None,
            update: UpdateState::None,
        }
    }

    fn run(&mut self, operation: Operation, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        let mut client = self.client.clone();
        let bundled = self.bundled.clone();
        let progress = Arc::new(Mutex::new(Vec::<JoinEvent>::new()));
        let incoming = progress.clone();
        if matches!(operation, Operation::Join(..)) {
            self.screen = Screen::Joining(Vec::new());
            cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(100))
                        .await;
                    let Ok(keep_running) = this.update(cx, |this, cx| {
                        if let Screen::Joining(events) = &mut this.screen {
                            *events = incoming.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        }
                        cx.notify();
                        this.busy
                    }) else {
                        break;
                    };
                    if !keep_running {
                        break;
                    }
                }
            })
            .detach();
        }
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    match operation {
                        Operation::Open => {
                            let path = client::resolve_cli(&client.runner, &bundled)?;
                            if let Some(path) = path {
                                client.executable = path.clone();
                                let status = client.status()?;
                                Ok(Outcome::Open(Some(path), Some(status)))
                            } else {
                                Ok(Outcome::Open(None, None))
                            }
                        }
                        Operation::Install(also_terminal) => {
                            let path = client::installed_path()?;
                            client::install(&client.runner, &bundled, &path)?;
                            let warning = if also_terminal {
                                client::enable_terminal(&path).err().map(|error| {
                                    format!(
                                        "The tool is installed, but Terminal setup failed: {error}. Add {} to your PATH by hand.",
                                        path.parent().map(|p| p.display().to_string()).unwrap_or_default()
                                    )
                                })
                            } else {
                                None
                            };
                            client.executable = path.clone();
                            Ok(Outcome::Installed(path, client.status()?, warning))
                        }
                        Operation::Preview(inv) => client.preview(&inv).map(Outcome::Preview),
                        Operation::Join(inv, folders, auto) => {
                            client.join(&inv, &folders, auto, |event| {
                                progress
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .push(event)
                            })?;
                            client.status().map(Outcome::Status)
                        }
                        Operation::Status => client.status().map(Outcome::Status),
                        Operation::Check => {
                            let check = client.check()?;
                            Ok(Outcome::Check(check, client.status()?))
                        }
                        Operation::Changes => client.changes().map(Outcome::Changes),
                        Operation::Accept => {
                            client.accept()?;
                            client.status().map(Outcome::Status)
                        }
                        Operation::Schedule(enabled) => {
                            client.schedule(enabled)?;
                            client.status().map(Outcome::Status)
                        }
                        Operation::UpdateCli(line) => {
                            let call = update::shell_invocation(Platform::current(), &line);
                            update::run(&client.runner, &call)?;
                            client.status().map(Outcome::Status)
                        }
                    }
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(Outcome::Open(path, status)) => {
                        if let Some(path) = path {
                            this.client.executable = path;
                        }
                        let resume = status.as_ref().and_then(client::resume_join);
                        this.screen = status.map(Self::status_screen).unwrap_or(Screen::Install);
                        if let Some(automatic) = resume {
                            this.run(Operation::Join(String::new(), Vec::new(), automatic), cx);
                        }
                    }
                    Ok(Outcome::Installed(path, status, warning)) => {
                        this.client.executable = path;
                        this.screen = Self::status_screen(status);
                        this.error = warning;
                    }
                    Ok(Outcome::Preview(preview)) => {
                        this.automatic = false;
                        this.folders.clear();
                        this.screen = Screen::Review(preview);
                    }
                    Ok(Outcome::Status(status)) => this.screen = Self::status_screen(status),
                    Ok(Outcome::Check(check, status)) => {
                        // A denied claim is a result, not a failure: show which checks failed.
                        if !check.accepted {
                            this.all_controls = true;
                        }
                        this.last_check = Some(check);
                        this.screen = Self::status_screen(status);
                    }
                    Ok(Outcome::Changes(changes)) => this.screen = Screen::Changed(changes),
                    Err(error) => this.error = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn status_screen(status: Status) -> Screen {
        if status.approval.state.is_none() && status.manifest.is_none() {
            Screen::Invitation
        } else {
            Screen::Status(Box::new(status))
        }
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
                    .client
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
                    .child(div().text_color(rgb(INK_2)).child("open-pact does its work with a small command line tool that comes with this app. It goes to a fixed place so the scheduled check keeps working when you move or update the app."))
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
                .child(actions().child(self.action("continue", "Continue", |this, cx| Operation::Preview(this.invitation.read(cx).value().to_string()), cx)))
                .child(runs("runs", "open-pact-client join --preview -- 'opi1:…'")),
            Screen::Review(preview) => {
                if self.folders.is_empty() {
                    self.folders = preview.folders.iter().map(|folder| cx.new(|cx| InputState::new(window, cx).default_value(folder.clone()))).collect();
                }
                let matches = preview.company.matches_invitation;
                let key_color = rgb(if matches { 0x2e7d4f } else { BAD });
                let shown = if self.all_controls { usize::MAX } else { 5 };
                let mut checks = table();
                for control in preview.controls.iter().take(shown) {
                    checks = checks.child(row(control.title.clone(), plain_value(&control.requirement)));
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
                    .child(note(format!("Sent to the company: {}.", preview.disclosed_metadata.iter().map(plain_value).collect::<Vec<_>>().join(", "))));
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
                    .child(runs("runs", "open-pact-client join --yes --json --auto-send on|off -- 'opi1:…'"))
            }
            Screen::Joining(events) => column().gap(px(14.)).child(title("Joining your company"))
                .child(column().gap_4().children(events.iter().map(step_view)))
                .child(note("Closing the window is safe. Reopen it to check saved status."))
                .child(actions().child(self.action("reload", "Refresh status", |_, _| Operation::Status, cx))),
            Screen::Status(status) => {
                if status.approval.state.as_deref() == Some("revoked") {
                    return column().child(verdict(Tone::Bad, "IT removed this device", "Ask IT if this is a mistake."));
                }
                let head = headline(&status);
                let installable = job_needs_install(&plain_value(&status.schedule["job"]))
                    || status.issues.iter().any(|issue| issue_action(issue) == Some(IssueAction::InstallJob));
                let mut view = column().child(verdict(head.tone, head.heading, head.detail));
                if let Some(cli) = &status.update {
                    let (text, command) = update::cli_notice(cli);
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
                let consented = status.schedule["owner_consented"] == true;
                let last_result = status.last_claim.as_ref().map(|claim| format!("{} · {}", readable_local(&plain_value(&claim["response_at"])), plain_value(&claim["response"]))).unwrap_or_else(|| "None saved yet".into());
                let scheduled = status.schedule["last_scheduled_claim"].as_object().map(|claim| {
                    [claim.get("answered_at").map(|v| readable_local(&plain_value(v))), claim.get("response").map(plain_value)].into_iter().flatten().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" · ")
                });
                let signed = status.manifest.as_ref().map(|m| plain_value(&m["signed"]));
                let agreement = status.manifest.as_ref().and_then(|m| agreement_text(&plain_value(&m["agreement"])));
                if let Some(check) = self.last_check.as_ref().filter(|check| !check.accepted) {
                    let reasons = if check.reasons.is_empty() {
                        "The company did not accept the last check.".to_owned()
                    } else {
                        format!("The company did not accept the last check: {}", check.reasons.join("; "))
                    };
                    view = view.child(banner(reasons, BAD, BAD_WASH));
                }
                view = view
                    .child(actions().child(Button::new("checks").label(if self.all_controls { "Hide every check" } else { "Show every check" }).on_click(cx.listener(|this, _, _, cx| { this.all_controls = !this.all_controls; cx.notify(); })))
                        .child(self.action("check", "Check now", |_, _| Operation::Check, cx)))
                    .child(table()
                        .child(div().flex().items_center().justify_between().gap_4().py(px(9.)).border_b_1().border_color(rgb(RULE_2))
                            .child(div().flex_none().child("Send results automatically"))
                            .child(div().flex().items_center().justify_end().gap_3().min_w_0()
                                .child(div().min_w_0().text_right().text_color(rgb(INK_2)).child(plain_value(&status.schedule["policy"])))
                                .child(div().flex_none().child(Switch::new("schedule").checked(consented).disabled(self.busy).on_click(cx.listener(|this, checked: &bool, _, cx| this.run(Operation::Schedule(*checked), cx)))))))
                        .child(row("Last result", last_result.clone()))
                        .when_some(scheduled.filter(|text| !text.is_empty() && *text != last_result), |view, text| view.child(row("Last scheduled result", text)))
                        .child(row("Approval", approval_text(status.approval.state.as_deref(), status.approval.live)))
                        .child(row("Scheduled job", {
                            let raw = plain_value(&status.schedule["job"]);
                            div().flex().items_center().gap_3().child(job_text(&raw))
                                .when(job_needs_install(&raw), |value| value.child(Button::new("install-job").label("Install job").small().disabled(self.busy)
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
                    } else if let Some(results) = status.last_claim.as_ref().and_then(|claim| claim["results"].as_object()) {
                        for (id, value) in results { every = every.child(row(humanize(id), plain_value(value))); }
                    }
                    view = view.child(every);
                    for limitation in &status.limitations { view = view.child(note(limitation.clone())); }
                }
                view.child(div().flex().gap_1()
                        .child(self.button("refresh", "Refresh status", |_, _| Operation::Status, false, cx).ghost().small())
                        .child(self.button("changes", "Review changes", |_, _| Operation::Changes, false, cx).ghost().small()))
                    .child(column().gap_1().child(runs("opening runs", "open-pact-client status --online --json")).child(runs("Check now runs", "open-pact-client check --json"))
                        .when(installable, |view| view.child(runs("Install job runs", "open-pact-client schedule on"))))
                    .max_w(px(860.))
            }
            Screen::Changed(changes) => {
                let mut list = table();
                for change in &changes.changes {
                    let before = plain_value(&change["before"]);
                    list = list.child(row(plain_value(&change["id"]), div().flex().gap_2()
                        .child(duration_text(&plain_value(&change["after"])))
                        .child(div().text_color(rgb(MUTED)).child(if before.is_empty() { "new".to_owned() } else { format!("was {}", duration_text(&before)) }))));
                }
                column().child(verdict(Tone::Info, "Your company changed what is checked", "Review and sign the new list to keep sending results."))
                    .child(list)
                    .when(changes.schedule_widened, |view| view.child(note("Signing turns automatic sending off until you turn it on again, because the schedule widened.")))
                    .child(actions().child(self.button("later", "Later", |_, _| Operation::Status, false, cx)).child(self.action("accept", "Review and sign", |_, _| Operation::Accept, cx)))
                    .child(runs("runs", "open-pact-client accept --yes"))
            }
        }
    }
}

fn step_view(event: &JoinEvent) -> Div {
    let (done, text, detail) = match event {
        JoinEvent::Step {
            title,
            state,
            detail,
            ..
        } => (state == "done", title.clone(), step_detail(detail.as_ref())),
        JoinEvent::Result { result, .. } => (
            true,
            format!("Result sent: {}", plain_value(result)),
            String::new(),
        ),
    };
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

fn schedule_text(value: &serde_json::Value) -> String {
    let interval = value
        .get("interval")
        .or_else(|| value.get("every"))
        .map(|interval| duration_text(&plain_value(interval)))
        .unwrap_or_else(|| "the signed interval".into());
    if value["mode"] == "vpn" || value["policy"] == "vpn" {
        format!("Every {interval} while on the company VPN. You can turn it off later.")
    } else {
        format!("Every {interval}. You can turn it off later.")
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = self.content(window, cx);
        let mut page = column()
            .id("client")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .gap_4()
            .p_7()
            .child(content);
        if self.busy {
            page = page.child(note("Working…"));
        }
        if let Some(error) = &self.error {
            page = page.child(banner(error.clone(), BAD, BAD_WASH));
        }
        let banner = update_banner(
            &self.update,
            cx.listener(|this, _, _, cx| {
                let runner = this.client.runner.clone();
                start_update(&mut this.update, cx, runner, |view| &mut view.update);
            }),
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .children(banner)
            .child(page)
            .child(terminal_drawer(
                self.terminal,
                &self.client.runner,
                cx.listener(|this, _, _, cx| {
                    this.terminal = !this.terminal;
                    cx.notify();
                }),
            ))
    }
}

fn main() {
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    if let Some(output) = std::env::var_os("OPEN_PACT_SHOTS") {
        snapshots(PathBuf::from(output));
        return;
    }
    runner::tool_path();
    let runner = Runner::default();
    let bundled = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|path| client::bundled_path(&path))
        .unwrap_or_else(|_| PathBuf::from(client::cli_name()));
    launch("open-pact", 520., 680., move |window, cx| {
        cx.new(|cx| {
            let mut app = AppView::new(
                Screen::Install,
                Client {
                    runner,
                    executable: bundled.clone(),
                },
                bundled,
                window,
                cx,
            );
            app.run(Operation::Open, cx);
            let runner = app.client.runner.clone();
            watch_updates(cx, runner, |view: &mut AppView| &mut view.update);
            app
        })
    });
}

#[cfg(all(feature = "snapshot", target_os = "macos"))]
fn snapshots(output: PathBuf) {
    let preview: Preview =
        serde_json::from_str(include_str!("../../../tests/fixtures/preview.json")).unwrap();
    let status: Status =
        serde_json::from_str(include_str!("../../../tests/fixtures/status.json")).unwrap();
    let changes: Changes =
        serde_json::from_str(include_str!("../../../tests/fixtures/changes.json")).unwrap();
    let mut good = status.clone();
    good.verdict = "no_known_problem".into();
    good.issues.clear();
    let denied: Check =
        serde_json::from_str(include_str!("../../../tests/fixtures/check-denied.json")).unwrap();
    let denied_status = status.clone();
    let needs: Status = serde_json::from_str(include_str!(
        "../../../tests/fixtures/status-needs-action.json"
    ))
    .unwrap();
    let vpn_only: Status =
        serde_json::from_str(include_str!("../../../tests/fixtures/status-vpn-only.json")).unwrap();
    let cli_update: Status = serde_json::from_str(include_str!(
        "../../../tests/fixtures/status-cli-update.json"
    ))
    .unwrap();
    let cli_bundled: Status = serde_json::from_str(include_str!(
        "../../../tests/fixtures/status-cli-update-bundled.json"
    ))
    .unwrap();
    let mut revoked = status.clone();
    revoked.approval.state = Some("revoked".into());
    for (name, screen) in [
        ("client-0-install", Screen::Install),
        ("client-1-invitation", Screen::Invitation),
        ("client-2-review", Screen::Review(preview)),
        (
            "client-3-joining",
            Screen::Joining(vec![
                JoinEvent::Step {
                    step: 1,
                    title: "Signed and enrolled".into(),
                    state: "done".into(),
                    detail: None,
                },
                JoinEvent::Step {
                    step: 5,
                    title: "Approved".into(),
                    state: "done".into(),
                    detail: None,
                },
                JoinEvent::Step {
                    step: 6,
                    title: "Running the first check".into(),
                    state: "started".into(),
                    detail: None,
                },
            ]),
        ),
        ("client-4-action", Screen::Status(Box::new(status))),
        ("client-5-good", Screen::Status(Box::new(good))),
        ("client-6-changed", Screen::Changed(changes)),
        ("client-7-revoked", Screen::Status(Box::new(revoked))),
        ("client-8-denied", Screen::Status(Box::new(denied_status))),
        ("client-9-actions", Screen::Status(Box::new(needs))),
        ("client-a-vpn-only", Screen::Status(Box::new(vpn_only))),
        ("client-b-update", Screen::Status(Box::new(cli_update))),
        (
            "client-c-update-bundled",
            Screen::Status(Box::new(cli_bundled)),
        ),
    ] {
        let width = if matches!(name, "client-9-actions" | "client-a-vpn-only") {
            1100.
        } else {
            520.
        };
        snapshot(
            &output,
            name,
            width,
            if width > 600. { 980. } else { 740. },
            |window, cx| {
                cx.new(|cx| {
                    let mut app = AppView::new(
                        screen,
                        Client {
                            runner: Runner::default(),
                            executable: "open-pact-client".into(),
                        },
                        "open-pact-client".into(),
                        window,
                        cx,
                    );
                    app.clock = Some("2026-11-16T15:00:00Z".into());
                    if name.starts_with("client-b") || name.starts_with("client-c") {
                        app.update = UpdateState::Available("0.1.1".into());
                    }
                    if name == "client-8-denied" {
                        app.last_check = Some(denied.clone());
                        app.all_controls = true;
                    }
                    app
                })
            },
        );
    }
}
