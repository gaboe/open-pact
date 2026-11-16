use gpui::{prelude::*, *};
use gpui_component::{
    Disableable,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
};
use runner::{
    Runner,
    client::{self, Changes, Check, Client, JoinEvent, Preview, Screen, Status},
    desktop::*,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

enum Operation {
    Open,
    Install,
    Preview(String),
    Join(String, Vec<String>, bool),
    Status,
    Check,
    Changes,
    Accept,
    Schedule(bool),
}

enum Outcome {
    Open(Option<PathBuf>, Option<Status>),
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
    busy: bool,
    error: Option<String>,
    terminal: bool,
    all_controls: bool,
    last_check: Option<Check>,
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
            busy: false,
            error: None,
            terminal: false,
            all_controls: false,
            last_check: None,
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
                        Operation::Install => {
                            let path = client::installed_path()?;
                            client::install(&client.runner, &bundled, &path)?;
                            client.executable = path.clone();
                            Ok(Outcome::Open(Some(path), Some(client.status()?)))
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
                        this.screen = status.map(Self::status_screen).unwrap_or(Screen::Install);
                    }
                    Ok(Outcome::Preview(preview)) => {
                        this.automatic = false;
                        this.folders.clear();
                        this.screen = Screen::Review(preview);
                    }
                    Ok(Outcome::Status(status)) => this.screen = Self::status_screen(status),
                    Ok(Outcome::Check(check, status)) => {
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

    fn action(
        &self,
        id: &'static str,
        label: &'static str,
        operation: impl Fn(&Self, &App) -> Operation + 'static,
        cx: &Context<Self>,
    ) -> Button {
        Button::new(id)
            .label(label)
            .primary()
            .disabled(self.busy)
            .on_click(cx.listener(move |this, _, _, cx| {
                let operation = operation(this, cx);
                this.run(operation, cx);
            }))
    }

    fn content(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        match self.screen.clone() {
            Screen::Install => column()
                .child(title("Set up open-pact on this computer"))
                .child("open-pact does its work with a small command line tool that comes with this app. It goes to a fixed place so the scheduled check keeps working when you move or update the app.")
                .child(row("Command line tool", client::installed_path().map(|p| p.display().to_string()).unwrap_or_default()))
                .child(row("Version", "Bundled command line tool"))
                .child(note("The installed tool can also be used in Terminal. Add its folder to your PATH if you want to use it there."))
                .child(self.action("install", "Install and continue", |_, _| Operation::Install, cx))
                .child(note("copies the bundled tool, then runs open-pact-client --version")),
            Screen::Invitation => column()
                .child(title("Join your company"))
                .child("Paste the invitation line that IT sent you. It starts with opi1: and works once, for 72 hours.")
                .child("Invitation")
                .child(Input::new(&self.invitation))
                .child(self.action("continue", "Continue", |this, cx| Operation::Preview(this.invitation.read(cx).value().to_string()), cx))
                .child(note("runs open-pact-client join --preview 'opi1:…'")),
            Screen::Review(preview) => {
                if self.folders.is_empty() {
                    self.folders = preview.folders.iter().map(|folder| cx.new(|cx| InputState::new(window, cx).default_value(folder.clone()))).collect();
                }
                let mut view = column().child(title(format!("{} asks to check this device", preview.company.name)))
                    .child(banner(format!("Company key {} {}", preview.company.key_fingerprint, if preview.company.matches_invitation { "matches your invitation" } else { "does not match your invitation" }), if preview.company.matches_invitation { 0x2e7d4f } else { 0xb3261e }, if preview.company.matches_invitation { 0xe5f2ea } else { 0xfbe6e4 }));
                for control in preview.controls.iter().take(if self.all_controls { usize::MAX } else { 5 }) {
                    view = view.child(row(control.title.clone(), display(&control.requirement)));
                }
                if preview.controls.len() > 5 {
                    view = view.child(Button::new("show-all").label("Show all").on_click(cx.listener(|this, _, _, cx| { this.all_controls = true; cx.notify(); })));
                }
                view = view.child(note(format!("Sent to the company: {}", preview.disclosed_metadata.iter().map(display).collect::<Vec<_>>().join(", "))));
                for folder in &self.folders { view = view.child(Input::new(folder)); }
                view = view.child(Button::new("automatic").label(if self.automatic { "☑ Send results automatically" } else { "☐ Send results automatically" })
                    .disabled(preview.schedule.is_none() || self.busy)
                    .on_click(cx.listener(|this, _, _, cx| { this.automatic = !this.automatic; cx.notify(); })))
                    .child(note(preview.schedule.as_ref().map(display).unwrap_or_else(|| "No automatic sending schedule.".into())))
                    .child(Button::new("cancel").label("Cancel").disabled(self.busy).on_click(cx.listener(|this, _, _, cx| { this.screen = Screen::Invitation; cx.notify(); })))
                    .child(self.action("join", "Sign and join", |this, cx| Operation::Join(this.invitation.read(cx).value().to_string(), this.folders.iter().map(|p| p.read(cx).value().to_string()).collect(), this.automatic), cx).disabled(self.busy || !preview.company.matches_invitation))
                    .child(note("runs open-pact-client join --yes --json --auto-send on|off 'opi1:…'"));
                view
            }
            Screen::Joining(events) => column().child(title("Joining your company"))
                .children(events.iter().map(|event| match event {
                    JoinEvent::Step { step, title, state, detail } => column().gap_1().child(format!("{step}. {title} · {state}")).child(note(detail.as_ref().map(display).unwrap_or_default())),
                    JoinEvent::Result { result, device, .. } => column().child(format!("{result} · {device}")),
                }))
                .child(note("Closing the window is safe. Reopen it to check saved status."))
                .child(self.action("reload", "Refresh status", |_, _| Operation::Status, cx)),
            Screen::Status(status) => {
                let revoked = status.approval.state.as_deref() == Some("revoked");
                let heading = if revoked { "IT removed this device. Ask IT if this is a mistake." }
                    else { match status.verdict.as_str() { "no_known_problem" => "All good", "action_needed" => "Action needed", "alarm" => "Keep the last checkpoint and tell IT.", _ => "Current status is unknown" } };
                let mut view = column().child(banner(heading, if status.verdict == "no_known_problem" { 0x2e7d4f } else { 0x9a5b0c }, if status.verdict == "no_known_problem" { 0xe5f2ea } else { 0xfbeedc }));
                for issue in &status.issues {
                    view = view.child(column().gap_1().child(issue.message.clone()).child(note(issue.fix.clone().unwrap_or_default())).child(note(issue.deadline.clone())));
                }
                view = view.child(note(status.current_compliance.clone()))
                    .child(row("Approval", format!("{} · {}", status.approval.state.as_deref().unwrap_or("unknown"), status.approval.source)))
                    .child(row("Last result", status.last_claim.as_ref().map(|v| format!("{} · {}", display(&v["response_at"]), display(&v["response"]))).unwrap_or_else(|| "No saved result".into())))
                    .child(row("Send results automatically", display(&status.schedule["policy"])))
                    .child(row("Scheduled job", display(&status.schedule["job"])))
                    .child(row("What is checked", status.manifest.as_ref().map(|v| display(&v["signed"])).unwrap_or_else(|| "Unknown".into())))
                    .child(self.action("schedule", if status.schedule["owner_consented"] == true { "Turn automatic sending off" } else { "Turn automatic sending on" }, |this, _| {
                        let enabled = matches!(&this.screen, Screen::Status(s) if s.schedule["owner_consented"] == true);
                        Operation::Schedule(!enabled)
                    }, cx))
                    .child(self.action("check", "Check now", |_, _| Operation::Check, cx))
                    .child(self.action("refresh", "Refresh status", |_, _| Operation::Status, cx))
                    .child(self.action("changes", "Review changes", |_, _| Operation::Changes, cx))
                    .child(Button::new("checks").label("Show every check").on_click(cx.listener(|this, _, _, cx| { this.all_controls = !this.all_controls; cx.notify(); })));
                if self.all_controls {
                    if let Some(check) = &self.last_check {
                        for control in &check.controls { view = view.child(note(display(control))); }
                    } else if let Some(claim) = &status.last_claim { view = view.child(note(display(&claim["results"]))); }
                    for limitation in &status.limitations { view = view.child(note(limitation.clone())); }
                }
                view.child(note("opening runs open-pact-client status --json; Check now runs open-pact-client check --json"))
            }
            Screen::Changed(changes) => {
                let mut view = column().child(banner("Your company changed what is checked", BLUE, 0xe9eef8))
                    .child("Review and sign the new list to keep sending results.");
                for change in &changes.changes { view = view.child(row(display(&change["id"]), format!("{} → {}", display(&change["before"]), display(&change["after"])))); }
                if changes.schedule_widened { view = view.child(note("Signing turns automatic sending off until you turn it on again, because the schedule widened.")); }
                view.child(self.action("later", "Later", |_, _| Operation::Status, cx))
                    .child(self.action("accept", "Review and sign", |_, _| Operation::Accept, cx))
                    .child(note("runs open-pact-client accept --yes"))
            }
        }
    }
}

fn display(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = self.content(window, cx);
        let mut view = column()
            .id("client")
            .size_full()
            .overflow_y_scroll()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .p_7()
            .child(content);
        if self.busy {
            view = view.child(note("Working…"));
        }
        if let Some(error) = &self.error {
            view = view.child(banner(error.clone(), 0xb3261e, 0xfbe6e4));
        }
        view = view.child(
            Button::new("terminal")
                .label(if self.terminal {
                    "Terminal · hide"
                } else {
                    "Terminal · show"
                })
                .on_click(cx.listener(|this, _, _, cx| {
                    this.terminal = !this.terminal;
                    cx.notify();
                })),
        );
        if self.terminal {
            view = view.child(terminal(&self.client.runner));
        }
        view
    }
}

fn main() {
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    if let Some(output) = std::env::var_os("OPEN_PACT_SHOTS") {
        snapshots(PathBuf::from(output));
        return;
    }
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
    ] {
        snapshot(&output, name, 520., 740., |window, cx| {
            cx.new(|cx| {
                AppView::new(
                    screen,
                    Client {
                        runner: Runner::default(),
                        executable: "open-pact-client".into(),
                    },
                    "open-pact-client".into(),
                    window,
                    cx,
                )
            })
        });
    }
}
