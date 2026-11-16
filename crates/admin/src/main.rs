use gpui::{prelude::*, *};
use gpui_component::{
    Disableable,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
};
use runner::{
    Runner,
    admin::{self, Admin, Device, Gateway, History, Invitation, Restore, Settings},
    desktop::*,
    manifest::{self, Field, Kind},
};
#[cfg(all(feature = "snapshot", target_os = "macos"))]
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Setup,
    Overview,
    Manifest,
    Devices,
}

#[derive(Clone)]
enum Dialog {
    Apply,
    Restore(Restore, String),
    Revoke(Device),
    Approve(Device),
    Invitation(Option<Invitation>),
}

enum Operation {
    Setup(Settings),
    Refresh,
    Apply(String, String, String),
    Sync,
    PreviewRestore(Restore),
    Restore(Restore, String),
    Device(&'static str, String),
    Invite(String, String),
}

struct Overview {
    gateway: Gateway,
    devices: Vec<Device>,
    deployment: serde_json::Value,
}

enum Outcome {
    Setup(Settings, String, Overview, History),
    Refresh(Overview, String),
    Applied(String, String, History),
    Synced(History),
    RestorePreview(Restore, String, String),
    WriteFailed(String, Option<String>, Option<Gateway>),
    Device(Vec<Device>),
    Invitation(Invitation),
}

struct AppView {
    admin: Admin,
    screen: Screen,
    dialog: Option<Dialog>,
    setup: Vec<Entity<InputState>>,
    draft: String,
    editor: Entity<TextareaState>,
    fields: Vec<(Field, Entity<InputState>)>,
    lists: std::collections::HashMap<usize, Vec<Entity<InputState>>>,
    subscriptions: Vec<Subscription>,
    editor_subscription: Option<Subscription>,
    active: String,
    history: Option<History>,
    form: bool,
    show_history: bool,
    overview: Option<Overview>,
    error: Option<String>,
    status: Option<String>,
    busy: bool,
    terminal: bool,
    device_filter: String,
    change_note: Entity<InputState>,
    invitation_note: Entity<InputState>,
    ttl: String,
}

impl AppView {
    fn new(settings: Settings, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let setup = [
            settings.context.clone(),
            settings.namespace.clone(),
            settings.backup_dir.display().to_string(),
        ]
        .into_iter()
        .map(|value| cx.new(|cx| InputState::new(window, cx).default_value(value)))
        .collect();
        let editor = cx.new(|cx| TextareaState::new(window, cx).rows(18));
        let editor_subscription = cx.subscribe(&editor, |this, state, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                this.draft = state.read(cx).value().to_string();
                cx.notify();
            }
        });
        Self {
            admin: Admin::new(Runner::default(), settings),
            screen: Screen::Setup,
            dialog: None,
            setup,
            draft: String::new(),
            editor,
            fields: Vec::new(),
            lists: std::collections::HashMap::new(),
            subscriptions: Vec::new(),
            editor_subscription: Some(editor_subscription),
            active: String::new(),
            history: None,
            form: true,
            show_history: false,
            overview: None,
            error: None,
            status: None,
            busy: false,
            terminal: false,
            device_filter: "approved".into(),
            change_note: cx
                .new(|cx| InputState::new(window, cx).default_value("Update open-pact manifest")),
            invitation_note: cx.new(|cx| InputState::new(window, cx).placeholder("Note for you")),
            ttl: "72h".into(),
        }
    }

    fn build_fields(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.subscriptions.clear();
        self.fields.clear();
        self.lists.clear();
        let Ok(fields) = manifest::fields(&self.draft) else {
            return;
        };
        for field in fields {
            if field.kind == Kind::List {
                let mut items = Vec::new();
                for (index, value) in manifest::list_items(&field)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                {
                    let input = cx.new(|cx| InputState::new(window, cx).default_value(value));
                    let edited = field.clone();
                    self.subscriptions.push(cx.subscribe_in(
                        &input,
                        window,
                        move |this, input, event: &InputEvent, window, cx| {
                            if matches!(event, InputEvent::Change) {
                                match manifest::edit_list(
                                    &this.draft,
                                    &edited,
                                    manifest::ListEdit::Set(index, &input.read(cx).value()),
                                ) {
                                    Ok(text) => {
                                        this.draft = text.clone();
                                        this.error = None;
                                        this.editor.update(cx, |state, cx| {
                                            state.set_value(text, window, cx)
                                        });
                                    }
                                    Err(error) => this.error = Some(error),
                                }
                                cx.notify();
                            }
                        },
                    ));
                    items.push(input);
                }
                self.lists.insert(self.fields.len(), items);
            }
            let input = cx.new(|cx| InputState::new(window, cx).default_value(field.value.clone()));
            let edited = field.clone();
            self.subscriptions.push(cx.subscribe_in(
                &input,
                window,
                move |this, input, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::Change) {
                        match manifest::set_field(&this.draft, &edited, &input.read(cx).value()) {
                            Ok(text) => {
                                this.draft = text.clone();
                                this.error = None;
                                this.editor
                                    .update(cx, |state, cx| state.set_value(text, window, cx));
                            }
                            Err(error) => this.error = Some(error),
                        }
                        cx.notify();
                    }
                },
            ));
            self.fields.push((field, input));
        }
    }

    fn run(&mut self, operation: Operation, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        self.status = Some("Working...".into());
        let mut admin = self.admin.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx.background_executor().spawn(async move {
                fn overview(admin: &Admin) -> Result<Overview, String> {
                    Ok(Overview { gateway: admin.gateway()?, devices: admin.devices()?, deployment: admin.deployment()? })
                }
                fn applied(admin: &Admin, hash: String) -> Result<Outcome, String> {
                    let active = admin.manifest(None)?;
                    if admin::hash(&active) != hash { return Err("Another manifest became active. Reload and review the current manifest.".into()); }
                    let history = admin.sync()?;
                    Ok(Outcome::Applied(hash, active, history))
                }
                fn written(admin: &Admin, result: Result<String, String>) -> Result<Outcome, String> {
                    match result.and_then(|hash| applied(admin, hash)) {
                        Ok(outcome) => Ok(outcome),
                        Err(error) => Ok(Outcome::WriteFailed(error, admin.manifest(None).ok(), admin.gateway().ok())),
                    }
                }
                match operation {
                    Operation::Setup(settings) => {
                        if settings.context.trim().is_empty() || settings.namespace.trim().is_empty() || !settings.backup_dir.is_absolute() {
                            return Err("Enter a kube context, namespace, and absolute backup folder path".into());
                        }
                        admin.settings = settings.clone();
                        let active = admin.manifest(None)?;
                        manifest::fields(&active)?;
                        let overview = overview(&admin)?;
                        let history = admin.sync()?;
                        settings.save()?;
                        Ok(Outcome::Setup(settings, active, overview, history))
                    }
                    Operation::Refresh => Ok(Outcome::Refresh(overview(&admin)?, admin.manifest(None)?)),
                    Operation::Sync => admin.sync().map(Outcome::Synced),
                    Operation::PreviewRestore(restore) => {
                        let text = admin.restore_text(&restore)?;
                        let active = admin.manifest(None)?;
                        Ok(Outcome::RestorePreview(restore, text, active))
                    }
                    Operation::Apply(text, note, reviewed) => {
                        written(&admin, admin.apply(&text, &note, &reviewed, Duration::from_secs(60)))
                    }
                    Operation::Restore(restore, reviewed) => {
                        written(&admin, admin.restore(&restore, &reviewed, Duration::from_secs(60)))
                    }
                    Operation::Device(action, device) => { admin.device_action(action, &device)?; admin.devices().map(Outcome::Device) }
                    Operation::Invite(ttl, note) => admin.invite(&ttl, &note).map(Outcome::Invitation),
                }
            }).await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.busy = false;
                match result {
                    Ok(Outcome::Setup(settings, active, overview, history)) => {
                        this.admin.settings = settings; this.active = active.clone(); this.draft = active;
                        this.overview = Some(overview); this.history = Some(history);
                        this.editor.update(cx, |state, cx| state.set_value(this.draft.clone(), window, cx));
                        this.build_fields(window, cx); this.screen = Screen::Overview; this.status = None;
                    }
                    Ok(Outcome::Refresh(overview, active)) => {
                        if this.draft == this.active {
                            this.draft = active.clone();
                            this.editor.update(cx, |state, cx| state.set_value(this.draft.clone(), window, cx));
                            this.build_fields(window, cx);
                        }
                        this.active = active; this.overview = Some(overview); this.status = Some("Gateway and active manifest refreshed.".into());
                    }
                    Ok(Outcome::WriteFailed(error, stored, gateway)) => {
                        this.dialog = None;
                        this.error = Some(format!("{error} The write outcome is unconfirmed."));
                        this.status = Some(match stored {
                            Some(stored) => { let hash = admin::hash(&stored); this.active = stored; format!("Reloaded stored manifest {hash}. Your draft is retained. Review it before retrying.") }
                            None => "Could not reload the stored manifest. Refresh before retrying.".into(),
                        });
                        if let (Some(overview), Some(gateway)) = (&mut this.overview, gateway) { overview.gateway = gateway; }
                    }
                    Ok(Outcome::Synced(history)) => { this.history = Some(history); this.status = Some("Manifest history synced.".into()); }
                    Ok(Outcome::RestorePreview(restore, text, active)) => {
                        this.active = active; this.dialog = Some(Dialog::Restore(restore, text)); this.status = None;
                    }
                    Ok(Outcome::Applied(hash, active, history)) => {
                        this.active = active.clone(); this.draft = active; this.history = Some(history); this.dialog = None;
                        this.editor.update(cx, |state, cx| state.set_value(this.draft.clone(), window, cx));
                        this.build_fields(window, cx);
                        if let Some(overview) = &mut this.overview { overview.gateway.manifest_hash = hash.clone(); }
                        this.status = Some(format!("Manifest {hash} is in force."));
                    }
                    Ok(Outcome::Device(devices)) => {
                        this.dialog = None;
                        if let Some(overview) = &mut this.overview { overview.devices = devices; }
                        this.status = Some("Device list refreshed.".into());
                    }
                    Ok(Outcome::Invitation(invitation)) => { this.dialog = Some(Dialog::Invitation(Some(invitation))); this.status = None; }
                    Err(error) => { this.error = Some(error); this.status = None; }
                }
                cx.notify();
            });
        }).detach();
        cx.notify();
    }

    fn setup_screen(&self, cx: &Context<Self>) -> Div {
        column().max_w(px(640.)).child(title("Where is your gateway?"))
            .child("The admin app uses your kubectl access. It saves a local backup before each manifest change and syncs the server history.")
            .children(["Cluster", "Namespace", "Local backup folder"].into_iter().enumerate().map(|(i, label)| column().gap_1().child(note(label)).child(Input::new(&self.setup[i]))))
            .child(Button::new("save").label("Save and open").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                let values: Vec<_> = this.setup.iter().map(|state| state.read(cx).value().to_string()).collect();
                this.run(Operation::Setup(Settings { context: values[0].clone(), namespace: values[1].clone(), backup_dir: values[2].clone().into() }), window, cx);
            })))
            .child(note("runs kubectl exec deploy/open-pact-gateway -- open-pact-gateway status --json and manifest history --json"))
    }

    fn overview_screen(&self) -> Div {
        let mut view = column().child(title("Gateway"));
        if let Some(overview) = &self.overview {
            view = view
                .child(banner(
                    if admin::ready(&overview.deployment) {
                        "Running"
                    } else {
                        "Gateway is not ready"
                    },
                    if admin::ready(&overview.deployment) {
                        0x2e7d4f
                    } else {
                        0x9a5b0c
                    },
                    PAPER,
                ))
                .child(row("Version", overview.gateway.version.clone()))
                .child(row(
                    "Manifest in force",
                    overview.gateway.manifest_hash.clone(),
                ))
                .child(row("Devices", overview.gateway.devices.to_string()))
                .child(row(
                    "Automatic approval",
                    if overview.gateway.auto_approve {
                        "On"
                    } else {
                        "Off"
                    },
                ))
                .child(title("Latest results"));
            for device in &overview.devices {
                view = view.child(row(
                    device.note.clone(),
                    format!(
                        "{} · {} · {}",
                        device.last_claim_at.as_deref().unwrap_or("No result"),
                        device.last_result.as_ref().map(display).unwrap_or_default(),
                        device
                            .last_reasons
                            .as_ref()
                            .map(display)
                            .unwrap_or_default()
                    ),
                ));
            }
        }
        view
    }

    fn manifest_screen(&self, cx: &Context<Self>) -> Div {
        if self.show_history {
            return column()
                .child(title("Manifest"))
                .child(
                    Button::new("back-editor")
                        .label("Back to editor")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_history = false;
                            cx.notify();
                        })),
                )
                .child(self.history_screen(cx));
        }
        let parse_error = self.draft.parse::<toml_edit::DocumentMut>().err();
        let mut view = column()
            .child(title("Manifest"))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("form")
                            .label("Form")
                            .disabled(parse_error.is_some() || self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.form = true;
                                this.build_fields(window, cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("toml")
                            .label("TOML")
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.form = false;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                Button::new("history-view")
                    .label("History")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_history = true;
                        cx.notify();
                    })),
            );
        if self.form {
            let mut groups: Vec<(String, Vec<Div>)> = Vec::new();
            for (i, (field, state)) in self.fields.iter().enumerate() {
                let section = field.label.split(" / ").next().unwrap_or("Manifest");
                let label = field
                    .label
                    .strip_prefix(&format!("{section} / "))
                    .unwrap_or(&field.label)
                    .replace('_', " ");
                let original = manifest::fields(&self.active).ok().and_then(|fields| {
                    fields
                        .into_iter()
                        .find(|original| original.path == field.path)
                });
                let changed = original
                    .is_some_and(|original| original.value != state.read(cx).value().as_str());
                let mut control = column()
                    .w(px(180.))
                    .gap_1()
                    .child(note(label).text_color(rgb(if changed { BLUE } else { MUTED })));
                if field.kind == Kind::Bool {
                    let field = field.clone();
                    let checked = state.read(cx).value() == "true";
                    control = control.child(
                        Button::new(("bool", i))
                            .label(if checked { "☑ On" } else { "☐ Off" })
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                match manifest::set_field(
                                    &this.draft,
                                    &field,
                                    if checked { "false" } else { "true" },
                                ) {
                                    Ok(text) => {
                                        this.draft = text.clone();
                                        this.editor.update(cx, |state, cx| {
                                            state.set_value(text, window, cx)
                                        });
                                        this.build_fields(window, cx);
                                    }
                                    Err(error) => this.error = Some(error),
                                }
                                cx.notify();
                            })),
                    );
                } else if field.kind == Kind::List {
                    if let Some(items) = self.lists.get(&i) {
                        for (index, item) in items.iter().enumerate() {
                            let edited = field.clone();
                            control = control.child(
                                div()
                                    .flex()
                                    .gap_1()
                                    .child(Input::new(item).disabled(self.busy))
                                    .child(
                                        Button::new(("remove-item", i * 10000 + index))
                                            .label("Remove")
                                            .disabled(self.busy)
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                match manifest::edit_list(
                                                    &this.draft,
                                                    &edited,
                                                    manifest::ListEdit::Remove(index),
                                                ) {
                                                    Ok(text) => {
                                                        this.draft = text.clone();
                                                        this.editor.update(cx, |state, cx| {
                                                            state.set_value(text, window, cx)
                                                        });
                                                        this.build_fields(window, cx);
                                                    }
                                                    Err(error) => this.error = Some(error),
                                                }
                                                cx.notify();
                                            })),
                                    ),
                            );
                        }
                    }
                    let edited = field.clone();
                    control = control.child(
                        Button::new(("add-item", i))
                            .label("Add item")
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                match manifest::edit_list(
                                    &this.draft,
                                    &edited,
                                    manifest::ListEdit::Add,
                                ) {
                                    Ok(text) => {
                                        this.draft = text.clone();
                                        this.editor.update(cx, |state, cx| {
                                            state.set_value(text, window, cx)
                                        });
                                        this.build_fields(window, cx);
                                    }
                                    Err(error) => this.error = Some(error),
                                }
                                cx.notify();
                            })),
                    );
                } else {
                    control = control.child(Input::new(state).disabled(self.busy));
                }
                if let Some((_, controls)) = groups.iter_mut().find(|(key, _)| key == section) {
                    controls.push(control);
                } else {
                    groups.push((section.into(), vec![control]));
                }
            }
            for (section, controls) in groups {
                let label = match section.as_str() {
                    "company" => "Company",
                    "schedule" => "Automatic sending",
                    "controls" => "Checks",
                    _ => &section,
                };
                view = view.child(
                    div()
                        .flex()
                        .gap_4()
                        .py_2()
                        .border_b_1()
                        .border_color(rgb(RULE))
                        .child(
                            div()
                                .w(px(150.))
                                .flex_shrink_0()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(label.to_string()),
                        )
                        .child(div().flex().flex_wrap().gap_4().flex_1().children(controls)),
                );
            }
        } else {
            view = view.child(Textarea::new(&self.editor).disabled(self.busy));
        }
        if let Some(error) = parse_error {
            view = view.child(banner(error.to_string(), 0xb3261e, 0xfbe6e4));
        }
        let changed = self.active != self.draft;
        view.child(note(
            "Form and TOML edit the same text. Changed values are included in the review.",
        ))
        .child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("discard")
                        .label("Discard")
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.draft = this.active.clone();
                            this.editor.update(cx, |state, cx| {
                                state.set_value(this.draft.clone(), window, cx)
                            });
                            this.build_fields(window, cx);
                            this.error = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("review")
                        .label("Review and apply")
                        .primary()
                        .disabled(
                            self.busy
                                || !changed
                                || self.draft.parse::<toml_edit::DocumentMut>().is_err()
                                || self.error.is_some(),
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.dialog = Some(Dialog::Apply);
                            cx.notify();
                        })),
                ),
        )
    }

    fn history_screen(&self, cx: &Context<Self>) -> Div {
        let mut view = column().child(title("History")).child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("sync")
                        .label("Sync now")
                        .disabled(self.busy)
                        .on_click(
                            cx.listener(|this, _, window, cx| {
                                this.run(Operation::Sync, window, cx)
                            }),
                        ),
                )
                .child(Button::new("open-backups").label("Open folder").on_click(
                    cx.listener(|this, _, _, cx| cx.reveal_path(&this.admin.settings.backup_dir)),
                )),
        );
        if let Some(history) = &self.history {
            view = view.child(note(format!("Last sync {}", history.synced_at)));
            for (i, version) in history.versions.iter().enumerate() {
                let selected = Restore::Server(version.clone());
                view = view.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(
                            note(format!(
                                "Version {} · {} · {}{}",
                                version.version,
                                version.created_at,
                                version.note,
                                if version.active { " · active" } else { "" }
                            ))
                            .flex_1(),
                        )
                        .child(
                            Button::new(("server-restore", i))
                                .label("Restore")
                                .disabled(self.busy || version.active)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.run(
                                        Operation::PreviewRestore(selected.clone()),
                                        window,
                                        cx,
                                    )
                                })),
                        ),
                );
            }
            view = view.child(note("Local backups"));
            for (i, backup) in history.backups.iter().enumerate() {
                let selected = Restore::Local(backup.clone());
                view = view.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(
                            note(
                                backup
                                    .path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into_owned(),
                            )
                            .flex_1(),
                        )
                        .child(
                            Button::new(("local-restore", i))
                                .label("Restore")
                                .disabled(self.busy)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.run(
                                        Operation::PreviewRestore(selected.clone()),
                                        window,
                                        cx,
                                    )
                                })),
                        ),
                );
            }
        } else {
            view = view.child(note("No history synced yet."));
        }
        view
    }

    fn devices_screen(&self, cx: &Context<Self>) -> Div {
        let mut view = column()
            .child(title("Devices"))
            .child(
                Button::new("invite")
                    .label("New invitation")
                    .primary()
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.dialog = Some(Dialog::Invitation(None));
                        cx.notify();
                    })),
            )
            .child(
                div().flex().gap_2().children(
                    [
                        ("pending", "Waiting"),
                        ("approved", "Approved"),
                        ("revoked", "Revoked"),
                    ]
                    .into_iter()
                    .enumerate()
                    .map(|(i, (state, label))| {
                        Button::new(("filter", i))
                            .label(label)
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.device_filter = state.into();
                                cx.notify();
                            }))
                    }),
                ),
            );
        if let Some(overview) = &self.overview {
            for (i, device) in overview
                .devices
                .iter()
                .filter(|d| d.state == self.device_filter)
                .enumerate()
            {
                let mut line = column()
                    .gap_1()
                    .child(row(device.code.clone(), device.note.clone()))
                    .child(note(format!(
                        "{} · {} · {}",
                        device.state,
                        device.last_claim_at.as_deref().unwrap_or("No result"),
                        device.last_result.as_ref().map(display).unwrap_or_default()
                    )));
                let selected = device.clone();
                if device.state == "pending" && !overview.gateway.auto_approve {
                    line = line.child(
                        Button::new(("approve", i))
                            .label("Approve")
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.dialog = Some(Dialog::Approve(selected.clone()));
                                cx.notify();
                            })),
                    );
                } else if device.state == "approved" {
                    line = line.child(
                        Button::new(("revoke", i))
                            .label("Revoke")
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.dialog = Some(Dialog::Revoke(selected.clone()));
                                cx.notify();
                            })),
                    );
                }
                view = view.child(line);
            }
        }
        view.child(note("Every gateway command runs through kubectl exec."))
    }

    fn dialog(&self, dialog: Dialog, cx: &Context<Self>) -> Div {
        let mut view = column()
            .p_6()
            .w(px(520.))
            .rounded_lg()
            .border_1()
            .border_color(rgb(RULE))
            .bg(rgb(0xffffff));
        match dialog {
            Dialog::Apply => {
                view = view.child(title("Apply these manifest changes?"))
                    .child(note(manifest::diff(&self.active, &self.draft)))
                    .child("Devices must sign the new manifest. Until they do, their results are refused.")
                    .child(note("Change note")).child(Input::new(&self.change_note))
                    .child(note(format!("Saves the active TOML in {}. Then pipes the new TOML to kubectl exec -i deploy/open-pact-gateway -- open-pact-gateway manifest set --note {:?} --json", self.admin.settings.backup_dir.display(), self.change_note.read(cx).value())))
                    .child(Button::new("apply").label("Apply manifest").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                        this.run(Operation::Apply(this.draft.clone(), this.change_note.read(cx).value().to_string(), admin::hash(&this.active)), window, cx);
                    })));
            }
            Dialog::Restore(restore, text) => {
                let selected = restore.clone();
                view = view.child(title("Restore this manifest?"))
                    .child(note(manifest::diff(&self.active, &text)))
                    .child("Devices must sign the restored manifest before sending results. The current active manifest is backed up first.")
                    .child(note(match &restore {
                        Restore::Server(version) => format!("open-pact-gateway manifest activate {} --json", version.version),
                        Restore::Local(backup) => format!("Restores {}. Activates its server version if present; otherwise pipes this file to manifest set --note restore --json.", backup.path.display()),
                    }))
                    .child(Button::new("restore-confirm").label("Restore").primary().disabled(self.busy).on_click(cx.listener(move |this, _, window, cx| {
                        this.run(Operation::Restore(selected.clone(), admin::hash(&this.active)), window, cx);
                    })));
            }
            Dialog::Revoke(device) | Dialog::Approve(device) => {
                let revoke = device.state == "approved";
                let action = if revoke { "revoke" } else { "approve" };
                let target = if revoke {
                    device.pseudonym.clone()
                } else {
                    device.code.clone()
                };
                view = view
                    .child(title(if revoke {
                        "Remove this device?"
                    } else {
                        "Approve this device?"
                    }))
                    .child(device.note)
                    .child(if revoke {
                        "This is final. The device cannot be approved again."
                    } else {
                        "The device will be allowed to send results."
                    })
                    .child(note(format!(
                        "kubectl {:?}",
                        self.admin.gateway_args(&["devices", action, &target])
                    )))
                    .child(
                        Button::new("device-action")
                            .label(if revoke { "Revoke" } else { "Approve" })
                            .primary()
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.run(Operation::Device(action, target.clone()), window, cx);
                            })),
                    );
            }
            Dialog::Invitation(invitation) => {
                view = view
                    .child(title("New invitation"))
                    .child(note("Note for you"))
                    .child(Input::new(&self.invitation_note))
                    .child(note("Valid for"))
                    .child(
                        div().flex().gap_2().children(
                            [("24h", "24 h"), ("72h", "72 h"), ("7d", "7 days")]
                                .into_iter()
                                .enumerate()
                                .map(|(i, (ttl, label))| {
                                    Button::new(("ttl", i))
                                        .label(label)
                                        .disabled(self.busy)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.ttl = ttl.into();
                                            cx.notify();
                                        }))
                                }),
                        ),
                    );
                if let Some(invitation) = invitation {
                    let text = invitation.invitation.clone();
                    view = view.child(note("Send this line to the person")).child(invitation.invitation)
                        .child(note(format!("Expires {}. Tell them the company key fingerprint by another channel if they ask: {}", invitation.expires_at, invitation.company_key_fingerprint)))
                        .child(Button::new("copy").label("Copy invitation").primary().on_click(cx.listener(move |_, _, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(text.clone())))));
                } else {
                    view = view
                        .child(note(format!(
                            "open-pact-gateway invite --ttl {} --note {:?} --json",
                            self.ttl,
                            self.invitation_note.read(cx).value()
                        )))
                        .child(
                            Button::new("create")
                                .label("Create invitation")
                                .primary()
                                .disabled(self.busy)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.run(
                                        Operation::Invite(
                                            this.ttl.clone(),
                                            this.invitation_note.read(cx).value().to_string(),
                                        ),
                                        window,
                                        cx,
                                    );
                                })),
                        );
                }
            }
        }
        div().child(
            column()
                .id("dialog-scroll")
                .max_h(px(650.))
                .overflow_y_scroll()
                .child(
                    view.child(
                        Button::new("cancel")
                            .label("Close")
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.dialog = None;
                                cx.notify();
                            })),
                    ),
                ),
        )
    }
}

impl Render for AppView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let _ = &self.editor_subscription;
        let content = match self.screen {
            Screen::Setup => self.setup_screen(cx),
            Screen::Overview => self.overview_screen(),
            Screen::Manifest => self.manifest_screen(cx),
            Screen::Devices => self.devices_screen(cx),
        };
        let sidebar = column()
            .w(px(180.))
            .h_full()
            .p_4()
            .bg(rgb(PAPER))
            .children(
                [
                    (Screen::Overview, "Overview"),
                    (Screen::Manifest, "Manifest"),
                    (Screen::Devices, "Devices"),
                    (Screen::Setup, "Settings"),
                ]
                .into_iter()
                .enumerate()
                .map(|(i, (screen, label))| {
                    Button::new(("nav", i))
                        .label(label)
                        .disabled(self.busy || (screen != Screen::Setup && self.overview.is_none()))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.screen = screen;
                            cx.notify();
                        }))
                }),
            )
            .child(note(format!(
                "Cluster\n{}\nNamespace\n{}",
                self.admin.settings.context, self.admin.settings.namespace
            )))
            .child(
                Button::new("refresh")
                    .label("Refresh")
                    .disabled(self.busy || self.overview.is_none())
                    .on_click(
                        cx.listener(|this, _, window, cx| this.run(Operation::Refresh, window, cx)),
                    ),
            );
        let mut main = column()
            .id("admin-main")
            .flex_1()
            .h_full()
            .overflow_y_scroll()
            .p_6()
            .child(content);
        if let Some(status) = &self.status {
            main = main.child(note(status.clone()));
        }
        if let Some(error) = &self.error {
            main = main.child(banner(error.clone(), 0xb3261e, 0xfbe6e4));
        }
        main = main.child(
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
            main = main.child(terminal(&self.admin.runner));
        }
        let mut root = div()
            .relative()
            .size_full()
            .flex()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .child(sidebar)
            .child(main);
        if let Some(dialog) = self.dialog.clone() {
            root = root.child(
                div()
                    .absolute()
                    .inset_0()
                    .bg(rgba(0x16202b48))
                    .flex()
                    .justify_center()
                    .items_start()
                    .pt_10()
                    .child(self.dialog(dialog, cx)),
            );
        }
        root
    }
}

fn display(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn main() {
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    if let Some(output) = std::env::var_os("OPEN_PACT_SHOTS") {
        snapshots(PathBuf::from(output));
        return;
    }
    let settings = Settings::load();
    launch("open-pact admin", 1040., 760., move |window, cx| {
        cx.new(|cx| {
            let mut app = AppView::new(settings.clone().unwrap_or_default(), window, cx);
            match settings {
                Ok(settings) if !settings.context.is_empty() => {
                    app.run(Operation::Setup(settings), window, cx)
                }
                Err(error) => app.error = Some(error),
                _ => (),
            }
            app
        })
    });
}

#[cfg(all(feature = "snapshot", target_os = "macos"))]
fn snapshots(output: PathBuf) {
    for (name, screen, form, dialog) in [
        ("admin-setup", Screen::Setup, true, None),
        ("admin-a-overview", Screen::Overview, true, None),
        ("admin-b-form", Screen::Manifest, true, None),
        ("admin-c-toml", Screen::Manifest, false, None),
        ("admin-d-apply", Screen::Manifest, true, Some(Dialog::Apply)),
        (
            "admin-e-invitation",
            Screen::Devices,
            true,
            Some(Dialog::Invitation(Some(
                serde_json::from_str(include_str!("../../../tests/fixtures/invitation.json"))
                    .unwrap(),
            ))),
        ),
        ("admin-f-history", Screen::Manifest, true, None),
        (
            "admin-g-restore",
            Screen::Manifest,
            true,
            Some(Dialog::Restore(
                Restore::Server(
                    serde_json::from_str::<Vec<admin::Version>>(include_str!(
                        "../../../tests/fixtures/history.json"
                    ))
                    .unwrap()
                    .remove(0),
                ),
                include_str!("../../../tests/fixtures/manifest-v2.toml").into(),
            )),
        ),
    ] {
        snapshot(&output, name, 1040., 800., |window, cx| {
            cx.new(|cx| {
            let mut app = AppView::new(Settings { backup_dir: "/fictional/backups".into(), context: "test-cluster".into(), namespace: "open-pact".into() }, window, cx);
            app.screen = screen; app.form = form; app.dialog = dialog;
            app.show_history = name == "admin-f-history";
                app.active = include_str!("../../../tests/fixtures/manifest.toml").into();
                app.draft = app.active.clone();
            if name == "admin-d-apply" { app.draft = include_str!("../../../tests/fixtures/manifest-v2.toml").into(); }
            if !form { app.draft = "manifest_version = 1\n[schedule]\nmode = \"vpn\"\ninterval = \"55m\n".into(); }
            app.editor.update(cx, |state, cx| state.set_value(app.draft.clone(), window, cx));
            app.build_fields(window, cx);
            app.overview = Some(Overview {
                gateway: serde_json::from_str(include_str!("../../../tests/fixtures/gateway.json")).unwrap(),
                devices: serde_json::from_str(include_str!("../../../tests/fixtures/devices.json")).unwrap(),
                deployment: serde_json::json!({"status":{"conditions":[{"type":"Available","status":"True"}]}}),
            });
            app.history = Some(History { versions: serde_json::from_str(include_str!("../../../tests/fixtures/history.json")).unwrap(), backups: vec![admin::Backup { path: "/fictional/backups/20261116T100000Z-v1-example.toml".into(), manifest_hash: admin::hash(&app.active) }], synced_at: "2026-11-16T12:30:00Z".into() });
            app
        })
        });
    }
}
