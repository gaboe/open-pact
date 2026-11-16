use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
};
use runner::{
    Runner,
    admin::{self, Admin, Device, Gateway, History, Invitation, Restore, Settings},
    desktop::*,
    manifest::{self, Field, Kind},
    text::*,
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

    fn edit_draft(
        &mut self,
        result: Result<String, String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok(text) => {
                self.draft = text.clone();
                self.editor
                    .update(cx, |state, cx| state.set_value(text, window, cx));
                self.build_fields(window, cx);
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    fn change_count(&self) -> usize {
        let (Ok(before), Ok(after)) = (
            manifest::fields(&self.active),
            manifest::fields(&self.draft),
        ) else {
            return usize::from(self.active != self.draft);
        };
        let changed = after
            .iter()
            .filter(|field| {
                !before
                    .iter()
                    .any(|old| old.path == field.path && old.value == field.value)
            })
            .count();
        let removed = before
            .iter()
            .filter(|old| !after.iter().any(|field| field.path == old.path))
            .count();
        changed + removed
    }

    fn setup_screen(&self, cx: &Context<Self>) -> Div {
        column().max_w(px(640.)).gap(px(14.)).child(title("Where is your gateway?"))
            .child(div().text_color(rgb(INK_2)).child("The admin app uses your kubectl access. It saves a local backup before each manifest change and syncs the server history."))
            .children(["Cluster", "Namespace", "Local backup folder"].into_iter().enumerate().map(|(i, name)| column().gap_1p5().child(label(name)).child(Input::new(&self.setup[i]))))
            .child(actions().child(Button::new("save").label("Save and open").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                let values: Vec<_> = this.setup.iter().map(|state| state.read(cx).value().to_string()).collect();
                this.run(Operation::Setup(Settings { context: values[0].clone(), namespace: values[1].clone(), backup_dir: values[2].clone().into() }), window, cx);
            }))))
            .child(runs("runs", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway status --json"))
            .child(runs("and", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway manifest history --json"))
    }

    fn overview_screen(&self, cx: &Context<Self>) -> Div {
        let mut view = column().gap(px(18.));
        let Some(overview) = &self.overview else {
            return view.child(title("Gateway"));
        };
        let ready = admin::ready(&overview.deployment);
        let hash = overview.gateway.manifest_hash.clone();
        let copy = hash.clone();
        let version = overview.gateway.version.clone();
        let cell = |name: &'static str, value: Div| {
            div()
                .px(px(14.))
                .py(px(12.))
                .border_r_1()
                .border_color(rgb(RULE))
                .child(div().text_size(px(12.)).text_color(rgb(MUTED)).child(name))
                .child(value.mt(px(2.)))
        };
        let fact = |text: String| {
            div()
                .text_size(px(15.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(text)
        };
        view = view
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(title("Gateway").flex_1())
                    .child(pill(
                        if ready {
                            "Running"
                        } else {
                            "Gateway is not ready"
                        },
                        if ready { Tone::Good } else { Tone::Warn },
                    )),
            )
            .child(
                div()
                    .flex()
                    .overflow_hidden()
                    .rounded(px(10.))
                    .border_1()
                    .border_color(rgb(RULE))
                    .child(
                        cell(
                            "Version",
                            fact(if version.starts_with('v') {
                                version
                            } else {
                                format!("v{version}")
                            }),
                        )
                        .w(px(120.)),
                    )
                    .child(
                        cell(
                            "Manifest in force",
                            div()
                                .flex()
                                .items_center()
                                .gap_1()
                                .child(hash_chip(&hash))
                                .child(
                                    ghost("copy-hash", "Copy")
                                        .xsmall()
                                        .tooltip(hash.clone())
                                        .on_click(cx.listener(move |_, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                copy.clone(),
                                            ))
                                        })),
                                ),
                        )
                        .w(px(230.)),
                    )
                    .child(
                        cell("Devices", fact(devices_summary(&overview.gateway.devices))).flex_1(),
                    )
                    .child(
                        cell(
                            "Automatic approval",
                            fact(if overview.gateway.auto_approve {
                                "On".into()
                            } else {
                                "Off".into()
                            }),
                        )
                        .w(px(160.))
                        .border_r_0(),
                    ),
            )
            .child(label("Latest results"));
        let mut results = table().child(result_header());
        for device in &overview.devices {
            let result = result_text(device.last_result.as_ref());
            let reasons = reasons_text(device.last_reasons.as_ref());
            results = results.child(result_row(
                device
                    .last_claim_at
                    .as_deref()
                    .map(readable_local)
                    .unwrap_or_else(|| "–".into()),
                div().child(device.note.clone()),
                &result,
                if reasons.is_empty() {
                    "–".into()
                } else {
                    reasons
                },
            ));
        }
        view.child(results)
            .child(column().gap_1().child(runs("runs", "kubectl get deploy/open-pact-gateway -o json")).child(runs("and", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway devices list --json")))
    }

    fn manifest_screen(&self, cx: &Context<Self>) -> Div {
        if self.show_history {
            return column()
                .gap(px(14.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(title("Manifest").flex_1())
                        .child(ghost("back-editor", "Back to editor").on_click(cx.listener(
                            |this, _, _, cx| {
                                this.show_history = false;
                                cx.notify();
                            },
                        ))),
                )
                .child(self.history_screen(cx));
        }
        let parse_error = self.draft.parse::<toml_edit::DocumentMut>().err();
        let form_blocked = parse_error.is_some() || self.busy;
        let mut view = column().gap(px(18.)).child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(title("Manifest").flex_1())
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .text_size(px(13.))
                        .text_color(rgb(MUTED))
                        .child("in force")
                        .child(hash_chip(&admin::hash(&self.active))),
                )
                .child(seg(vec![
                    seg_item("form", "Form", self.form)
                        .when(form_blocked, |item| item.opacity(0.45))
                        .on_click(cx.listener(|this, _, window, cx| {
                            if this.busy || this.draft.parse::<toml_edit::DocumentMut>().is_err() {
                                return;
                            }
                            this.form = true;
                            this.build_fields(window, cx);
                            cx.notify();
                        })),
                    seg_item("toml", "TOML", !self.form)
                        .when(self.busy, |item| item.opacity(0.45))
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.busy {
                                this.form = false;
                                cx.notify();
                            }
                        })),
                ]))
                .child(
                    ghost("history-view", "History").on_click(cx.listener(|this, _, _, cx| {
                        this.show_history = true;
                        cx.notify();
                    })),
                ),
        );
        if self.form {
            let original = manifest::fields(&self.active).unwrap_or_default();
            let mut groups: Vec<(String, Vec<Div>)> = Vec::new();
            for (i, (field, state)) in self.fields.iter().enumerate() {
                let changed = original
                    .iter()
                    .find(|old| old.path == field.path)
                    .is_none_or(|old| old.value != state.read(cx).value().as_str());
                let mut control = column().w(px(180.)).gap_1().child(
                    note(field.label.clone()).text_color(rgb(if changed { BLUE } else { MUTED })),
                );
                if field.kind == Kind::Bool {
                    let field = field.clone();
                    let checked = state.read(cx).value() == "true";
                    control = control.child(
                        Checkbox::new(("bool", i))
                            .label(if checked { "On" } else { "Off" })
                            .checked(checked)
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                let result = manifest::set_field(
                                    &this.draft,
                                    &field,
                                    if checked { "false" } else { "true" },
                                );
                                this.edit_draft(result, window, cx);
                            })),
                    );
                } else if field.kind == Kind::List {
                    for (index, item) in self.lists.get(&i).into_iter().flatten().enumerate() {
                        let edited = field.clone();
                        control = control.child(
                            div()
                                .flex()
                                .gap_1()
                                .items_center()
                                .child(div().flex_1().child(Input::new(item).disabled(self.busy)))
                                .child(
                                    Button::new(("remove-item", i * 10000 + index))
                                        .label("Remove")
                                        .small()
                                        .disabled(self.busy)
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            let result = manifest::edit_list(
                                                &this.draft,
                                                &edited,
                                                manifest::ListEdit::Remove(index),
                                            );
                                            this.edit_draft(result, window, cx);
                                        })),
                                ),
                        );
                    }
                    let edited = field.clone();
                    control = control.child(
                        ghost(("add-item", i), "Add item")
                            .disabled(self.busy)
                            .self_start()
                            .on_click(cx.listener(move |this, _, window, cx| {
                                let result = manifest::edit_list(
                                    &this.draft,
                                    &edited,
                                    manifest::ListEdit::Add,
                                );
                                this.edit_draft(result, window, cx);
                            })),
                    );
                } else {
                    control = control.child(Input::new(state).disabled(self.busy));
                }
                if let Some((_, controls)) =
                    groups.iter_mut().find(|(key, _)| *key == field.section)
                {
                    controls.push(control);
                } else {
                    groups.push((field.section.clone(), vec![control]));
                }
            }
            let mut grid = div().flex().flex_col().border_t_1().border_color(rgb(RULE));
            for (section, controls) in groups {
                grid = grid.child(
                    div()
                        .flex()
                        .gap_4()
                        .py(px(11.))
                        .border_b_1()
                        .border_color(rgb(RULE_2))
                        .child(
                            div()
                                .w(px(160.))
                                .flex_shrink_0()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(INK_2))
                                .child(section),
                        )
                        .child(div().flex().flex_wrap().gap_4().flex_1().children(controls)),
                );
            }
            view = view.child(grid);
        } else {
            view = view.child(Textarea::new(&self.editor).disabled(self.busy));
        }
        if let Some(error) = parse_error {
            let line = error.span().map_or(1, |span| {
                self.draft[..span.start.min(self.draft.len())]
                    .matches('\n')
                    .count()
                    + 1
            });
            view = view.child(error_block(format!(
                "Line {line}: {}. Fix it to switch back to Form or apply.",
                error.message()
            )));
        }
        let changes = self.change_count();
        let can_review = !(self.busy
            || changes == 0
            || self.draft.parse::<toml_edit::DocumentMut>().is_err()
            || self.error.is_some());
        view.child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .px_4()
                .py_3()
                .rounded(px(10.))
                .bg(rgb(SIDE))
                .border_1()
                .border_color(rgb(RULE))
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(match changes {
                                    0 => "No changes.".to_owned(),
                                    1 => "1 change.".to_owned(),
                                    n => format!("{n} changes."),
                                }),
                        )
                        .child(note("Form and TOML edit the same text.")),
                )
                .child(
                    Button::new("discard")
                        .label("Discard")
                        .disabled(self.busy || changes == 0)
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
                        .disabled(!can_review)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.dialog = Some(Dialog::Apply);
                            cx.notify();
                        })),
                ),
        )
    }

    fn history_screen(&self, cx: &Context<Self>) -> Div {
        let mut view =
            column().gap(px(14.)).child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(title("History").flex_1())
                    .child(
                        Button::new("sync")
                            .label("Sync now")
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run(Operation::Sync, window, cx)
                            })),
                    )
                    .child(
                        Button::new("open-backups")
                            .label("Open folder")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| {
                                cx.reveal_path(&this.admin.settings.backup_dir)
                            })),
                    ),
            );
        let Some(history) = &self.history else {
            return view.child(note("No history synced yet."));
        };
        view = view.child(note(format!(
            "Last sync {}",
            readable_local(&history.synced_at)
        )));
        let mut versions = table();
        for (i, version) in history.versions.iter().enumerate() {
            let selected = Restore::Server(version.clone());
            versions = versions.child(row(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("Version {}", version.version)),
                    )
                    .child(note(format!(
                        "{} · {}",
                        readable_local(&version.created_at),
                        version.note
                    )))
                    .when(version.active, |line| {
                        line.child(pill("Active", Tone::Good))
                    }),
                Button::new(("server-restore", i))
                    .label("Restore")
                    .small()
                    .disabled(self.busy || version.active)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.run(Operation::PreviewRestore(selected.clone()), window, cx)
                    })),
            ));
        }
        view = view.child(versions).child(label("Local backups"));
        let mut backups = table();
        for (i, backup) in history.backups.iter().enumerate() {
            let selected = Restore::Local(backup.clone());
            backups = backups.child(row(
                div().font_family(mono()).text_size(px(12.5)).child(
                    backup
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                ),
                Button::new(("local-restore", i))
                    .label("Restore")
                    .small()
                    .disabled(self.busy)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.run(Operation::PreviewRestore(selected.clone()), window, cx)
                    })),
            ));
        }
        view.child(backups)
    }

    fn devices_screen(&self, cx: &Context<Self>) -> Div {
        let devices = self
            .overview
            .as_ref()
            .map(|overview| overview.devices.as_slice())
            .unwrap_or_default();
        let count = |state: &str| devices.iter().filter(|d| d.state == state).count();
        let mut view = column()
            .gap(px(18.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(title("Devices").flex_1())
                    .child(
                        Button::new("invite")
                            .label("New invitation")
                            .primary()
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.dialog = Some(Dialog::Invitation(None));
                                cx.notify();
                            })),
                    ),
            )
            .child(tabs(
                [
                    ("pending", "Waiting"),
                    ("approved", "Approved"),
                    ("revoked", "Revoked"),
                ]
                .into_iter()
                .enumerate()
                .map(|(i, (state, name))| {
                    tab_item(
                        ("filter", i),
                        format!("{name} {}", count(state)),
                        self.device_filter == state,
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.device_filter = state.into();
                        cx.notify();
                    }))
                })
                .collect(),
            ));
        let mut list = div().flex().flex_col().child(device_header());
        if let Some(overview) = &self.overview {
            for (i, device) in overview
                .devices
                .iter()
                .filter(|d| d.state == self.device_filter)
                .enumerate()
            {
                let selected = device.clone();
                let result = result_text(device.last_result.as_ref());
                let reasons = reasons_text(device.last_reasons.as_ref());
                let action = if device.state == "pending" && !overview.gateway.auto_approve {
                    Some(
                        Button::new(("approve", i))
                            .label("Approve")
                            .primary()
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.dialog = Some(Dialog::Approve(selected.clone()));
                                cx.notify();
                            })),
                    )
                } else if device.state == "approved" {
                    Some(
                        Button::new(("revoke", i))
                            .label("Revoke")
                            .danger()
                            .outline()
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.dialog = Some(Dialog::Revoke(selected.clone()));
                                cx.notify();
                            })),
                    )
                } else {
                    None
                };
                list = list.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .py(px(10.))
                        .border_b_1()
                        .border_color(rgb(RULE_2))
                        .child(
                            div()
                                .w(px(100.))
                                .font_family(mono())
                                .child(device.code.clone()),
                        )
                        .child(
                            div()
                                .flex_1()
                                .flex()
                                .flex_col()
                                .child(device.note.clone())
                                .when(!reasons.is_empty(), |cell| cell.child(note(reasons))),
                        )
                        .child(
                            div().w(px(160.)).child(
                                device
                                    .last_claim_at
                                    .as_deref()
                                    .map(readable_local)
                                    .unwrap_or_else(|| "–".into()),
                            ),
                        )
                        .child(
                            div()
                                .w(px(120.))
                                .text_color(rgb(tone_text(result_tone(&result))))
                                .child(result),
                        )
                        .child(div().w(px(90.)).flex().justify_end().children(action)),
                );
            }
        }
        view = view.child(list);
        view.child(
            runs(
                "Revoke runs",
                "open-pact-gateway devices revoke <pseudonym>",
            )
            .child(note("after a confirmation that says it is final.")),
        )
        .child(note("Every gateway command runs through kubectl exec."))
    }

    fn dialog(&self, dialog: Dialog, cx: &Context<Self>) -> Div {
        let heading = |text: &'static str| {
            div()
                .text_size(px(19.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(text)
        };
        let close = Button::new("cancel")
            .label("Close")
            .disabled(self.busy)
            .on_click(cx.listener(|this, _, _, cx| {
                this.dialog = None;
                cx.notify();
            }));
        let mut view = column().gap(px(14.));
        match dialog {
            Dialog::Apply => {
                view = view.child(heading("Apply these manifest changes?"))
                    .child(diff_view(&manifest::diff(&self.active, &self.draft)))
                    .child(note("Devices must sign the new manifest. Until they do, their results are refused."))
                    .child(column().gap_1p5().child(label("Change note")).child(Input::new(&self.change_note)))
                    .child(note(format!("Saves the active TOML in {} first.", self.admin.settings.backup_dir.display())))
                    .child(runs("runs", format!("kubectl exec -i deploy/open-pact-gateway -- open-pact-gateway manifest set --note {:?} --json", self.change_note.read(cx).value())))
                    .child(actions().child(close.label("Cancel")).child(Button::new("apply").label("Apply manifest").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                        this.run(Operation::Apply(this.draft.clone(), this.change_note.read(cx).value().to_string(), admin::hash(&this.active)), window, cx);
                    }))));
            }
            Dialog::Restore(restore, text) => {
                let selected = restore.clone();
                view = view.child(heading("Restore this manifest?"))
                    .child(diff_view(&manifest::diff(&self.active, &text)))
                    .child(note("Devices must sign the restored manifest before sending results. The current active manifest is backed up first."))
                    .child(match &restore {
                        Restore::Server(version) => runs("runs", format!("open-pact-gateway manifest activate {} --json", version.version)),
                        Restore::Local(backup) => runs("restores", backup.path.display().to_string()),
                    })
                    .when(matches!(restore, Restore::Local(_)), |view| view.child(note("Activates its server version if present; otherwise pipes this file to manifest set --note restore --json.")))
                    .child(actions().child(close.label("Cancel")).child(Button::new("restore-confirm").label("Restore").primary().disabled(self.busy).on_click(cx.listener(move |this, _, window, cx| {
                        this.run(Operation::Restore(selected.clone(), admin::hash(&this.active)), window, cx);
                    }))));
            }
            Dialog::Revoke(device) | Dialog::Approve(device) => {
                let revoke = device.state == "approved";
                let action = if revoke { "revoke" } else { "approve" };
                let target = if revoke {
                    device.pseudonym.clone()
                } else {
                    device.code.clone()
                };
                let command = format!(
                    "kubectl {}",
                    self.admin
                        .gateway_args(&["devices", action, &target])
                        .join(" ")
                );
                let confirm = Button::new("device-action")
                    .label(if revoke { "Revoke" } else { "Approve" })
                    .disabled(self.busy)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.run(Operation::Device(action, target.clone()), window, cx);
                    }));
                view = view
                    .child(heading(if revoke {
                        "Remove this device?"
                    } else {
                        "Approve this device?"
                    }))
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(device.note))
                    .child(if revoke {
                        "This is final. The device cannot be approved again."
                    } else {
                        "The device will be allowed to send results."
                    })
                    .child(runs("runs", command))
                    .child(actions().child(close.label("Cancel")).child(if revoke {
                        confirm.danger()
                    } else {
                        confirm.primary()
                    }));
            }
            Dialog::Invitation(invitation) => {
                view = view
                    .child(heading("New invitation"))
                    .child(
                        column()
                            .gap_1p5()
                            .child(label("Note for you"))
                            .child(Input::new(&self.invitation_note)),
                    )
                    .child(
                        column().gap_1p5().child(label("Valid for")).child(seg([
                            ("24h", "24 h"),
                            ("72h", "72 h"),
                            ("7d", "7 days"),
                        ]
                        .into_iter()
                        .enumerate()
                        .map(|(i, (ttl, name))| {
                            seg_item(("ttl", i), name, self.ttl == ttl).on_click(cx.listener(
                                move |this, _, _, cx| {
                                    this.ttl = ttl.into();
                                    cx.notify();
                                },
                            ))
                        })
                        .collect())),
                    );
                if let Some(invitation) = invitation {
                    let text = invitation.invitation.clone();
                    view = view.child(column().gap_1p5().child(label("Send this line to the person"))
                            .child(div().px(px(12.)).py(px(10.)).rounded(px(8.)).border_1().border_color(rgb(FIELD_BORDER)).font_family(mono()).text_size(px(12.5)).child(invitation.invitation)))
                        .child(div().flex().flex_wrap().items_center().gap_1p5().text_size(px(13.)).text_color(rgb(MUTED))
                            .child(div().min_w_0().child(format!("Expires {}. Tell them the company key fingerprint by another channel if they ask:", readable_local(&invitation.expires_at))))
                            .child(code(invitation.company_key_fingerprint)))
                        .child(actions().child(close).child(Button::new("copy").label("Copy invitation").primary().on_click(cx.listener(move |_, _, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(text.clone()))))));
                } else {
                    view = view
                        .child(runs(
                            "runs",
                            format!(
                                "open-pact-gateway invite --ttl {} --note {:?} --json",
                                self.ttl,
                                self.invitation_note.read(cx).value()
                            ),
                        ))
                        .child(
                            actions().child(close).child(
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
                            ),
                        );
                }
            }
        }
        div()
            .w(px(520.))
            .rounded(px(12.))
            .border_1()
            .border_color(rgb(RULE))
            .bg(rgb(0xffffff))
            .shadow_lg()
            .child(
                div()
                    .id("dialog-scroll")
                    .max_h(px(650.))
                    .overflow_y_scroll()
                    .p(px(24.))
                    .child(view),
            )
    }
}

fn result_header() -> Div {
    div()
        .flex()
        .gap_3()
        .py(px(10.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .text_size(px(12.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(MUTED))
        .child(div().w(px(160.)).child("Time"))
        .child(div().flex_1().child("Device"))
        .child(div().w(px(170.)).child("Result"))
        .child(div().flex_1().child("Reason"))
}

fn result_row(time: String, device: Div, result: &str, reasons: String) -> Div {
    div()
        .flex()
        .gap_3()
        .py(px(10.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .child(div().w(px(160.)).child(time))
        .child(div().flex_1().child(device))
        .child(
            div()
                .w(px(170.))
                .text_color(rgb(tone_text(result_tone(result))))
                .child(result.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(13.))
                .text_color(rgb(MUTED))
                .child(reasons),
        )
}

fn device_header() -> Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .py(px(10.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .text_size(px(12.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(MUTED))
        .child(div().w(px(100.)).child("Device code"))
        .child(div().flex_1().child("Note"))
        .child(div().w(px(160.)).child("Last result"))
        .child(div().w(px(120.)).child("Result"))
        .child(div().w(px(90.)))
}

fn diff_view(diff: &str) -> Stateful<Div> {
    div()
        .id("diff")
        .max_h(px(260.))
        .overflow_y_scroll()
        .py(px(10.))
        .rounded(px(10.))
        .border_1()
        .border_color(rgb(RULE))
        .bg(rgb(0xfbfaf7))
        .font_family(mono())
        .text_size(px(12.5))
        .children(diff.lines().map(|line| {
            let (background, color) = if line.starts_with('+') && !line.starts_with("+++") {
                (0xe7f3eb, INK)
            } else if line.starts_with('-') && !line.starts_with("---") {
                (0xfbe9e7, INK)
            } else if line.starts_with("@@") || line.starts_with("+++") || line.starts_with("---") {
                (0xfbfaf7, MUTED)
            } else {
                (0xfbfaf7, INK_2)
            };
            div()
                .px(px(12.))
                .bg(rgb(background))
                .text_color(rgb(color))
                .child(if line.is_empty() {
                    " ".to_owned()
                } else {
                    line.to_owned()
                })
        }))
}

fn tone_text(tone: Tone) -> u32 {
    match tone {
        Tone::Good => 0x2e7d4f,
        Tone::Warn => 0x9a5b0c,
        Tone::Bad => BAD,
        _ => INK_2,
    }
}

impl Render for AppView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let _ = &self.editor_subscription;
        let content = match self.screen {
            Screen::Setup => self.setup_screen(cx),
            Screen::Overview => self.overview_screen(cx),
            Screen::Manifest => self.manifest_screen(cx),
            Screen::Devices => self.devices_screen(cx),
        };
        let sidebar = div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(200.))
            .h_full()
            .gap_0p5()
            .px(px(10.))
            .py_4()
            .bg(rgb(SIDE))
            .border_r_1()
            .border_color(rgb(RULE))
            .children(
                [
                    (Screen::Overview, "Overview"),
                    (Screen::Manifest, "Manifest"),
                    (Screen::Devices, "Devices"),
                    (Screen::Setup, "Settings"),
                ]
                .into_iter()
                .enumerate()
                .map(|(i, (screen, name))| {
                    nav_item(("nav", i), name, self.screen == screen).on_click(cx.listener(
                        move |this, _, _, cx| {
                            if this.busy || (screen != Screen::Setup && this.overview.is_none()) {
                                return;
                            }
                            this.screen = screen;
                            cx.notify();
                        },
                    ))
                }),
            )
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .px(px(12.))
                    .pt(px(10.))
                    .border_t_1()
                    .border_color(rgb(RULE))
                    .child(note("Cluster"))
                    .child(
                        div()
                            .font_family(mono())
                            .text_size(px(12.))
                            .child(self.admin.settings.context.clone()),
                    )
                    .child(note("Namespace"))
                    .child(
                        div()
                            .font_family(mono())
                            .text_size(px(12.))
                            .child(self.admin.settings.namespace.clone()),
                    )
                    .child(
                        ghost("refresh", "Refresh")
                            .disabled(self.busy || self.overview.is_none())
                            .self_start()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run(Operation::Refresh, window, cx)
                            })),
                    ),
            );
        let mut main = column()
            .id("admin-main")
            .flex_1()
            .h_full()
            .min_w_0()
            .overflow_y_scroll()
            .gap(px(18.))
            .px(px(28.))
            .py(px(24.))
            .child(content);
        if let Some(status) = &self.status {
            main = main.child(note(status.clone()));
        }
        if let Some(error) = &self.error {
            main = main.child(banner(error.clone(), BAD, BAD_WASH));
        }
        let mut root = div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .child(div().flex().flex_1().min_h_0().child(sidebar).child(main))
            .child(terminal_drawer(
                self.terminal,
                &self.admin.runner,
                cx.listener(|this, _, _, cx| {
                    this.terminal = !this.terminal;
                    cx.notify();
                }),
            ));
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
            if name == "admin-d-apply" || name == "admin-b-form" { app.draft = include_str!("../../../tests/fixtures/manifest-v2.toml").into(); }
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
