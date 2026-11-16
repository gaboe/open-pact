use gpui::{prelude::*, *};
use gpui_component::{
    Disableable,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
};
use runner::{
    Runner,
    admin::{self, Admin, Device, Gateway, Invitation, Settings},
    desktop::*,
    manifest::{self, Block, Field, Kind},
};
use std::{path::PathBuf, time::Duration};

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
    Revoke(Device),
    Approve(Device),
    Invitation(Option<Invitation>),
}

enum Operation {
    Setup(Settings),
    Refresh,
    Apply(Block, String, String),
    Device(&'static str, String),
    Invite(String, String),
}

struct Overview {
    gateway: Gateway,
    devices: Vec<Device>,
    deployment: serde_json::Value,
}

enum Outcome {
    Setup(Settings, Block, Overview),
    Refresh(Overview),
    Applied(String),
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
    subscriptions: Vec<Subscription>,
    editor_subscription: Option<Subscription>,
    block: Option<Block>,
    form: bool,
    overview: Option<Overview>,
    error: Option<String>,
    status: Option<String>,
    busy: bool,
    terminal: bool,
    device_filter: String,
    commit_message: Entity<InputState>,
    invitation_note: Entity<InputState>,
    ttl: String,
}

impl AppView {
    fn new(settings: Settings, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let setup = [
            settings.repo.display().to_string(),
            settings.manifest.display().to_string(),
            settings.context.clone(),
            settings.namespace.clone(),
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
            subscriptions: Vec::new(),
            editor_subscription: Some(editor_subscription),
            block: None,
            form: true,
            overview: None,
            error: None,
            status: None,
            busy: false,
            terminal: false,
            device_filter: "approved".into(),
            commit_message: cx.new(|cx| {
                InputState::new(window, cx).default_value("chore: update open-pact manifest")
            }),
            invitation_note: cx.new(|cx| InputState::new(window, cx).placeholder("Note for you")),
            ttl: "72h".into(),
        }
    }

    fn build_fields(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.subscriptions.clear();
        self.fields.clear();
        let Ok(fields) = manifest::fields(&self.draft) else {
            return;
        };
        for field in fields {
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
        self.status = Some("Working…".into());
        let mut admin = self.admin.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    fn overview(admin: &Admin) -> Result<Overview, String> {
                        Ok(Overview {
                            gateway: admin.gateway()?,
                            devices: admin.devices()?,
                            deployment: admin.deployment()?,
                        })
                    }
                    match operation {
                        Operation::Setup(mut settings) => {
                            if settings.context.trim().is_empty()
                                || settings.namespace.trim().is_empty()
                            {
                                return Err("Enter a kube context and namespace".into());
                            }
                            settings.repo =
                                settings.repo.canonicalize().map_err(|e| e.to_string())?;
                            if settings.manifest.as_os_str().is_empty() {
                                settings.manifest = admin::relative(
                                    &settings.repo,
                                    &manifest::discover(&settings.repo)?,
                                )?;
                            }
                            admin.settings = settings.clone();
                            admin.validate()?;
                            let block = admin::load_block(&settings)?;
                            manifest::fields(&block.text)?;
                            let overview = overview(&admin)?;
                            settings.save()?;
                            Ok(Outcome::Setup(settings, block, overview))
                        }
                        Operation::Refresh => overview(&admin).map(Outcome::Refresh),
                        Operation::Apply(block, text, message) => admin
                            .apply(&block, &text, &message, Duration::from_secs(180), |_| {})
                            .map(Outcome::Applied),
                        Operation::Device(action, device) => {
                            admin.device_action(action, &device)?;
                            admin.devices().map(Outcome::Device)
                        }
                        Operation::Invite(ttl, note) => {
                            admin.invite(&ttl, &note).map(Outcome::Invitation)
                        }
                    }
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.busy = false;
                match result {
                    Ok(Outcome::Setup(settings, block, overview)) => {
                        this.admin.settings = settings;
                        this.draft = block.text.clone();
                        this.block = Some(block);
                        this.overview = Some(overview);
                        this.editor.update(cx, |state, cx| {
                            state.set_value(this.draft.clone(), window, cx)
                        });
                        this.build_fields(window, cx);
                        this.screen = Screen::Overview;
                        this.status = None;
                    }
                    Ok(Outcome::Refresh(overview)) => {
                        this.overview = Some(overview);
                        this.status = Some("Gateway refreshed.".into());
                    }
                    Ok(Outcome::Applied(hash)) => {
                        this.dialog = None;
                        this.status =
                            Some(format!("Gateway restarted. Manifest {hash} is in force."));
                        match admin::load_block(&this.admin.settings) {
                            Ok(block) => {
                                this.draft = block.text.clone();
                                this.block = Some(block);
                            }
                            Err(error) => this.error = Some(error),
                        }
                    }
                    Ok(Outcome::Device(devices)) => {
                        this.dialog = None;
                        if let Some(overview) = &mut this.overview {
                            overview.devices = devices;
                        }
                        this.status = Some("Device list refreshed.".into());
                    }
                    Ok(Outcome::Invitation(invitation)) => {
                        this.dialog = Some(Dialog::Invitation(Some(invitation)));
                        this.status = None;
                    }
                    Err(error) => {
                        this.error = Some(error);
                        this.status = None;
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn setup_screen(&self, cx: &Context<Self>) -> Div {
        column().max_w(px(640.)).child(title("Where is your gateway configured?"))
            .child("The admin app changes the manifest in your deployment repository and lets your deployment tool roll it out. It reads the cluster with your kubectl access.")
            .children(["Deployment repository", "File with the manifest", "Kube context", "Namespace"].into_iter().enumerate().map(|(i, label)| column().gap_1().child(note(label)).child(Input::new(&self.setup[i]))))
            .child(note("Leave the file empty to find the only YAML file that deploys the open-pact chart and contains a manifest block."))
            .child(Button::new("save").label("Save and open").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                let values: Vec<_> = this.setup.iter().map(|state| state.read(cx).value().to_string()).collect();
                this.run(Operation::Setup(Settings { repo: values[0].clone().into(), manifest: values[1].clone().into(), context: values[2].clone(), namespace: values[3].clone() }), window, cx);
            })))
            .child(note("runs git -C <repo> status and kubectl --context <context> -n <namespace> get deploy/open-pact-gateway -o json"))
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
        let parse_error = self.draft.parse::<toml_edit::DocumentMut>().err();
        let mut view = column().child(title("Manifest")).child(
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
        );
        if self.form {
            for (i, (field, state)) in self.fields.iter().enumerate() {
                let mut control = column().gap_1().child(note(field.label.clone()));
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
                } else {
                    control = control.child(Input::new(state).disabled(self.busy));
                    if field.kind == Kind::List {
                        control = control.child(note(
                            "Edit the list in TOML array format, for example [\"one\", \"two\"].",
                        ));
                    }
                }
                view = view.child(control);
            }
        } else {
            view = view.child(Textarea::new(&self.editor).disabled(self.busy));
        }
        if let Some(error) = parse_error {
            view = view.child(banner(error.to_string(), 0xb3261e, 0xfbe6e4));
        }
        let changed = self
            .block
            .as_ref()
            .is_some_and(|block| block.text != self.draft);
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
                            if let Some(block) = &this.block {
                                this.draft = block.text.clone();
                            }
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
                view = view.child(title("Commit changes to the deployment repository?"))
                    .child(note(manifest::diff(self.block.as_ref().map(|b| b.text.as_str()).unwrap_or(""), &self.draft)))
                    .child("Devices must sign the new manifest. Until they do, their results are refused.")
                    .child(note("Commit message")).child(Input::new(&self.commit_message))
                    .child(note(format!("runs in {}\ngit pull --ff-only\ngit commit -am {:?}\ngit push", self.admin.settings.repo.display(), self.commit_message.read(cx).value())))
                    .child(Button::new("apply").label("Commit and push").primary().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| {
                        if let Some(block) = this.block.clone() {
                            this.run(Operation::Apply(block, this.draft.clone(), this.commit_message.read(cx).value().to_string()), window, cx);
                        }
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
        view.child(
            Button::new("cancel")
                .label("Close")
                .disabled(self.busy)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.dialog = None;
                    cx.notify();
                })),
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
                Ok(settings) if !settings.repo.as_os_str().is_empty() => {
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
    ] {
        snapshot(&output, name, 1040., 800., |window, cx| {
            cx.new(|cx| {
            let mut app = AppView::new(Settings { repo: "~/work/infra".into(), manifest: "clusters/test/open-pact/application.yaml".into(), context: "test-cluster".into(), namespace: "open-pact".into() }, window, cx);
            app.screen = screen; app.form = form; app.dialog = dialog;
            let block = Block::parse(include_str!("../../../tests/fixtures/application.yaml").into()).unwrap();
            app.draft = block.text.clone(); app.block = Some(block);
            if !form { app.draft = "manifest_version = 1\n[schedule]\nmode = \"vpn\"\ninterval = \"55m\n".into(); }
            app.editor.update(cx, |state, cx| state.set_value(app.draft.clone(), window, cx));
            app.build_fields(window, cx);
            app.overview = Some(Overview {
                gateway: serde_json::from_str(include_str!("../../../tests/fixtures/gateway.json")).unwrap(),
                devices: serde_json::from_str(include_str!("../../../tests/fixtures/devices.json")).unwrap(),
                deployment: serde_json::json!({"status":{"conditions":[{"type":"Available","status":"True"}]}}),
            }); app
        })
        });
    }
}
