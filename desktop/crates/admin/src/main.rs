#![cfg_attr(windows, windows_subsystem = "windows")]

mod form;
mod results;

use form::FormState;
use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Sizable,
    button::{Button, ButtonVariants},
    input::{EditorState, Input, InputEvent, InputState},
    select::{Select, SelectEvent, SelectState},
};
use gpui_kit_assets::IconName;
use results::ResultsView;
use runner::{
    Runner,
    admin::{
        self, Admin, Device, Gateway, History, Invitation, Restore, Settings, WriteError, Written,
    },
    desktop::*,
    manifest, shell_line, shell_quote,
    text::*,
    update::UpdateState,
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
    Results,
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

/// What a refresh does with the draft and the inputs of the form.
#[derive(Debug, PartialEq, Eq)]
enum RefreshStep {
    /// Take the refreshed manifest as the draft and make the inputs again.
    Rebuild,
    /// Keep the draft and the inputs.
    Keep,
    /// Keep the draft and the inputs, and say that the gateway changed. The field holds unread text.
    Warn(String),
}

/// Unread input is never rebuilt away. The draft follows the gateway only when it is the active
/// manifest and no input holds unread text.
fn refresh_step(
    unread: Option<String>,
    draft_is_active: bool,
    active_changed: bool,
) -> RefreshStep {
    match unread {
        Some(field) if active_changed => RefreshStep::Warn(field),
        Some(_) => RefreshStep::Keep,
        None if draft_is_active => RefreshStep::Rebuild,
        None => RefreshStep::Keep,
    }
}

struct Overview {
    gateway: Gateway,
    devices: Vec<Device>,
    deployment: serde_json::Value,
}

enum Outcome {
    Setup(Settings, String, Overview, History),
    Refresh(Overview, String),
    Applied(Written, String, Option<History>, Option<String>),
    Synced(History),
    RestorePreview(Restore, String, String),
    WriteFailed(WriteError, Option<String>, Option<Gateway>),
    Device(Vec<Device>),
    Invitation(Invitation),
}

/// What kubectl answered for a list on the setup screen.
#[derive(Clone)]
enum Listing {
    Loading,
    /// Nothing to ask yet, for example no cluster is chosen.
    Idle,
    Listed(Vec<String>),
    Failed(String),
}

impl Listing {
    fn items(&self) -> Option<&Vec<String>> {
        match self {
            Self::Listed(list) if !list.is_empty() => Some(list),
            _ => None,
        }
    }
}

/// Save may run only when the cluster and the namespace on screen are final. While kubectl lists,
/// the hidden text field would be saved.
fn can_save(contexts: &Listing, namespaces: &Listing, busy: bool) -> bool {
    !busy && !matches!(contexts, Listing::Loading) && !matches!(namespaces, Listing::Loading)
}

type Choice = Entity<SelectState<Vec<SharedString>>>;

struct AppView {
    admin: Admin,
    screen: Screen,
    dialog: Option<Dialog>,
    cluster: Choice,
    cluster_text: Entity<InputState>,
    namespace: Choice,
    namespace_text: Entity<InputState>,
    kubectl_input: Entity<InputState>,
    contexts: Listing,
    namespaces: Listing,
    /// Counts kubectl list requests, so a late answer for an old cluster is dropped.
    generation: u64,
    kubectl_loaded: String,
    setup_subscriptions: Vec<Subscription>,
    draft: String,
    editor: Entity<EditorState>,
    fv: FormState,
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
    update: UpdateState,
    results: ResultsView,
}

impl AppView {
    fn new(settings: Settings, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cluster = cx.new(|cx| SelectState::new(Vec::<SharedString>::new(), None, window, cx));
        let namespace = cx.new(|cx| SelectState::new(Vec::<SharedString>::new(), None, window, cx));
        let cluster_text = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Cluster name")
                .default_value(settings.context.clone())
        });
        let namespace_text = cx.new(|cx| {
            InputState::new(window, cx).default_value(if settings.namespace.trim().is_empty() {
                "open-pact".to_owned()
            } else {
                settings.namespace.clone()
            })
        });
        let kubectl_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Empty searches PATH")
                .default_value(settings.kubectl.clone())
        });
        let setup_subscriptions = vec![
            cx.subscribe_in(
                &cluster,
                window,
                |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                    let SelectEvent::Confirm(Some(context)) = event else {
                        return;
                    };
                    this.load_namespaces(context.to_string(), window, cx);
                },
            ),
            cx.subscribe_in(
                &kubectl_input,
                window,
                |this, input, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::Blur | InputEvent::PressEnter { .. })
                        && input.read(cx).value().as_ref() != this.kubectl_loaded
                    {
                        this.load_contexts(window, cx);
                    }
                },
            ),
        ];
        let kubectl_loaded = settings.kubectl.clone();
        let editor = cx.new(|cx| EditorState::new(window, cx).language("toml"));
        let editor_subscription = cx.subscribe_in(
            &editor,
            window,
            |this, state, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let value = state.read(cx).value().to_string();
                    if value != this.draft {
                        let before = std::mem::replace(&mut this.draft, value);
                        runner::manifest::sends_after_edit(
                            &before,
                            &this.draft,
                            &mut this.fv.sends_kept,
                            &mut this.fv.sends_seen,
                        );
                        this.show_draft(window, cx);
                        cx.notify();
                    }
                }
            },
        );
        let fv = FormState::new(window, cx);
        let results = ResultsView::new(window, cx);
        Self {
            admin: Admin::new(Runner::default(), settings),
            screen: Screen::Setup,
            dialog: None,
            cluster,
            cluster_text,
            namespace,
            namespace_text,
            kubectl_input,
            contexts: Listing::Idle,
            namespaces: Listing::Idle,
            generation: 0,
            kubectl_loaded,
            setup_subscriptions,
            draft: String::new(),
            editor,
            fv,
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
            update: UpdateState::None,
            results,
        }
    }

    /// The kubectl program from the field, as saved settings would use it.
    fn kubectl_program(&self, cx: &App) -> std::path::PathBuf {
        Settings {
            kubectl: self.kubectl_input.read(cx).value().to_string(),
            ..Settings::default()
        }
        .kubectl_program()
    }

    /// Asks kubectl for the clusters, then for the namespaces of the one that is selected.
    fn load_contexts(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.generation += 1;
        let generation = self.generation;
        self.contexts = Listing::Loading;
        self.namespaces = Listing::Idle;
        self.kubectl_loaded = self.kubectl_input.read(cx).value().to_string();
        let runner = self.admin.runner.clone();
        let kubectl = self.kubectl_program(cx);
        let saved = self.admin.settings.context.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let contexts = admin::list_contexts(&runner, &kubectl)?;
                    let current = if contexts.is_empty() {
                        None
                    } else {
                        admin::current_context(&runner, &kubectl)
                    };
                    Ok::<_, String>((contexts, current))
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                if this.generation != generation {
                    return;
                }
                match result {
                    Ok((contexts, current)) if !contexts.is_empty() => {
                        let picked = admin::pick_context(&saved, &contexts, current.as_deref());
                        this.show_contexts(contexts, picked.clone(), window, cx);
                        if let Some(context) = picked {
                            this.load_namespaces(context, window, cx);
                        }
                    }
                    Ok(_) => this.contexts = Listing::Listed(Vec::new()),
                    Err(error) => this.contexts = Listing::Failed(error),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Asks kubectl for the namespaces of one cluster. The text field stays when kubectl cannot list.
    fn load_namespaces(&mut self, context: String, window: &mut Window, cx: &mut Context<Self>) {
        self.generation += 1;
        let generation = self.generation;
        self.namespaces = Listing::Loading;
        let runner = self.admin.runner.clone();
        let kubectl = self.kubectl_program(cx);
        let saved = self.admin.settings.namespace.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { admin::list_namespaces(&runner, &kubectl, &context) })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                if this.generation != generation {
                    return;
                }
                match result {
                    Ok(list) => this.show_namespaces(list, &saved, window, cx),
                    Err(error) => this.namespaces = Listing::Failed(error),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn show_contexts(
        &mut self,
        contexts: Vec<String>,
        picked: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let items: Vec<SharedString> = contexts.iter().cloned().map(Into::into).collect();
        self.cluster.update(cx, |state, cx| {
            state.set_items(items, window, cx);
            match picked {
                Some(name) => state.set_selected_value(&SharedString::from(name), window, cx),
                None => state.set_selected_index(None, window, cx),
            }
        });
        self.contexts = Listing::Listed(contexts);
    }

    fn show_namespaces(
        &mut self,
        namespaces: Vec<String>,
        saved: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let picked = admin::pick_namespace(saved, &namespaces);
        let items: Vec<SharedString> = namespaces.iter().cloned().map(Into::into).collect();
        self.namespace.update(cx, |state, cx| {
            state.set_items(items, window, cx);
            match picked {
                Some(name) => state.set_selected_value(&SharedString::from(name), window, cx),
                None => state.set_selected_index(None, window, cx),
            }
        });
        self.namespaces = Listing::Listed(namespaces);
    }

    /// The settings the user chose: the dropdown values, or the text fields when kubectl gave no list.
    fn chosen(&self, cx: &App) -> Settings {
        let text = |input: &Entity<InputState>| input.read(cx).value().trim().to_owned();
        let selected = |choice: &Choice| {
            choice
                .read(cx)
                .selected_value()
                .map(ToString::to_string)
                .unwrap_or_default()
        };
        Settings {
            context: if self.contexts.items().is_some() {
                selected(&self.cluster)
            } else {
                text(&self.cluster_text)
            },
            namespace: if self.namespaces.items().is_some() {
                selected(&self.namespace)
            } else {
                text(&self.namespace_text)
            },
            kubectl: text(&self.kubectl_input),
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
                fn applied(admin: &Admin, written: Written) -> Result<Outcome, WriteError> {
                    // The gateway confirmed this write, so a failure from here on is not an unconfirmed write.
                    let active = admin.manifest(None).map_err(|error| WriteError::AfterWrite(format!("The manifest was saved, but reloading it failed ({error}). Refresh before you continue.")))?;
                    if admin::hash(&active) != written.hash { return Err(WriteError::AfterWrite("The manifest was saved, then another manifest became active. Reload and review the current manifest.".into())); }
                    // The write is confirmed. A failed history sync must not turn it into an unconfirmed write.
                    let (history, sync_problem) = match admin.sync() {
                        Ok(history) => (Some(history), None),
                        Err(error) => (None, Some(format!("The manifest was saved, but the history sync failed: {error}"))),
                    };
                    let notice = match (&written.overwritten, sync_problem) {
                        (Some(previous), problem) => Some([Some(format!("Another admin's manifest {previous} was active when you applied and is now replaced. It stays in the server history. Check History.")), problem].into_iter().flatten().collect::<Vec<_>>().join(" ")),
                        (None, problem) => problem,
                    };
                    Ok(Outcome::Applied(written, active, history, notice))
                }
                fn written(admin: &Admin, result: Result<Written, WriteError>) -> Result<Outcome, String> {
                    match result.and_then(|written| applied(admin, written)) {
                        Ok(outcome) => Ok(outcome),
                        Err(error) => Ok(Outcome::WriteFailed(error, admin.manifest(None).ok(), admin.gateway().ok())),
                    }
                }
                match operation {
                    Operation::Setup(settings) => {
                        if settings.context.trim().is_empty() || settings.namespace.trim().is_empty() {
                            return Err("Choose a cluster and a namespace.".into());
                        }
                        admin.use_settings(settings.clone());
                        let active = admin.manifest(None)?;
                        manifest::Form::parse(&active)?;
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
                        this.admin.use_settings(settings); this.active = active.clone(); this.replace_draft(active);
                        this.overview = Some(overview);
                        this.forget_results_gateway(window, cx);
                        let skipped = history.warnings.len();
                        this.history = Some(history);
                        this.show_draft(window, cx);
                        this.build_form(window, cx); this.screen = Screen::Overview;
                        this.status = (skipped > 0).then(|| format!("Skipped {skipped} backup file(s). See Manifest, then History."));
                    }
                    Ok(Outcome::Refresh(overview, active)) => {
                        match refresh_step(this.unread_field(), this.draft == this.active, this.active != active) {
                            RefreshStep::Rebuild => {
                                let edit = (this.active == active).then(|| this.fv.description_edit.take()).flatten();
                                this.replace_draft(active.clone());
                                this.fv.description_edit = edit;
                                this.show_draft(window, cx);
                                this.build_form(window, cx);
                            }
                            RefreshStep::Keep => {}
                            RefreshStep::Warn(field) => {
                                this.error = Some(format!("The manifest on the gateway changed. Fix {field} or discard your edits, then refresh again."));
                            }
                        }
                        this.active = active; this.overview = Some(overview); this.status = Some("Gateway and active manifest refreshed.".into());
                    }
                    Ok(Outcome::WriteFailed(error, stored, gateway)) => {
                        this.dialog = None;
                        this.error = Some(error.to_string());
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
                    Ok(Outcome::Applied(written, active, history, notice)) => {
                        let hash = written.hash;
                        this.active = active.clone(); this.replace_draft(active); this.dialog = None;
                        if history.is_some() { this.history = history; }
                        this.error = notice;
                        this.show_draft(window, cx);
                        this.build_form(window, cx);
                        if let Some(overview) = &mut this.overview { overview.gateway.manifest_hash = hash.clone(); }
                        this.status = Some("Saved. The gateway loads it within 10 seconds.".into());
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
        let muted = |text: String| note(text).text_size(px(12.));
        let cluster = match &self.contexts {
            Listing::Listed(list) if !list.is_empty() => Select::new(&self.cluster)
                .placeholder("Choose a cluster")
                .into_any_element(),
            Listing::Loading => muted("Reading kubectl contexts...".into()).into_any_element(),
            _ => Input::new(&self.cluster_text).into_any_element(),
        };
        let cluster_line = match &self.contexts {
            Listing::Listed(list) if list.is_empty() => {
                Some("No kubectl contexts found. Log in to your cluster first.".to_owned())
            }
            Listing::Failed(error) => Some(admin::short_error(error)),
            _ => None,
        };
        let namespace = match &self.namespaces {
            Listing::Listed(list) if !list.is_empty() => Select::new(&self.namespace)
                .placeholder("Choose a namespace")
                .into_any_element(),
            Listing::Loading => muted("Reading namespaces...".into()).into_any_element(),
            _ => Input::new(&self.namespace_text).into_any_element(),
        };
        let namespace_line = match &self.namespaces {
            Listing::Failed(error) => Some(admin::short_error(error)),
            _ => None,
        };
        let open_label = if cfg!(target_os = "macos") {
            "Open in Finder"
        } else if cfg!(windows) {
            "Open in Explorer"
        } else {
            "Open folder"
        };
        let mut view = column().max_w(px(640.)).gap(px(14.)).child(title("Where is your gateway?"))
            .child(div().text_color(rgb(INK_2)).child("The admin app uses your kubectl access. It saves a local backup before each manifest change and syncs the server history."))
            .child(column().gap_1p5().child(label("Cluster")).child(cluster).when_some(cluster_line, |field, line| field.child(muted(line))))
            .child(column().gap_1p5().child(label("Namespace")).child(namespace).when_some(namespace_line, |field, line| field.child(muted(line))))
            .child(column().gap_1p5().child(label("kubectl path (optional)")).child(Input::new(&self.kubectl_input)));
        if self.overview.is_some() {
            let folder = self.admin.backup_dir();
            view = view.child(
                column()
                    .gap_1p5()
                    .child(label("Local backup folder"))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .font_family(mono())
                                    .text_size(px(12.))
                                    .text_color(rgb(INK_2))
                                    .child(folder.display().to_string()),
                            )
                            .child(
                                Button::new("open-backup-folder")
                                    .label(open_label)
                                    .small()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if let Err(error) =
                                            runner::open_folder(&this.admin.backup_dir())
                                        {
                                            this.error = Some(error);
                                        }
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(muted(
                        "The app keeps backups here, one folder for each cluster and namespace."
                            .into(),
                    )),
            );
        }
        view.child(actions()
                .child(Button::new("reload-kube").label("Reload from kubectl").ghost().small().disabled(self.busy).on_click(cx.listener(|this, _, window, cx| this.load_contexts(window, cx))))
                .child(Button::new("save").label("Save and open").primary().disabled(!can_save(&self.contexts, &self.namespaces, self.busy)).on_click(cx.listener(|this, _, window, cx| {
                    let settings = this.chosen(cx);
                    this.run(Operation::Setup(settings), window, cx);
                }))))
            .child(column().gap_1()
                .child(runs("lists clusters with", "kubectl config get-contexts -o name"))
                .child(runs("and namespaces with", "kubectl get namespaces -o name --context <cluster>"))
                .child(runs("saving runs", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway status --json"))
                .child(runs("and", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway manifest history --json")))
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
        for (index, device) in admin::latest_results(&overview.devices)
            .into_iter()
            .enumerate()
        {
            let result = result_text(device.last_result.as_ref());
            let reasons = reasons_text(device.last_reasons.as_ref());
            let code = device.code.clone();
            results = results.child(
                result_row(
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
                )
                .id(("latest-result", index))
                .cursor_pointer()
                .hover(|row| row.bg(rgb(0xfaf8f4)))
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.show_device_results(code.clone(), window, cx);
                })),
            );
        }
        view.child(results)
            .child(column().gap_1().child(runs("runs", "kubectl get deploy/open-pact-gateway -o json")).child(runs("and", "kubectl exec deploy/open-pact-gateway -- open-pact-gateway devices list --json")))
    }

    fn manifest_history(&self, cx: &Context<Self>) -> Div {
        column()
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
            .child(self.history_screen(cx))
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
                                cx.reveal_path(&this.admin.backup_dir())
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
        for warning in &history.warnings {
            view = view.child(banner(warning.clone(), BAD, BAD_WASH));
        }
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
                                .w(px(140.))
                                .flex_none()
                                .whitespace_nowrap()
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
                    .child(note(format!("Saves the active TOML in {} first.", self.admin.backup_dir().display())))
                    .child(runs("runs", shell_line(&["kubectl", "exec", "-i", "deploy/open-pact-gateway", "--", "open-pact-gateway", "manifest", "set", &format!("--note={}", self.change_note.read(cx).value()), "--json"])))
                    .child(actions().child(close.label("Cancel")).child(Button::new("apply").label("Apply manifest").primary().disabled(!self.review_open()).on_click(cx.listener(|this, _, window, cx| {
                        if this.review_open() {
                            this.run(Operation::Apply(this.draft.clone(), this.change_note.read(cx).value().to_string(), admin::hash(&this.active)), window, cx);
                        }
                    }))));
            }
            Dialog::Restore(restore, text) => {
                let selected = restore.clone();
                view = view.child(heading("Restore this manifest?"))
                    .child(diff_view(&manifest::diff(&self.active, &text)))
                    .child(note("Devices must sign the restored manifest before sending results. The current active manifest is backed up first."))
                    .child(match &restore {
                        Restore::Server(version) => runs("runs", format!("kubectl exec deploy/open-pact-gateway -- open-pact-gateway manifest activate {} --json", version.version)),
                        Restore::Local(backup) => runs("restores", backup.path.display().to_string()),
                    })
                    .when(matches!(restore, Restore::Local(_)), |view| view.child(note(format!("Activates its server version if present; otherwise pipes this file to manifest set {} --json.", shell_quote(&format!("--note={}", admin::restore_note(&restore)))))))
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
                    shell_line(&self.admin.gateway_args(&["devices", action, &target]))
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
                                "kubectl exec deploy/open-pact-gateway -- open-pact-gateway invite --ttl {} {} --json",
                                shell_quote(&self.ttl),
                                shell_quote(&format!("--note={}", self.invitation_note.read(cx).value()))
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
        .child(div().w(px(160.)).flex_none().child("Time"))
        .child(div().w(px(220.)).flex_none().child("Device"))
        .child(div().w(px(190.)).flex_none().child("Result"))
        .child(div().flex_1().min_w_0().child("Reason"))
}

fn result_row(time: String, device: Div, result: &str, reasons: String) -> Div {
    div()
        .flex()
        .gap_3()
        .py(px(10.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .child(div().w(px(160.)).flex_none().child(time))
        .child(
            div()
                .w(px(220.))
                .flex_none()
                .min_w_0()
                .overflow_hidden()
                .child(device),
        )
        .child(
            div()
                .w(px(190.))
                .flex_none()
                .text_color(rgb(tone_text(result_tone(result))))
                .child(result.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
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
        .child(div().w(px(140.)).flex_none().child("Device code"))
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

impl AppView {
    /// The cluster and namespace this app reads, with the refresh button. The dot turns green once
    /// the cluster answered.
    fn connection(&self, cx: &Context<Self>) -> Div {
        let settings = &self.admin.settings;
        let tone = if self.overview.is_some() {
            Tone::Good
        } else {
            Tone::Idle
        };
        let (_, dot, _) = tone_colors(tone);
        let line = |text: String, color: u32, size: f32| {
            div()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .text_size(px(size))
                .text_color(rgb(color))
                .child(text)
        };
        div()
            .flex()
            .items_start()
            .gap(px(8.))
            .pl(px(6.))
            .pt(px(12.))
            .border_t_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .flex_none()
                    .mt(px(5.))
                    .size(px(7.))
                    .rounded_full()
                    .bg(rgb(dot)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(px(1.))
                    .child(
                        line(settings.context.clone(), INK, 12.5).font_weight(FontWeight::MEDIUM),
                    )
                    .child(line(settings.namespace.clone(), MUTED, 12.)),
            )
            .child(
                Button::new("refresh")
                    .icon(gpui_kit_assets::IconName::RefreshCw)
                    .ghost()
                    .xsmall()
                    .tooltip(format!(
                        "Refresh from {} / {}",
                        settings.context, settings.namespace
                    ))
                    .disabled(self.busy || self.overview.is_none())
                    .on_click(
                        cx.listener(|this, _, window, cx| this.run(Operation::Refresh, window, cx)),
                    ),
            )
    }
}

impl Render for AppView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let _ = (
            &self.editor_subscription,
            &self.setup_subscriptions,
            &self.results.subscriptions,
        );
        let content = match self.screen {
            Screen::Setup => self.setup_screen(cx),
            Screen::Overview => self.overview_screen(cx),
            Screen::Manifest if self.show_history => self.manifest_history(cx),
            Screen::Manifest => self.manifest_editor(cx),
            Screen::Devices => self.devices_screen(cx),
            Screen::Results => self.results_screen(cx),
        };
        let wide = self.screen == Screen::Results
            || (self.screen == Screen::Manifest && !self.show_history);
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
                    (Screen::Overview, "Overview", IconName::LayoutDashboard),
                    (Screen::Manifest, "Manifest", IconName::FileText),
                    (Screen::Devices, "Devices", IconName::HardDrive),
                    (Screen::Results, "Results", IconName::CircleCheck),
                    (Screen::Setup, "Settings", IconName::Settings),
                ]
                .into_iter()
                .enumerate()
                .map(|(i, (screen, name, icon))| {
                    nav_item_with_icon(("nav", i), Some(icon), name, self.screen == screen)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if this.busy || (screen != Screen::Setup && this.overview.is_none()) {
                                return;
                            }
                            if screen == Screen::Results {
                                this.open_results(window, cx);
                                return;
                            }
                            this.screen = screen;
                            cx.notify();
                        }))
                }),
            )
            .child(div().flex_1())
            .child(self.connection(cx));
        let mut main = if wide {
            div()
                .id("admin-main")
                .flex()
                .flex_1()
                .h_full()
                .min_w_0()
                .child(content)
        } else {
            column()
                .id("admin-main")
                .flex_1()
                .h_full()
                .min_w_0()
                .overflow_y_scroll()
                .gap(px(18.))
                .px(px(28.))
                .py(px(24.))
                .child(content)
        };
        if !wide {
            if let Some(status) = &self.status {
                main = main.child(note(status.clone()));
            }
            if let Some(error) = &self.error {
                main = main.child(banner(error.clone(), BAD, BAD_WASH));
            }
        }
        let mut root = div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0xffffff))
            .text_color(rgb(INK))
            .text_size(px(15.))
            .children(update_banner(
                &self.update,
                cx.listener(|this, _, _, cx| {
                    let runner = this.admin.runner.clone();
                    start_update(&mut this.update, cx, runner, |view| &mut view.update);
                }),
            ))
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
    runner::tool_path();
    let programs = runner::client::cli_candidates(std::env::current_exe().ok().as_deref());
    let settings = Settings::load();
    launch("open-pact admin", 1360., 860., move |window, cx| {
        cx.new(|cx| {
            let mut app = AppView::new(settings.clone().unwrap_or_default(), window, cx);
            app.load_contexts(window, cx);
            load_builtin_texts_later(programs, cx);
            let runner = app.admin.runner.clone();
            watch_updates(cx, runner, |view: &mut AppView| &mut view.update);
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

/// Loads the default texts after the window opens, so a slow CLI does not hold the window back.
/// Until they arrive, the panel shows the plain description and hides Reset text. The panel reads
/// the texts on each paint, so the view repaints when they arrive.
fn load_builtin_texts_later(programs: Vec<std::path::PathBuf>, cx: &mut Context<AppView>) {
    cx.spawn(async move |this, cx| {
        cx.background_executor()
            .spawn(async move {
                manifest::load_builtin_texts(&programs);
            })
            .await;
        this.update(cx, |_, cx| cx.notify()).ok();
    })
    .detach();
}

/// The default texts a snapshot scene uses when no CLI is installed. The text is a placeholder,
/// so the scenes do not carry the real text of the checks.
#[cfg(all(feature = "snapshot", target_os = "macos"))]
const SNAPSHOT_BUILTIN_TEXTS: &str = r#"[
  {"check": "builtin:disk_encryption@1", "id": "disk_encryption", "about": "Snapshot placeholder text."},
  {"check": "builtin:firewall@1", "id": "firewall", "about": "Snapshot placeholder text."},
  {"check": "builtin:screen_lock@1", "id": "screen_lock", "about": "Snapshot placeholder text."}
]"#;

#[cfg(all(feature = "snapshot", target_os = "macos"))]
fn snapshots(output: PathBuf) {
    let programs = runner::client::cli_candidates(std::env::current_exe().ok().as_deref());
    if !manifest::load_builtin_texts(&programs) {
        let texts = manifest::parse_builtin_texts(SNAPSHOT_BUILTIN_TEXTS)
            .expect("the snapshot placeholder texts are valid JSON");
        manifest::set_builtin_texts(texts);
    }
    for (name, screen, form, dialog) in [
        ("admin-setup", Screen::Setup, true, None),
        ("admin-h-settings", Screen::Setup, true, None),
        ("admin-i-setup-fallback", Screen::Setup, true, None),
        ("admin-j-setup-no-contexts", Screen::Setup, true, None),
        ("admin-k-update", Screen::Overview, true, None),
        ("admin-l-devices", Screen::Devices, true, None),
        ("admin-t-results", Screen::Results, true, None),
        ("admin-u-result-detail", Screen::Results, true, None),
        ("admin-v-results-empty", Screen::Results, true, None),
        ("admin-a-overview", Screen::Overview, true, None),
        ("admin-b-form", Screen::Manifest, true, None),
        ("admin-w-sending-both", Screen::Manifest, true, None),
        ("admin-x-description-edit", Screen::Manifest, true, None),
        ("admin-c-toml", Screen::Manifest, false, None),
        ("admin-m-number-check", Screen::Manifest, true, None),
        ("admin-n-add-check", Screen::Manifest, true, None),
        ("admin-o-field-errors", Screen::Manifest, true, None),
        ("admin-p-add-check-all", Screen::Manifest, true, None),
        ("admin-q-add-check-scrolled", Screen::Manifest, true, None),
        ("admin-r-old-cli", Screen::Manifest, true, None),
        ("admin-s-check-line", Screen::Manifest, false, None),
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
        let (width, height) = if screen == Screen::Results {
            (1440., 880.)
        } else if matches!(name, "admin-p-add-check-all" | "admin-q-add-check-scrolled") {
            (1360., 860.)
        } else if screen == Screen::Manifest {
            (
                1440.,
                if matches!(
                    name,
                    "admin-b-form"
                        | "admin-x-description-edit"
                        | "admin-w-sending-both"
                        | "admin-m-number-check"
                        | "admin-n-add-check"
                        | "admin-o-field-errors"
                ) {
                    1700.
                } else {
                    880.
                },
            )
        } else {
            (1040., 800.)
        };
        snapshot(&output, name, width, height, |window, cx| {
            cx.new(|cx| {
            let mut app = AppView::new(Settings { context: "test-cluster".into(), namespace: "open-pact".into(), ..Settings::default() }, window, cx);
            app.admin.backup_root = "/fictional/backups".into();
            app.screen = screen; app.form = form; app.dialog = dialog;
            app.show_history = name == "admin-f-history";
            if name == "admin-k-update" { app.update = UpdateState::Available("0.1.1".into()); }
                app.active = include_str!("../../../tests/fixtures/manifest.toml").into();
                app.draft = app.active.clone();
            if matches!(name, "admin-d-apply" | "admin-b-form" | "admin-x-description-edit" | "admin-w-sending-both" | "admin-m-number-check" | "admin-n-add-check" | "admin-o-field-errors" | "admin-p-add-check-all" | "admin-q-add-check-scrolled" | "admin-r-old-cli" | "admin-s-check-line") { app.draft = include_str!("../../../tests/fixtures/manifest-v2.toml").into(); }
            if name == "admin-w-sending-both" {
                app.draft = format!("{}
[schedule.always]
interval = \"24h\"
", app.draft.trim_end());
            }
            if name == "admin-o-field-errors" {
                app.draft = app.draft
                    .replace("windows = { max = 30 }, linux = { max = 30 } }\ngrace = \"1d\"\n\n[[control]]\nid = \"os_supported\"", "windows = { max = 3651 }, linux = { max = 30 } }\ngrace = \"1d\"\n\n[[control]]\nid = \"os_supported\"");
            }
            if matches!(name, "admin-p-add-check-all" | "admin-q-add-check-scrolled") {
                let text = &app.draft;
                let (head, tail) = (text.find("[[control]]"), text.find("[log]"));
                if let (Some(head), Some(tail)) = (head, tail) {
                    app.draft = format!("{}{}", &text[..head], &text[tail..]);
                }
            }
            if !form && name != "admin-s-check-line" { app.draft = include_str!("../../../tests/fixtures/manifest-v2.toml").replace("issuer = \"Example Company, IT security\"", "issuer = \"Example Company, IT security"); }
            app.fv.selected = match name { "admin-m-number-check" | "admin-o-field-errors" => Some("os_patch_age_days".to_owned()), "admin-b-form" | "admin-n-add-check" | "admin-x-description-edit" => Some("screen_lock".to_owned()), _ => None };
            app.fv.add_open = matches!(name, "admin-n-add-check" | "admin-p-add-check-all" | "admin-q-add-check-scrolled");
            app.fv.manual_check = true;
            app.show_draft(window, cx);
            app.build_form(window, cx);
            app.fv.set_check(&app.draft, snapshot_check(name, &app.draft));
            app.mark_lines(cx);
            if name == "admin-x-description-edit" { app.open_description_edit(window, cx); }
            if name == "admin-o-field-errors" { app.type_valid_from("garbage", window, cx); }
            if matches!(name, "admin-p-add-check-all" | "admin-q-add-check-scrolled") { app.fv.scroll.set_offset(point(px(0.), px(-1000.))); }
            if name == "admin-q-add-check-scrolled" { app.fv.add_scroll.set_offset(point(px(0.), px(-5000.))); }
            app.overview = Some(Overview {
                gateway: serde_json::from_str(include_str!("../../../tests/fixtures/gateway.json")).unwrap(),
                devices: serde_json::from_str(include_str!("../../../tests/fixtures/devices.json")).unwrap(),
                deployment: serde_json::json!({"status":{"conditions":[{"type":"Available","status":"True"}]}}),
            });
            app.history = Some(History { versions: serde_json::from_str(include_str!("../../../tests/fixtures/history.json")).unwrap(), backups: vec![admin::Backup { path: "/fictional/backups/20261116T100000Z-v1-example.toml".into(), manifest_hash: admin::hash(&app.active) }], synced_at: "2026-11-16T12:30:00Z".into(), warnings: if name == "admin-f-history" { vec!["Skipped backup 20261116T101500.000Z-0123456789ab.toml: its content does not match the hash in its name. Move it out of the folder and sync again.".into()] } else { Vec::new() } });
            if screen == Screen::Results {
                use runner::results::{ClaimDetail, ClaimList, Filters, Period, ResultFilter};
                let now = "2026-11-16T12:00:00Z".parse().unwrap();
                let mut list: ClaimList = serde_json::from_str(include_str!("../../../tests/fixtures/claims.json")).unwrap();
                let test_a = Some("7c09e1f4a2b8".to_owned());
                let filters = match name {
                    "admin-t-results" => Filters { period: Period::Month, ..Filters::default() },
                    "admin-u-result-detail" => Filters { device: test_a.clone(), ..Filters::default() },
                    _ => Filters { device: test_a.clone(), result: ResultFilter::Denied, period: Period::Day },
                };
                match name {
                    "admin-u-result-detail" => list.claims.retain(|claim| Some(claim.code()) == test_a),
                    "admin-v-results-empty" => { list.claims.clear(); list.unreadable = 0; }
                    _ => (),
                }
                app.results.state.command = Admin::claims_command(&filters, now);
                app.results.state.filters = filters;
                app.results.state.list = results::Fetch::Ready(list);
                if name == "admin-u-result-detail" {
                    app.results.state.selected = Some(4814);
                    let detail: ClaimDetail = serde_json::from_str(include_str!("../../../tests/fixtures/claim.json")).unwrap();
                    app.results.state.detail = results::Fetch::Ready(detail);
                }
                app.sync_result_devices(window, cx);
            }
            if matches!(name, "admin-setup" | "admin-h-settings" | "admin-i-setup-fallback" | "admin-j-setup-no-contexts") {
                let clusters: Vec<String> = ["test-cluster", "staging-cluster", "prod-cluster"].map(String::from).into();
                match name {
                    "admin-j-setup-no-contexts" => app.contexts = Listing::Listed(Vec::new()),
                    _ => {
                        let picked = admin::pick_context(if name == "admin-setup" { "" } else { "test-cluster" }, &clusters, Some("staging-cluster"));
                        app.show_contexts(clusters, picked, window, cx);
                        if name == "admin-i-setup-fallback" {
                            app.namespaces = Listing::Failed("Error from server (Forbidden): namespaces is forbidden: User \"fictional-user\" cannot list resource \"namespaces\" in API group \"\" at the cluster scope".into());
                        } else {
                            let namespaces: Vec<String> = ["default", "kube-system", "open-pact", "open-pact-staging"].map(String::from).into();
                            app.show_namespaces(namespaces, "open-pact", window, cx);
                        }
                    }
                }
                if name == "admin-setup" || name == "admin-i-setup-fallback" || name == "admin-j-setup-no-contexts" {
                    app.overview = None;
                }
            }
            app
        })
        });
    }
}

/// What the open-pact CLI would say about the draft of a snapshot scene.
#[cfg(all(feature = "snapshot", target_os = "macos"))]
fn snapshot_check(name: &str, draft: &str) -> Result<Vec<runner::admin::CheckError>, String> {
    use runner::admin::{CLI_TOO_OLD, CheckError};
    Ok(match name {
        "admin-o-field-errors" => vec![CheckError {
            message:
                "os_patch_age_days: required.windows 3651 is above the output range 0 to 3650."
                    .into(),
            line: None,
            key: Some("controls.os_patch_age_days.required.windows".into()),
        }],
        "admin-r-old-cli" => vec![CheckError {
            message: CLI_TOO_OLD.into(),
            line: None,
            key: None,
        }],
        "admin-s-check-line" => vec![CheckError {
            message: "invalid date, expected YYYY-MM-DD".into(),
            line: draft
                .lines()
                .position(|line| line.starts_with("valid_from"))
                .map(|index| index + 1),
            key: None,
        }],
        _ => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Listing, RefreshStep, can_save, refresh_step};

    #[test]
    fn a_refresh_keeps_unread_input_and_says_when_the_gateway_changed() {
        let field = Some("Valid from".to_owned());
        assert_eq!(refresh_step(field.clone(), true, false), RefreshStep::Keep);
        assert_eq!(refresh_step(field.clone(), false, false), RefreshStep::Keep);
        assert_eq!(
            refresh_step(field.clone(), true, true),
            RefreshStep::Warn("Valid from".to_owned())
        );
        assert_eq!(
            refresh_step(field, false, true),
            RefreshStep::Warn("Valid from".to_owned())
        );
    }

    #[test]
    fn a_refresh_without_unread_input_takes_the_gateway_only_into_an_active_draft() {
        assert_eq!(refresh_step(None, true, true), RefreshStep::Rebuild);
        assert_eq!(refresh_step(None, true, false), RefreshStep::Rebuild);
        assert_eq!(refresh_step(None, false, true), RefreshStep::Keep);
    }

    #[test]
    fn save_waits_while_kubectl_lists_namespaces() {
        let listed = Listing::Listed(vec!["open-pact".to_owned()]);
        assert!(!can_save(&listed, &Listing::Loading, false));
        assert!(!can_save(&listed, &listed, true));
        assert!(can_save(&listed, &listed, false));
        assert!(can_save(
            &listed,
            &Listing::Failed("forbidden".to_owned()),
            false
        ));
        assert!(can_save(&Listing::Idle, &Listing::Idle, false));
    }

    #[test]
    fn save_waits_while_kubectl_lists_clusters() {
        let listed = Listing::Listed(vec!["open-pact".to_owned()]);
        assert!(!can_save(&Listing::Loading, &Listing::Idle, false));
        assert!(!can_save(&Listing::Loading, &listed, false));
        assert!(can_save(
            &Listing::Failed("no kubectl".to_owned()),
            &Listing::Idle,
            false
        ));
        assert!(can_save(
            &Listing::Listed(Vec::new()),
            &Listing::Idle,
            false
        ));
    }
}
