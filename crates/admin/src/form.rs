//! The Manifest screen: the Form view with its sections, check table and panel, and the TOML view.
//! Both edit the same text, `AppView::draft`. Every form edit rewrites it with toml_edit.
use super::*;
use gpui_component::{
    date_picker::{DatePicker, DatePickerEvent, DatePickerState},
    h_resizable,
    highlighter::{Diagnostic, DiagnosticSeverity},
    input::{Editor, Position, Textarea, TextareaState},
    resizable_panel,
    switch::Switch,
};
use runner::manifest::{
    self, Control, Field, FieldError, Filter, Form, ManifestCheck, Os, Output, Pending, Problems,
    Requirement, Span, TRUST_LEVELS, Unit,
};
use std::{cell::Cell, rc::Rc, time::Duration};

/// How long the draft stays unchanged before the CLI is asked about it.
const CHECK_AFTER: Duration = Duration::from_millis(300);

type Units = Entity<SelectState<Vec<SharedString>>>;
/// Turns the app state and a new value into the new draft.
type Apply = Rc<dyn Fn(&AppView, &str) -> Result<String, String>>;

const SPANS: &[Unit] = &Unit::SPANS;
const INTERVALS: &[Unit] = &Unit::INTERVALS;
const HOURS: &[Unit] = &[Unit::Hour];

/// The units of an any-network interval: hours, or the units its stored value needs.
fn always_units(raw: &str) -> &'static [Unit] {
    match Span::parse(raw) {
        Some(span) if span.unit == Unit::Minute => INTERVALS,
        Some(span) if span.unit != Unit::Hour => SPANS,
        _ => HOURS,
    }
}
/// How far from the Add check button its options open, the gap kept to the window edge, and the
/// least height the options get.
const POPOVER_TOP: f32 = 40.;
const POPOVER_MARGIN: f32 = 12.;
const POPOVER_MIN: f32 = 200.;

/// Where the Add check options open and how tall they may be.
#[derive(Debug, PartialEq)]
struct PopoverPlace {
    above: bool,
    height: f32,
}

/// The options open below the button with the window height minus their top, never under 200 px.
/// When that leaves less than 200 px and the room above the button is larger, they open above.
fn popover_place(window_height: f32, button_top: f32) -> PopoverPlace {
    let below = window_height - (button_top + POPOVER_TOP) - POPOVER_MARGIN;
    let above = button_top - (POPOVER_TOP - 32.) - POPOVER_MARGIN;
    if below >= POPOVER_MIN || below >= above {
        PopoverPlace {
            above: false,
            height: below.max(POPOVER_MIN),
        }
    } else {
        PopoverPlace {
            above: true,
            height: above.max(POPOVER_MIN),
        }
    }
}
const CHIP: u32 = 0xefebe3;
const ROW_HOVER: u32 = 0xfaf8f4;
const PANEL_BG: u32 = 0xfbfaf7;

/// Which inputs an edit makes again from the new text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rebuild {
    No,
    /// The inputs of the form, not the panel of the selected check.
    Inputs,
    All,
}

/// The field a duration input edits. A check's panel looks it up when the input changes, because
/// the check may have a new ID by then.
type FieldOf = Rc<dyn Fn(&AppView) -> Option<Field>>;

pub struct DurationField {
    amount: Entity<InputState>,
    unit: Units,
}

struct DurationSpec {
    raw: String,
    units: &'static [Unit],
    panel: bool,
    field: FieldOf,
    /// An input that holds text the form could not read yet. It stays.
    reuse: Option<DurationField>,
}

pub struct FormInputs {
    issuer: Entity<InputState>,
    valid_from: Entity<DatePickerState>,
    controller: Entity<InputState>,
    max_age: DurationField,
    retention: DurationField,
    unknown_grace: DurationField,
    /// The inputs of the VPN part, while it is on.
    vpn: Option<VpnInputs>,
    /// The inputs of the any-network part, while it is on.
    always: Option<AlwaysInputs>,
}

pub struct VpnInputs {
    probe: Entity<InputState>,
    probe_name: Entity<InputState>,
    check: DurationField,
    interval: DurationField,
}

pub struct AlwaysInputs {
    interval: DurationField,
}

impl FormInputs {
    /// The duration input of a field, when the form has one for it.
    fn duration(&self, field: &Field) -> Option<&DurationField> {
        match field {
            Field::MaxAge => Some(&self.max_age),
            Field::Retention => Some(&self.retention),
            Field::UnknownGrace => Some(&self.unknown_grace),
            Field::VpnCheck => self.vpn.as_ref().map(|vpn| &vpn.check),
            Field::VpnInterval => self.vpn.as_ref().map(|vpn| &vpn.interval),
            Field::AlwaysInterval => self.always.as_ref().map(|always| &always.interval),
            _ => None,
        }
    }
}

enum Pick {
    Value(String),
    Reported,
    Keep,
}

enum OsInput {
    Choice(Units),
    Limit(Entity<InputState>),
}

pub struct Panel {
    /// None for a built-in check: its ID is fixed.
    id: Option<Entity<InputState>>,
    reference: Entity<InputState>,
    description: Entity<TextareaState>,
    /// The Description shows the editor. Otherwise it shows the text as read-only.
    editing: bool,
    os: [OsInput; 3],
    /// A number field is open for this OS before any number is typed.
    opened: [bool; 3],
    grace: DurationField,
}

pub struct FormState {
    pub inputs: Option<FormInputs>,
    pub panel: Option<Panel>,
    /// The id of the selected check.
    pub selected: Option<String>,
    /// The Description edit that is open: the check id and the text in its editor. A panel
    /// rebuilt for that check reopens the editor with this text.
    pub description_edit: Option<(String, String)>,
    pub filter: Filter,
    pub add_open: bool,
    /// Input the form could not read yet, one message per field.
    pub pending: Pending,
    /// What the open-pact CLI said about the draft.
    pub check: ManifestCheck,
    /// Tests and snapshots set the answer themselves, so no CLI runs.
    pub manual_check: bool,
    /// Where the Add check button was in the last paint: its top and the window height.
    add_anchor: Rc<Cell<(f32, f32)>>,
    pub adding_recipient: bool,
    /// The values of the sending parts that are off. The session keeps them, so that a part that
    /// is turned on again gets its old values back.
    pub sends_kept: manifest::KeptSends,
    /// The schedule of the last raw text that parsed. A syntax error in the middle of typing is
    /// not a schedule change.
    pub sends_seen: manifest::SeenSchedule,
    pub jump: usize,
    pub scroll: ScrollHandle,
    /// The scroll position of the Add check options.
    pub add_scroll: ScrollHandle,
    search: Entity<InputState>,
    add_search: Entity<InputState>,
    chip: Entity<InputState>,
    subs: Vec<Subscription>,
    panel_subs: Vec<Subscription>,
    _permanent: Vec<Subscription>,
}

impl FormState {
    /// Sets the answer of the CLI for `draft`, as a snapshot scene needs it.
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    pub fn set_check(
        &mut self,
        draft: &str,
        outcome: Result<Vec<runner::admin::CheckError>, String>,
    ) {
        let generation = self.check.begin();
        self.check.finish(generation, draft, outcome);
    }

    pub fn new(window: &mut Window, cx: &mut Context<AppView>) -> Self {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Find a check"));
        let add_search = cx.new(|cx| InputState::new(window, cx).placeholder("Find a check"));
        let chip = cx.new(|cx| InputState::new(window, cx).placeholder("Who gets the results"));
        let permanent = vec![
            cx.subscribe(&search, |_, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            }),
            cx.subscribe(&add_search, |_, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            }),
            cx.subscribe_in(
                &chip,
                window,
                |this, chip, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        let name = chip.read(cx).value().trim().to_owned();
                        this.fv.adding_recipient = false;
                        chip.update(cx, |state, cx| state.set_value("", window, cx));
                        if !name.is_empty() {
                            let mut items = Form::parse(&this.draft)
                                .map(|form| form.recipients)
                                .unwrap_or_default();
                            if !items.contains(&name) {
                                items.push(name);
                            }
                            let result =
                                manifest::set_top_list(&this.draft, "claim_recipients", &items);
                            this.edit_form(result, Rebuild::No, window, cx);
                        }
                        cx.notify();
                    }
                },
            ),
        ];
        Self {
            inputs: None,
            sends_kept: manifest::KeptSends::default(),
            sends_seen: manifest::SeenSchedule::default(),
            panel: None,
            selected: None,
            description_edit: None,
            filter: Filter::All,
            add_open: false,
            pending: Pending::default(),
            check: ManifestCheck::default(),
            manual_check: false,
            add_anchor: Rc::new(Cell::new((0., 0.))),
            adding_recipient: false,
            jump: 0,
            scroll: ScrollHandle::new(),
            add_scroll: ScrollHandle::new(),
            search,
            add_search,
            chip,
            subs: Vec::new(),
            panel_subs: Vec::new(),
            _permanent: permanent,
        }
    }
}

fn unit_labels(units: &[Unit], amount: u64) -> Vec<SharedString> {
    units.iter().map(|unit| unit.name(amount).into()).collect()
}

fn unit_of(units: &[Unit], label: &str) -> Option<Unit> {
    units
        .iter()
        .copied()
        .find(|unit| unit.name(1) == label || unit.name(2) == label)
}

fn section(title: &'static str, why: &'static str, body: impl IntoElement) -> Div {
    div()
        .flex()
        .gap(px(24.))
        .py(px(20.))
        .border_b_1()
        .border_color(rgb(RULE))
        .child(
            div()
                .w(px(190.))
                .flex_none()
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(title),
                )
                .child(
                    div()
                        .mt(px(4.))
                        .max_w(px(190.))
                        .text_size(px(13.))
                        .text_color(rgb(MUTED))
                        .child(why),
                ),
        )
        .child(div().flex_1().min_w_0().child(body))
}

fn kv_row(key: &'static str, control: impl IntoElement) -> Div {
    kv_row_error(key, control, None)
}

/// A line under a field that says why the form refuses its value.
fn error_line(message: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(12.5))
        .text_color(rgb(BAD))
        .child(message.into())
}

/// The draft after the Valid from picker changes. A picked day is written as YYYY-MM-DD. A
/// cleared picker writes an empty date, so the old date leaves the draft and the CLI refuses the
/// field.
fn valid_from_draft(draft: &str, picked: Option<String>) -> Result<String, String> {
    manifest::set_top_text(draft, "valid_from", &picked.unwrap_or_default())
}

/// The first message for a field. Unparsed input comes before what the manifest check finds.
fn error_of(issues: &[FieldError], field: &Field) -> Option<String> {
    issues
        .iter()
        .find(|issue| issue.field == *field)
        .map(|issue| issue.message.clone())
}

fn kv_row_error(key: &'static str, control: impl IntoElement, error: Option<String>) -> Div {
    let failed = error.is_some();
    div()
        .flex()
        .items_center()
        .gap(px(16.))
        .when(failed, |row| row.items_start())
        .child(
            div()
                .w(px(150.))
                .flex_none()
                .text_size(px(13.))
                .text_color(rgb(INK_2))
                .when(failed, |name| name.pt(px(7.)))
                .child(key),
        )
        .child(match error {
            Some(error) => column()
                .gap(px(4.))
                .child(control)
                .child(error_line(error))
                .into_any_element(),
            None => control.into_any_element(),
        })
}

/// One part of the sending section: its heading with the on or off switch, then its rows.
fn send_part(title: &'static str, switch: impl IntoElement) -> Div {
    div().flex().flex_col().gap(px(12.)).child(
        div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(INK_2))
                    .child(title),
            )
            .child(switch),
    )
}

fn rows(items: Vec<Div>) -> Div {
    div().flex().flex_col().gap(px(10.)).children(items)
}

fn seg2_item(id: impl Into<ElementId>, text: impl Into<SharedString>, on: bool) -> Stateful<Div> {
    div()
        .id(id)
        .px(px(12.))
        .py(px(6.))
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .whitespace_nowrap()
        .cursor_pointer()
        .border_r_1()
        .border_color(rgb(0xe3ded3))
        .when(on, |item| item.bg(rgb(BLUE_WASH)).text_color(rgb(BLUE_INK)))
        .when(!on, |item| item.text_color(rgb(INK_2)))
        .child(text.into())
}

fn seg2(items: Vec<Stateful<Div>>) -> Div {
    div()
        .flex()
        .self_start()
        .overflow_hidden()
        .rounded(px(7.))
        .border_1()
        .border_color(rgb(FIELD_BORDER))
        .bg(rgb(0xffffff))
        .children(items)
}

/// The square of the design's checkbox lists, drawn here so it needs no icon asset.
fn check_box(id: impl Into<ElementId>, on: bool) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .mt(px(1.))
        .size(px(18.))
        .rounded(px(5.))
        .border_2()
        .cursor_pointer()
        .text_size(px(12.))
        .font_weight(FontWeight::BOLD)
        .when(on, |square| {
            square
                .bg(rgb(BLUE))
                .border_color(rgb(BLUE))
                .text_color(rgb(0xffffff))
                .child("✓")
        })
        .when(!on, |square| square.border_color(rgb(0xb9b1a2)))
}

fn small(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(13.))
        .text_color(rgb(MUTED))
        .child(text.into())
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

impl AppView {
    /// Replaces the whole draft, as Setup, Refresh, Apply, Restore and Discard do. The sending
    /// values and an open description edit belong to the draft before, so they go too.
    pub fn replace_draft(&mut self, text: String) {
        self.draft = text;
        self.fv.description_edit = None;
        self.fv.sends_kept.forget();
        self.fv.sends_seen.forget();
    }

    /// Applies an edit of the form to the draft. `rebuild` says which inputs the new text makes
    /// again, for edits that change which inputs exist.
    pub fn edit_form(
        &mut self,
        result: Result<String, String>,
        rebuild: Rebuild,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok(text) => {
                self.error = None;
                self.draft = text;
                self.show_draft(window, cx);
                match rebuild {
                    Rebuild::No => (),
                    Rebuild::Inputs => self.make_inputs(window, cx),
                    Rebuild::All => self.refresh_form(window, cx),
                }
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    /// An edit of one input. A good value clears the error of that field only. A bad one leaves
    /// the draft as it is and marks the field until its input is fixed.
    fn edit_field(
        &mut self,
        field: Field,
        result: Result<String, String>,
        rebuild: Rebuild,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok(text) => {
                self.fv.pending.record(field, Ok(()));
                self.edit_form(Ok(text), rebuild, window, cx);
            }
            Err(message) => {
                self.fv.pending.record(field, Err(message));
                cx.notify();
            }
        }
    }

    /// Puts the draft into the TOML editor, marks the lines the parser and the CLI refuse in it,
    /// and asks the CLI about the draft.
    pub fn show_draft(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let draft = self.draft.clone();
        self.editor.update(cx, |state, cx| {
            if state.value().as_ref() != draft {
                state.set_value(draft, window, cx);
            }
        });
        self.mark_lines(cx);
        self.check_draft(window, cx);
    }

    /// Marks the line of a parse error and the line of each CLI error that has one.
    pub fn mark_lines(&mut self, cx: &mut Context<Self>) {
        let draft = self.draft.clone();
        let mut marks: Vec<(usize, String)> = Vec::new();
        match draft.parse::<toml_edit::DocumentMut>() {
            Err(error) => marks.push((
                manifest::error_line(&draft, &error),
                error.message().to_owned(),
            )),
            Ok(_) => marks.extend(
                self.fv
                    .check
                    .result(&draft)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|error| Some((error.line?, error.message))),
            ),
        }
        self.editor.update(cx, |state, cx| {
            let text = state.text().clone();
            if let Some(diagnostics) = state.diagnostics_mut() {
                diagnostics.reset(&text);
                let last = draft.lines().count().saturating_sub(1);
                for (line, message) in marks {
                    let line = line.saturating_sub(1).min(last);
                    let width = draft.lines().nth(line).map_or(1, |l| l.chars().count()) as u32;
                    let line = line as u32;
                    diagnostics.push(
                        Diagnostic::new(
                            Position::new(line, 0)..Position::new(line, width.max(1)),
                            message,
                        )
                        .with_severity(DiagnosticSeverity::Error),
                    );
                }
            }
            cx.notify();
        });
    }

    /// Asks the CLI about the draft once it has stayed the same for a moment. An answer that
    /// arrives after the draft changed again is dropped.
    fn check_draft(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.fv.manual_check {
            return;
        }
        let generation = self.fv.check.begin();
        let draft = self.draft.clone();
        if draft.parse::<toml_edit::DocumentMut>().is_err() {
            return;
        }
        let admin = self.admin.clone();
        cx.spawn_in(window, async move |this, cx| {
            cx.background_executor().timer(CHECK_AFTER).await;
            let current = this
                .update(cx, |this, _| this.fv.check.is_current(generation))
                .unwrap_or(false);
            if !current {
                return;
            }
            let asked = draft.clone();
            let outcome = cx
                .background_executor()
                .spawn(async move { admin.check_manifest(&asked) })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.fv.check.finish(generation, &draft, outcome) {
                    this.mark_lines(cx);
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Everything that stops a review of this draft.
    fn problems(&self) -> Problems {
        manifest::problems(
            &self.fv.pending,
            &self.fv.check.result(&self.draft).unwrap_or_default(),
        )
    }

    fn bind_text(
        &mut self,
        input: &Entity<InputState>,
        field: Option<Field>,
        apply: Apply,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let subscription = cx.subscribe_in(
            input,
            window,
            move |this, input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let value = input.read(cx).value().to_string();
                    let result = apply(this, &value);
                    match &field {
                        Some(field) => {
                            this.edit_field(field.clone(), result, Rebuild::No, window, cx)
                        }
                        None => this.edit_form(result, Rebuild::No, window, cx),
                    }
                }
            },
        );
        self.fv.subs.push(subscription);
    }

    /// A date picker for Valid from, set to the date of `value` when it has one. Picking a date
    /// writes it to the draft as YYYY-MM-DD.
    fn date_picker(
        &mut self,
        value: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<DatePickerState> {
        let picker = cx.new(|cx| DatePickerState::new(window, cx).date_format("%-d %b %Y"));
        if let Some(day) = manifest::parse_date(value).and_then(|date| date.and_hms_opt(0, 0, 0)) {
            picker.update(cx, |state, cx| state.set_date_time(day, window, cx));
        }
        let subscription = cx.subscribe_in(
            &picker,
            window,
            |this, _, event: &DatePickerEvent, window, cx| {
                let DatePickerEvent::Change(value) = event;
                let picked = value.start().map(|day| day.format("%Y-%m-%d").to_string());
                let result = valid_from_draft(&this.draft, picked);
                this.edit_field(Field::ValidFrom, result, Rebuild::No, window, cx);
            },
        );
        self.fv.subs.push(subscription);
        picker
    }

    fn text_input(
        &mut self,
        value: &str,
        field: Option<Field>,
        apply: Apply,
        reuse: Option<Entity<InputState>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        let input = reuse.unwrap_or_else(|| {
            cx.new(|cx| InputState::new(window, cx).default_value(value.to_owned()))
        });
        self.bind_text(&input, field, apply, window, cx);
        input
    }

    fn duration_field(
        &mut self,
        spec: DurationSpec,
        apply: Apply,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> DurationField {
        let DurationSpec {
            raw,
            units,
            panel,
            field,
            reuse,
        } = spec;
        let (amount, unit) = match reuse {
            Some(held) => (held.amount, held.unit),
            None => {
                let span = Span::parse(&raw).filter(|span| units.contains(&span.unit));
                let amount = cx.new(|cx| {
                    InputState::new(window, cx)
                        .default_value(span.map(|span| span.amount.to_string()).unwrap_or_default())
                });
                let unit = cx.new(|cx| {
                    SelectState::new(
                        unit_labels(units, span.map_or(0, |s| s.amount)),
                        None,
                        window,
                        cx,
                    )
                });
                if let Some(span) = span {
                    unit.update(cx, |state, cx| {
                        state.set_selected_value(
                            &SharedString::from(span.unit.name(span.amount)),
                            window,
                            cx,
                        )
                    });
                }
                (amount, unit)
            }
        };
        let changed = {
            let (amount, unit) = (amount.clone(), unit.clone());
            move |this: &mut AppView, window: &mut Window, cx: &mut Context<AppView>| {
                let Some(field) = field(this) else {
                    return;
                };
                let typed = amount.read(cx).value().trim().to_owned();
                let Ok(count) = typed.parse::<u64>() else {
                    this.fv
                        .pending
                        .record(field, Err("Type a whole number.".into()));
                    cx.notify();
                    return;
                };
                let chosen = unit
                    .read(cx)
                    .selected_value()
                    .and_then(|label| unit_of(units, label))
                    .unwrap_or(units[usize::from(units.len() > 1 && !panel)]);
                let text = Span {
                    amount: count,
                    unit: chosen,
                }
                .print();
                let result = apply(this, &text);
                this.edit_field(field, result, Rebuild::No, window, cx);
                unit.update(cx, |state, cx| {
                    state.set_items(unit_labels(units, count), window, cx);
                    state.set_selected_value(&SharedString::from(chosen.name(count)), window, cx);
                });
            }
        };
        let on_amount = changed.clone();
        let subs = [
            cx.subscribe_in(
                &amount,
                window,
                move |this, _, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::Change) {
                        on_amount(this, window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &unit,
                window,
                move |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                    if matches!(event, SelectEvent::Confirm(Some(_))) {
                        changed(this, window, cx);
                    }
                },
            ),
        ];
        let target = if panel {
            &mut self.fv.panel_subs
        } else {
            &mut self.fv.subs
        };
        target.extend(subs);
        DurationField { amount, unit }
    }

    fn top_span(
        &mut self,
        raw: &str,
        key: &'static str,
        field: Field,
        reuse: Option<DurationField>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> DurationField {
        let spec = DurationSpec {
            raw: raw.to_owned(),
            units: SPANS,
            panel: false,
            field: Rc::new(move |_| Some(field.clone())),
            reuse,
        };
        self.duration_field(
            spec,
            Rc::new(move |this, value| manifest::set_top_text(&this.draft, key, value)),
            window,
            cx,
        )
    }

    /// Makes every input again from the draft and forgets the text no input could read.
    pub fn build_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.fv.pending.clear();
        self.fv.inputs = None;
        self.refresh_form(window, cx);
    }

    /// Makes the inputs of the form and the panel again, and keeps the inputs that hold text the
    /// form could not read, so an edit elsewhere never drops it.
    fn refresh_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.make_inputs(window, cx);
        self.build_panel(window, cx);
    }

    fn make_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.fv.subs.clear();
        let kept = self.fv.inputs.take();
        let Ok(form) = Form::parse(&self.draft) else {
            self.fv.pending.clear();
            self.fv.panel = None;
            self.fv.panel_subs.clear();
            return;
        };
        self.fv.pending.drop_absent_sends(form.schedule.as_ref());
        let held = self.fv.pending.clone();
        let reuse = |field: Field| -> Option<DurationField> {
            kept.as_ref()
                .filter(|_| held.get(&field).is_some())
                .and_then(|inputs| inputs.duration(&field))
                .map(|duration| DurationField {
                    amount: duration.amount.clone(),
                    unit: duration.unit.clone(),
                })
        };
        let kept_max_age = reuse(Field::MaxAge);
        let kept_retention = reuse(Field::Retention);
        let kept_unknown_grace = reuse(Field::UnknownGrace);
        let kept_check = reuse(Field::VpnCheck);
        let kept_vpn_interval = reuse(Field::VpnInterval);
        let kept_always_interval = reuse(Field::AlwaysInterval);
        for (field, stays) in [
            (Field::MaxAge, kept_max_age.is_some()),
            (Field::Retention, kept_retention.is_some()),
            (Field::UnknownGrace, kept_unknown_grace.is_some()),
            (Field::VpnCheck, kept_check.is_some()),
            (Field::VpnInterval, kept_vpn_interval.is_some()),
            (Field::AlwaysInterval, kept_always_interval.is_some()),
        ] {
            if !stays {
                self.fv.pending.record(field, Ok(()));
            }
        }
        let top = |key: &'static str| -> Apply {
            Rc::new(move |this, value| manifest::set_top_text(&this.draft, key, value))
        };
        let issuer = self.text_input(&form.issuer, None, top("issuer"), None, window, cx);
        let controller = self.text_input(
            &form.data_controller,
            None,
            top("data_controller"),
            None,
            window,
            cx,
        );
        match manifest::parse_date(&form.valid_from) {
            Some(_) => self.fv.pending.record(Field::ValidFrom, Ok(())),
            None if form.valid_from.is_empty() => self.fv.pending.record(Field::ValidFrom, Ok(())),
            None => self.fv.pending.record(
                Field::ValidFrom,
                Err(format!(
                    "Pick a date. The draft has \"{}\" here.",
                    form.valid_from
                )),
            ),
        }
        let valid_from = self.date_picker(&form.valid_from, window, cx);
        let max_age = self.top_span(
            &form.max_age,
            "claim_max_age",
            Field::MaxAge,
            kept_max_age,
            window,
            cx,
        );
        let retention = self.top_span(
            &form.retention,
            "claim_retention",
            Field::Retention,
            kept_retention,
            window,
            cx,
        );
        let unknown_grace = self.top_span(
            &form.unknown_grace,
            "unknown_grace",
            Field::UnknownGrace,
            kept_unknown_grace,
            window,
            cx,
        );
        let send = |part: manifest::SendPart, key: &'static str| -> Apply {
            Rc::new(move |this, value| manifest::set_send_text(&this.draft, part, key, value))
        };
        let vpn = match form.schedule.as_ref().and_then(|s| s.vpn.clone()) {
            Some(vpn) => {
                let probe = self.text_input(
                    &vpn.probe,
                    None,
                    send(manifest::SendPart::Vpn, "probe"),
                    None,
                    window,
                    cx,
                );
                let probe_name = self.text_input(
                    &vpn.name,
                    None,
                    send(manifest::SendPart::Vpn, "probe_name"),
                    None,
                    window,
                    cx,
                );
                let check = self.duration_field(
                    DurationSpec {
                        raw: vpn.check.clone(),
                        units: INTERVALS,
                        panel: false,
                        field: Rc::new(|_| Some(Field::VpnCheck)),
                        reuse: kept_check,
                    },
                    send(manifest::SendPart::Vpn, "check"),
                    window,
                    cx,
                );
                let interval = self.duration_field(
                    DurationSpec {
                        raw: vpn.interval.clone(),
                        units: INTERVALS,
                        panel: false,
                        field: Rc::new(|_| Some(Field::VpnInterval)),
                        reuse: kept_vpn_interval,
                    },
                    send(manifest::SendPart::Vpn, "interval"),
                    window,
                    cx,
                );
                Some(VpnInputs {
                    probe,
                    probe_name,
                    check,
                    interval,
                })
            }
            None => None,
        };
        let always = form
            .schedule
            .as_ref()
            .and_then(|s| s.always.clone())
            .map(|always| {
                let interval = self.duration_field(
                    DurationSpec {
                        raw: always.interval.clone(),
                        units: always_units(&always.interval),
                        panel: false,
                        field: Rc::new(|_| Some(Field::AlwaysInterval)),
                        reuse: kept_always_interval,
                    },
                    send(manifest::SendPart::Always, "interval"),
                    window,
                    cx,
                );
                AlwaysInputs { interval }
            });
        self.fv.inputs = Some(FormInputs {
            issuer,
            valid_from,
            controller,
            max_age,
            retention,
            unknown_grace,
            vpn,
            always,
        });
        if self
            .fv
            .selected
            .as_ref()
            .is_some_and(|id| form.control(id).is_none())
        {
            self.fv.selected = None;
        }
    }

    /// Writes text the form cannot read as the draft's Valid from and rebuilds the form, as a
    /// draft with such a date has it. The snapshot of a refused date uses it.
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    pub fn type_valid_from(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let result = manifest::set_top_text(&self.draft, "valid_from", text);
        self.edit_form(result, Rebuild::Inputs, window, cx);
    }

    /// Moves between the Form and TOML views. Leaving the Form waits while an input holds text
    /// that is not a value yet, so that text is never dropped.
    fn switch_view(&mut self, to_form: bool, window: &mut Window, cx: &mut Context<Self>) {
        let unread = self.unread_note();
        match view_switch(self.form, to_form, unread.is_some()) {
            ViewSwitch::Stay => {}
            ViewSwitch::Refuse => self.error = unread,
            ViewSwitch::Switch if to_form => {
                self.form = true;
                self.build_form(window, cx);
            }
            ViewSwitch::Switch => {
                self.form = false;
                self.fv.pending.clear();
            }
        }
        cx.notify();
    }

    pub fn select_check(
        &mut self,
        id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let note = self.panel_note();
        self.fv.add_open = false;
        match panel_switch(self.fv.selected.as_deref(), id.as_deref(), note.is_some()) {
            PanelSwitch::Keep => {}
            PanelSwitch::Refuse => self.error = note,
            PanelSwitch::Replace => {
                self.fv.selected = id;
                self.fv.description_edit = None;
                self.build_panel(window, cx);
            }
        }
        cx.notify();
    }

    fn selected_index(&self) -> Option<usize> {
        let id = self.fv.selected.as_ref()?;
        Form::parse(&self.draft)
            .ok()?
            .controls
            .iter()
            .position(|control| &control.id == id)
    }

    fn selected_control(&self) -> Option<Control> {
        let id = self.fv.selected.as_ref()?;
        Form::parse(&self.draft).ok()?.control(id).cloned()
    }

    /// Opens the Description editor, as a snapshot scene needs it.
    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    pub fn open_description_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.start_description_edit(window, cx);
    }

    /// Opens the Description editor with the text the reader sees now.
    fn start_description_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self
            .selected_control()
            .map(|control| description_or_default(&control))
            .unwrap_or_default();
        let Some(panel) = self.fv.panel.as_mut() else {
            return;
        };
        panel.description.update(cx, |state, cx| {
            state.set_value(text.clone(), window, cx);
            state.focus(window, cx);
        });
        panel.editing = true;
        self.fv.description_edit = self.fv.selected.clone().map(|id| (id, text));
        cx.notify();
    }

    /// Writes the typed text to the draft. The default text writes an empty description. The
    /// editor closes only when the draft took the text.
    fn save_description(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(control), Some(index)) = (self.selected_control(), self.selected_index()) else {
            return;
        };
        let Some(panel) = self.fv.panel.as_ref() else {
            return;
        };
        let typed = panel.description.read(cx).value().trim().to_owned();
        let value = stored_description(&typed, manifest::default_about(&control.check));
        let result = manifest::set_control_text(&self.draft, index, "description", value);
        let saved = result.is_ok();
        self.edit_form(result, Rebuild::No, window, cx);
        if saved {
            self.close_description_editor();
        }
        cx.notify();
    }

    fn cancel_description(&mut self, cx: &mut Context<Self>) {
        self.close_description_editor();
        cx.notify();
    }

    /// Puts the default text in the editor. Save writes it.
    fn reset_description(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(text) = self
            .selected_control()
            .and_then(|control| manifest::default_about(&control.check))
        else {
            return;
        };
        if let Some(panel) = self.fv.panel.as_ref() {
            panel
                .description
                .update(cx, |state, cx| state.set_value(text, window, cx));
        }
        self.fv.description_edit = self.fv.selected.clone().map(|id| (id, text.to_owned()));
        cx.notify();
    }

    fn close_description_editor(&mut self) {
        self.fv.description_edit = None;
        if let Some(panel) = self.fv.panel.as_mut() {
            panel.editing = false;
        }
    }

    /// The Description field: the text as read, with Edit, or the editor with Save, Cancel and,
    /// for a built-in check with a default, Reset text.
    fn description_field(&self, panel: &Panel, control: &Control, cx: &Context<Self>) -> Div {
        if !panel.editing {
            let text = description_or_default(control);
            let shown = if text.is_empty() {
                small("No description yet.")
            } else {
                div().text_size(px(14.)).text_color(rgb(INK_2)).child(text)
            };
            return column().gap(px(8.)).child(shown).child(
                div().flex().child(
                    Button::new("edit-description")
                        .label("Edit")
                        .ghost()
                        .small()
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.start_description_edit(window, cx)
                        })),
                ),
            );
        }
        let default = manifest::default_about(&control.check);
        let holds_default =
            default.is_some_and(|text| panel.description.read(cx).value().trim() == text);
        column()
            .gap(px(8.))
            .child(Textarea::new(&panel.description).disabled(self.busy))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.))
                    .child(
                        Button::new("save-description")
                            .label("Save")
                            .primary()
                            .small()
                            .disabled(self.busy)
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.save_description(window, cx)
                                }),
                            ),
                    )
                    .child(
                        Button::new("cancel-description")
                            .label("Cancel")
                            .ghost()
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| this.cancel_description(cx))),
                    )
                    .children(default.map(|_| {
                        Button::new("reset-description")
                            .label("Reset text")
                            .ghost()
                            .small()
                            .disabled(self.busy || holds_default)
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.reset_description(window, cx)
                                }),
                            )
                    })),
            )
    }

    fn build_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.fv.panel_subs.clear();
        self.fv.panel = None;
        self.fv.pending.drop_panel();
        let Ok(form) = Form::parse(&self.draft) else {
            return;
        };
        let Some(control) = self
            .fv
            .selected
            .as_ref()
            .and_then(|id| form.control(id))
            .cloned()
        else {
            return;
        };
        let id = (!control.id_locked()).then(|| {
            let id = cx.new(|cx| InputState::new(window, cx).default_value(control.id.clone()));
            let renamed = cx.subscribe_in(
                &id,
                window,
                |this, input, event: &InputEvent, window, cx| {
                    if !matches!(event, InputEvent::Change) {
                        return;
                    }
                    let value = input.read(cx).value().trim().to_owned();
                    let (Some(index), Some(old)) =
                        (this.selected_index(), this.fv.selected.clone())
                    else {
                        return;
                    };
                    match manifest::set_control_text(&this.draft, index, "id", &value) {
                        Ok(text) => {
                            this.fv.pending.rename_control(&old, &value);
                            this.fv.selected = Some(value.clone());
                            match this.fv.description_edit.as_mut() {
                                Some((held, _)) if *held == old => *held = value.clone(),
                                _ => {}
                            }
                            this.edit_field(Field::Id(value), Ok(text), Rebuild::No, window, cx);
                        }
                        Err(message) => {
                            this.edit_field(Field::Id(old), Err(message), Rebuild::No, window, cx)
                        }
                    }
                },
            );
            self.fv.panel_subs.push(renamed);
            id
        });
        let reference = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Link or text")
                .default_value(control.reference.clone())
        });
        let reference_subscription = cx.subscribe_in(
            &reference,
            window,
            |this, state, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let Some(index) = this.selected_index() else {
                        return;
                    };
                    let result = manifest::set_control_text(
                        &this.draft,
                        index,
                        "reference",
                        state.read(cx).value().trim(),
                    );
                    this.edit_form(result, Rebuild::No, window, cx);
                }
            },
        );
        self.fv.panel_subs.push(reference_subscription);
        let held = kept_description(
            self.fv.description_edit.as_ref(),
            self.fv.selected.as_deref(),
        )
        .map(str::to_owned);
        let editing = held.is_some();
        let text = held.unwrap_or_else(|| description_or_default(&control));
        let description = cx.new(|cx| TextareaState::new(window, cx).rows(6).default_value(text));
        let description_subscription = cx.subscribe_in(
            &description,
            window,
            |this, state, event: &InputEvent, _, cx| {
                if !matches!(event, InputEvent::Change) {
                    return;
                }
                if let Some(id) = this.fv.selected.clone() {
                    let text = state.read(cx).value().to_string();
                    this.fv.description_edit = Some((id, text));
                }
            },
        );
        self.fv.panel_subs.push(description_subscription);
        let grace = self.duration_field(
            DurationSpec {
                raw: control.grace.clone(),
                units: SPANS,
                panel: true,
                field: Rc::new(|this| this.fv.selected.clone().map(Field::Grace)),
                reuse: None,
            },
            Rc::new(|this, value| {
                let index = this
                    .selected_index()
                    .ok_or("This check is no longer in the manifest")?;
                manifest::set_control_text(&this.draft, index, "grace", value)
            }),
            window,
            cx,
        );
        let os = Os::ALL.map(|os| self.os_input(&control, os, window, cx));
        self.fv.panel = Some(Panel {
            id,
            reference,
            description,
            editing,
            os,
            opened: [false; 3],
            grace,
        });
    }

    fn os_input(
        &mut self,
        control: &Control,
        os: Os,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> OsInput {
        match &control.output {
            Output::Integer { .. } => {
                let number = match control.requirement(os) {
                    Requirement::Max(n) | Requirement::Min(n) => n.to_string(),
                    _ => String::new(),
                };
                let input = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("Number")
                        .default_value(number)
                });
                let subscription = cx.subscribe_in(
                    &input,
                    window,
                    move |this, input, event: &InputEvent, window, cx| {
                        if !matches!(event, InputEvent::Change) {
                            return;
                        }
                        let (Some(index), Some(id)) =
                            (this.selected_index(), this.fv.selected.clone())
                        else {
                            return;
                        };
                        let field = Field::Requirement(id, os);
                        let typed = input.read(cx).value().trim().to_owned();
                        let Ok(number) = typed.parse::<i64>() else {
                            this.fv.pending.record(
                                field,
                                Err("Type a whole number, or choose Not required.".into()),
                            );
                            cx.notify();
                            return;
                        };
                        let Some(control) = Form::parse(&this.draft)
                            .ok()
                            .and_then(|form| form.controls.into_iter().nth(index))
                        else {
                            return;
                        };
                        let result = manifest::set_requirement(
                            &this.draft,
                            index,
                            os,
                            &control.limit(os, number),
                        );
                        this.edit_field(field, result, Rebuild::No, window, cx);
                    },
                );
                self.fv.panel_subs.push(subscription);
                OsInput::Limit(input)
            }
            _ => {
                let mut picks: Vec<(SharedString, Pick)> = control
                    .output
                    .choices()
                    .into_iter()
                    .map(|value| {
                        (
                            manifest::value_label(control.builtin_id(), &value, true).into(),
                            Pick::Value(value),
                        )
                    })
                    .collect();
                picks.push(("Not required".into(), Pick::Reported));
                let current = control.requirement(os);
                let current_label: SharedString = match current {
                    Requirement::Reported => "Not required".into(),
                    Requirement::Values(values) if values.len() == 1 => {
                        manifest::value_label(control.builtin_id(), &values[0], true).into()
                    }
                    other => manifest::requirement_text(control, other).into(),
                };
                if !picks.iter().any(|(label, _)| *label == current_label) {
                    picks.push((current_label.clone(), Pick::Keep));
                }
                let labels: Vec<SharedString> =
                    picks.iter().map(|(label, _)| label.clone()).collect();
                let select = cx.new(|cx| SelectState::new(labels, None, window, cx));
                select.update(cx, |state, cx| {
                    state.set_selected_value(&current_label, window, cx)
                });
                let listed: Vec<(SharedString, Option<Option<String>>)> = picks
                    .iter()
                    .map(|(label, pick)| {
                        (
                            label.clone(),
                            match pick {
                                Pick::Value(value) => Some(Some(value.clone())),
                                Pick::Reported => Some(None),
                                Pick::Keep => None,
                            },
                        )
                    })
                    .collect();
                let subscription = cx.subscribe_in(
                    &select,
                    window,
                    move |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                        let SelectEvent::Confirm(Some(label)) = event else {
                            return;
                        };
                        let Some((_, Some(pick))) = listed.iter().find(|(known, _)| known == label)
                        else {
                            return;
                        };
                        let Some(index) = this.selected_index() else {
                            return;
                        };
                        let requirement = match pick {
                            Some(value) => Requirement::Values(vec![value.clone()]),
                            None => Requirement::Reported,
                        };
                        let result =
                            manifest::set_requirement(&this.draft, index, os, &requirement);
                        this.edit_form(result, Rebuild::No, window, cx);
                    },
                );
                self.fv.panel_subs.push(subscription);
                OsInput::Choice(select)
            }
        }
    }
}

impl AppView {
    pub fn change_list(&self) -> Vec<String> {
        manifest::changes_between(&self.active, &self.draft)
    }

    /// Why the check panel may not be replaced now. Its inputs hold text that is not a value yet,
    /// and a new panel would drop it without a word.
    fn panel_note(&self) -> Option<String> {
        let form = Form::parse(&self.draft).ok()?;
        self.fv.pending.panel_blocks(&form)
    }

    fn unread_note(&self) -> Option<String> {
        let form = Form::parse(&self.draft).ok()?;
        self.fv.pending.unread_blocks(&form)
    }

    /// The label of the input that holds text the form could not read, if the form can be read.
    pub fn unread_field(&self) -> Option<String> {
        let form = Form::parse(&self.draft).ok()?;
        Some(self.fv.pending.first_unread()?.label(&form))
    }

    fn panel_blocked(&mut self) -> bool {
        let Some(note) = self.panel_note() else {
            return false;
        };
        self.fv.add_open = false;
        self.error = Some(note);
        true
    }

    /// Whether Review and apply may open: a draft that differs from the active one, confirmed by
    /// the CLI for these exact bytes, with no check running, no error and no unread input.
    pub fn review_open(&self) -> bool {
        !(self.busy
            || self.change_list().is_empty()
            || Form::parse(&self.draft).is_err()
            || self.fv.check.result(&self.draft).is_none()
            || !self.problems().is_empty())
    }

    fn add_check(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        if self.panel_blocked() {
            cx.notify();
            return;
        }
        match manifest::add_control(&self.draft, id) {
            Ok((text, _)) => {
                self.fv.add_open = false;
                self.fv.filter = Filter::All;
                self.fv.selected = Some(id.to_owned());
                self.edit_form(Ok(text), Rebuild::All, window, cx);
                let rows = Form::parse(&self.draft).map_or(0, |form| form.controls.len());
                self.fv.scroll.scroll_to_item(5.min(rows));
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    fn remove_check(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(index) = self.selected_index() else {
            return;
        };
        self.fv.selected = None;
        let result = manifest::remove_control(&self.draft, index);
        self.edit_form(result, Rebuild::All, window, cx);
    }

    pub fn manifest_editor(&self, cx: &Context<Self>) -> Div {
        let parse_error = self.draft.parse::<toml_edit::DocumentMut>().err();
        let form_blocked = parse_error.is_some() || self.busy;
        let top = div()
            .flex()
            .flex_none()
            .items_center()
            .gap_3()
            .px(px(28.))
            .pt(px(22.))
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
                        if !this.busy {
                            this.switch_view(true, window, cx);
                        }
                    })),
                seg_item("toml", "TOML", !self.form)
                    .when(self.busy, |item| item.opacity(0.45))
                    .on_click(cx.listener(|this, _, window, cx| {
                        if !this.busy {
                            this.switch_view(false, window, cx);
                        }
                    })),
            ]))
            .child(
                ghost("history-view", "History").on_click(cx.listener(|this, _, _, cx| {
                    this.show_history = true;
                    cx.notify();
                })),
            );
        let mut notices = column().gap(px(8.)).flex_none().px(px(28.));
        if let Some(status) = &self.status {
            notices = notices.child(note(status.clone()));
        }
        if let Some(error) = &self.error {
            notices = notices.child(banner(error.clone(), BAD, BAD_WASH));
        }
        let body = if self.form {
            self.form_body(parse_error.as_ref(), cx)
        } else {
            self.toml_body(parse_error.as_ref())
        };
        div()
            .flex()
            .flex_col()
            .flex_1()
            .h_full()
            .min_w_0()
            .child(top)
            .child(notices)
            .child(body)
            .children(self.error_list())
            .child(self.apply_bar(cx))
    }

    /// The errors that have no field to sit under, above the bottom bar. The TOML view has no
    /// fields, so it lists every error.
    fn error_list(&self) -> Option<Div> {
        let form = Form::parse(&self.draft).ok()?;
        let problems = self.problems();
        let mut lines: Vec<String> = Vec::new();
        if !self.form {
            lines.extend(
                problems
                    .fields
                    .iter()
                    .map(|issue| format!("{}: {}", issue.field.label(&form), issue.message)),
            );
        }
        lines.extend(problems.listed.iter().map(runner::admin::CheckError::text));
        (!lines.is_empty()).then(|| {
            div()
                .flex_none()
                .px(px(28.))
                .pb(px(12.))
                .child(error_block(format!(
                    "The gateway or a client would refuse this manifest.\n{}",
                    lines.join("\n")
                )))
        })
    }

    fn toml_body(&self, parse_error: Option<&toml_edit::TomlError>) -> Div {
        let mut body = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .gap_3()
            .px(px(28.))
            .pb(px(16.))
            .child(
                div().flex_1().min_h_0().child(
                    Editor::new(&self.editor)
                        .h(relative(1.))
                        .disabled(self.busy),
                ),
            );
        if let Some(error) = parse_error {
            let line = manifest::error_line(&self.draft, error);
            body = body.child(error_block(format!(
                "Line {line}: {}. Fix it to switch back to Form or apply.",
                error.message()
            )));
        }
        body
    }

    fn form_body(&self, parse_error: Option<&toml_edit::TomlError>, cx: &Context<Self>) -> Div {
        let fix = |text: String| {
            div()
                .flex_1()
                .px(px(28.))
                .pt(px(12.))
                .child(error_block(text))
        };
        if let Some(error) = parse_error {
            return fix(format!(
                "Fix the TOML first. Line {}: {}.",
                manifest::error_line(&self.draft, error),
                error.message()
            ));
        }
        let (Ok(form), Some(inputs)) = (Form::parse(&self.draft), &self.fv.inputs) else {
            return fix("Fix the TOML first.".into());
        };
        let before = Form::parse(&self.active).ok();
        let issues = self.problems().fields;
        let disabled = self.busy;
        let jumps = [
            "Agreement".to_owned(),
            "Results".to_owned(),
            "Sent with each result".to_owned(),
            "Sending".to_owned(),
            format!("Checks · {}", form.controls.len()),
        ];
        let jump = div()
            .flex()
            .gap(px(18.))
            .pb(px(14.))
            .border_b_1()
            .border_color(rgb(RULE))
            .children(jumps.into_iter().enumerate().map(|(i, name)| {
                div()
                    .id(("jump", i))
                    .text_size(px(13.))
                    .font_weight(FontWeight::MEDIUM)
                    .cursor_pointer()
                    .text_color(rgb(if self.fv.jump == i { INK } else { MUTED }))
                    .child(name)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.fv.jump = i;
                        this.fv.scroll.scroll_to_item(i + 1);
                        cx.notify();
                    }))
            }));
        let scroll = div()
            .id("form-scroll")
            .flex_1()
            .min_w_0()
            .h_full()
            .overflow_y_scroll()
            .track_scroll(&self.fv.scroll)
            .px(px(28.))
            .pt(px(22.))
            .child(jump)
            .child(self.agreement(&form, inputs, disabled, &issues, cx))
            .child(self.results(&form, inputs, &issues, cx))
            .child(self.sent(&form, cx))
            .child(self.sending(inputs, &issues, cx))
            .child(self.checks(&form, before.as_ref(), &issues, cx));
        let open = self
            .fv
            .selected
            .as_ref()
            .is_some_and(|id| form.control(id).is_some());
        let split = h_resizable("manifest-split").child(
            resizable_panel()
                .size_range(px(520.)..Pixels::MAX)
                .child(scroll),
        );
        let split = if open {
            split.child(
                resizable_panel()
                    .size(px(380.))
                    .size_range(px(380.)..px(600.))
                    .fixed()
                    .child(
                        div()
                            .id("check-panel-scroll")
                            .size_full()
                            .overflow_y_scroll()
                            .child(self.panel(&form, before.as_ref(), &issues, cx)),
                    ),
            )
        } else {
            split
        };
        div().flex().flex_1().min_h_0().child(split)
    }

    fn agreement(
        &self,
        form: &Form,
        inputs: &FormInputs,
        disabled: bool,
        issues: &[FieldError],
        cx: &Context<Self>,
    ) -> Div {
        let mut chips = div().flex().flex_wrap().items_center().gap(px(6.));
        for (i, name) in form.recipients.iter().enumerate() {
            chips = chips.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(7.))
                    .pl(px(10.))
                    .pr(px(6.))
                    .py(px(4.))
                    .rounded_full()
                    .bg(rgb(CHIP))
                    .text_size(px(13.))
                    .child(name.clone())
                    .child(
                        div()
                            .id(("remove-recipient", i))
                            .size(px(18.))
                            .rounded_full()
                            .flex()
                            .items_center()
                            .justify_center()
                            .cursor_pointer()
                            .text_color(rgb(MUTED))
                            .hover(|hover| hover.bg(rgb(0xe3ded3)))
                            .child("×")
                            .on_click(cx.listener(move |this, _, window, cx| {
                                let mut items = Form::parse(&this.draft)
                                    .map(|f| f.recipients)
                                    .unwrap_or_default();
                                if i < items.len() {
                                    items.remove(i);
                                }
                                let result =
                                    manifest::set_top_list(&this.draft, "claim_recipients", &items);
                                this.edit_form(result, Rebuild::No, window, cx);
                            })),
                    ),
            );
        }
        chips = if self.fv.adding_recipient {
            chips.child(div().w(px(220.)).child(Input::new(&self.fv.chip)))
        } else {
            chips.child(
                div()
                    .id("add-recipient")
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .px(px(6.))
                    .py(px(4.))
                    .cursor_pointer()
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(BLUE_INK))
                    .child("+ Add")
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.fv.adding_recipient = true;
                        this.fv.chip.update(cx, |state, cx| state.focus(window, cx));
                        cx.notify();
                    })),
            )
        };
        section(
            "Agreement",
            "Who asks for the checks and who answers for the data.",
            rows(vec![
                kv_row_error(
                    "Issuer",
                    div()
                        .w(px(440.))
                        .child(Input::new(&inputs.issuer).disabled(disabled)),
                    error_of(issues, &Field::Issuer),
                ),
                kv_row_error(
                    "Valid from",
                    div()
                        .w(px(150.))
                        .child(DatePicker::new(&inputs.valid_from).disabled(disabled)),
                    error_of(issues, &Field::ValidFrom),
                ),
                kv_row_error(
                    "Data controller",
                    div()
                        .w(px(440.))
                        .child(Input::new(&inputs.controller).disabled(disabled)),
                    error_of(issues, &Field::Controller),
                ),
                kv_row("Results go to", chips),
            ]),
        )
    }

    fn duration(&self, field: &DurationField, after: Option<&'static str>) -> Div {
        div()
            .flex()
            .items_center()
            .gap(px(6.))
            .child(
                div()
                    .w(px(64.))
                    .child(Input::new(&field.amount).disabled(self.busy)),
            )
            .child(
                div()
                    .w(px(110.))
                    .child(Select::new(&field.unit).disabled(self.busy)),
            )
            .when_some(after, |row, text| row.child(small(text)))
    }

    fn results(
        &self,
        form: &Form,
        inputs: &FormInputs,
        issues: &[FieldError],
        cx: &Context<Self>,
    ) -> Div {
        let trust = seg2(
            TRUST_LEVELS
                .iter()
                .enumerate()
                .map(|(i, (key, name))| {
                    seg2_item(("trust", i), *name, form.trust == *key).on_click(cx.listener(
                        move |this, _, window, cx| {
                            let result =
                                manifest::set_top_text(&this.draft, "min_trust_level", key);
                            this.edit_form(result, Rebuild::No, window, cx);
                        },
                    ))
                })
                .collect(),
        );
        section(
            "Results",
            "How old a result may be, and how long the gateway keeps it.",
            rows(vec![
                kv_row_error(
                    "A result is valid for",
                    self.duration(&inputs.max_age, None),
                    error_of(issues, &Field::MaxAge),
                ),
                kv_row_error(
                    "Results are kept for",
                    self.duration(&inputs.retention, None),
                    error_of(issues, &Field::Retention),
                ),
                kv_row_error(
                    "Unknown is allowed for",
                    self.duration(&inputs.unknown_grace, Some("then it counts as failed")),
                    error_of(issues, &Field::UnknownGrace),
                ),
                kv_row_error(
                    "Device key at least",
                    trust,
                    error_of(issues, &Field::Trust),
                ),
            ]),
        )
    }

    fn sent(&self, form: &Form, cx: &Context<Self>) -> Div {
        let mut entries: Vec<(String, String)> = manifest::METADATA
            .iter()
            .map(|(key, name)| ((*key).to_owned(), (*name).to_owned()))
            .collect();
        for key in &form.metadata {
            if !entries.iter().any(|(known, _)| known == key) {
                entries.push((key.clone(), key.clone()));
            }
        }
        let mut grid = div().grid().grid_cols(3).gap_x(px(18.)).gap_y(px(10.));
        for (i, (key, name)) in entries.into_iter().enumerate() {
            let checked = form.metadata.contains(&key);
            let fixed = manifest::metadata_mandatory(&key);
            let toggled = key.clone();
            grid = grid.child(
                div()
                    .flex()
                    .items_start()
                    .gap(px(9.))
                    .min_w_0()
                    .child(check_box(("metadata", i), checked).on_click(cx.listener(
                        move |this, _, window, cx| {
                            if fixed || this.busy {
                                return;
                            }
                            let mut items = Form::parse(&this.draft)
                                .map(|f| f.metadata)
                                .unwrap_or_default();
                            if let Some(at) = items.iter().position(|item| *item == toggled) {
                                items.remove(at);
                            } else {
                                items.push(toggled.clone());
                            }
                            let result =
                                manifest::set_top_list(&this.draft, "disclosed_metadata", &items);
                            this.edit_form(result, Rebuild::No, window, cx);
                        },
                    )))
                    .child(
                        column()
                            .gap(px(0.))
                            .min_w_0()
                            .child(div().text_size(px(14.)).child(name))
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .font_family(mono())
                                    .text_color(rgb(MUTED))
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .child(key),
                            ),
                    ),
            );
        }
        section(
            "Sent with each result",
            "What the contractor agrees to send besides the check values.",
            grid,
        )
    }

    fn sending(&self, inputs: &FormInputs, issues: &[FieldError], cx: &Context<Self>) -> Div {
        let switch = |id: &'static str, part: manifest::SendPart, on: bool| {
            Switch::new(id)
                .checked(on)
                .disabled(self.busy)
                .on_click(cx.listener(move |this, checked: &bool, window, cx| {
                    let result =
                        manifest::switch_send(&this.draft, part, *checked, &mut this.fv.sends_kept);
                    this.edit_form(result, Rebuild::Inputs, window, cx);
                }))
        };
        let vpn = send_part(
            "On the company VPN",
            switch("send-vpn", manifest::SendPart::Vpn, inputs.vpn.is_some()),
        )
        .when_some(inputs.vpn.as_ref(), |part, vpn| {
            part.child(rows(vec![
                kv_row_error(
                    "VPN answers at",
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            div()
                                .w(px(150.))
                                .font_family(mono())
                                .child(Input::new(&vpn.probe).disabled(self.busy)),
                        )
                        .child(small("shown as"))
                        .child(
                            div()
                                .w(px(180.))
                                .font_family(mono())
                                .child(Input::new(&vpn.probe_name).disabled(self.busy)),
                        ),
                    error_of(issues, &Field::VpnProbe)
                        .or_else(|| error_of(issues, &Field::VpnProbeName)),
                ),
                kv_row_error(
                    "Check every",
                    column()
                        .gap(px(4.))
                        .child(self.duration(&vpn.check, None))
                        .child(small(
                            "Windows checks at most every 5 minutes until measured.",
                        )),
                    error_of(issues, &Field::VpnCheck),
                ),
                kv_row_error(
                    "Send every",
                    column()
                        .gap(px(4.))
                        .child(self.duration(&vpn.interval, None))
                        .child(small("and at once on connect or when a result gets worse")),
                    error_of(issues, &Field::VpnInterval),
                ),
            ]))
        });
        let always = send_part(
            "On any network",
            switch(
                "send-always",
                manifest::SendPart::Always,
                inputs.always.is_some(),
            ),
        )
        .when_some(inputs.always.as_ref(), |part, always| {
            part.child(rows(vec![kv_row_error(
                "Send every",
                self.duration(&always.interval, None),
                error_of(issues, &Field::AlwaysInterval),
            )]))
        });
        let mut list = vec![vpn, always];
        if inputs.vpn.is_none() && inputs.always.is_none() {
            list.push(small(
                "Devices send nothing by themselves. The owner sends by hand.",
            ));
        }
        section(
            "Sending",
            "When devices send results on their own.",
            rows(list),
        )
    }

    fn checks(
        &self,
        form: &Form,
        before: Option<&Form>,
        issues: &[FieldError],
        cx: &Context<Self>,
    ) -> Div {
        let (all, required, reported) = form.counts();
        let filters = seg2(
            [
                (Filter::All, format!("All {all}")),
                (Filter::Required, format!("Required {required}")),
                (Filter::Reported, format!("Reported only {reported}")),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, (filter, name))| {
                seg2_item(("filter", i), name, self.fv.filter == filter).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.fv.filter = filter;
                        cx.notify();
                    },
                ))
            })
            .collect(),
        );
        let anchor = self.fv.add_anchor.clone();
        let add = div()
            .relative()
            .child(
                canvas(
                    move |bounds, window, _| {
                        anchor.set((
                            f32::from(bounds.origin.y),
                            f32::from(window.viewport_size().height),
                        ));
                    },
                    |_, _, _, _| (),
                )
                .absolute()
                .size_full(),
            )
            .child(
                Button::new("add-check")
                    .label("+ Add check")
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.fv.add_open = !this.fv.add_open;
                        if this.fv.add_open {
                            this.fv
                                .add_search
                                .update(cx, |state, cx| state.focus(window, cx));
                        }
                        cx.notify();
                    })),
            )
            .when(self.fv.add_open, |anchor| {
                anchor.child(deferred(self.add_popover(form, cx)).with_priority(10))
            });
        let tools = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(10.))
            .mb(px(10.))
            .child(
                div()
                    .text_size(px(15.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .mr(px(6.))
                    .child("Checks"),
            )
            .child(filters)
            .child(div().flex_1())
            .child(div().w(px(240.)).child(Input::new(&self.fv.search)))
            .child(add);
        let search = self.fv.search.read(cx).value().to_string();
        let visible = form.visible(self.fv.filter, &search);
        let changed = before
            .map(|before| manifest::changed_controls(before, form))
            .unwrap_or_default();
        let flagged: Vec<&str> = issues
            .iter()
            .filter_map(|issue| issue.field.control())
            .collect();
        let head = |text: &'static str, width: f32| div().w(px(width)).flex_none().child(text);
        let mut table = div()
            .flex()
            .flex_col()
            .border_t_1()
            .border_color(rgb(RULE))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .py(px(8.))
                    .text_size(px(12.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(MUTED))
                    .child(div().flex_1().min_w_0().child("Check"))
                    .child(head("macOS", 92.))
                    .child(head("Windows", 92.))
                    .child(head("Linux", 92.))
                    .child(head("Grace", 52.))
                    .child(div().w(px(18.)).flex_none()),
            );
        let rows = listed(visible, |index| form.controls[*index].group());
        for row in rows {
            let index = match row {
                Listed::Heading(group) => {
                    table = table.child(group_heading(group, 0.));
                    continue;
                }
                Listed::Item(index) => index,
            };
            let control = &form.controls[index];
            let selected = self.fv.selected.as_deref() == Some(control.id.as_str());
            let id = control.id.clone();
            let mut row = div()
                .id(("check", index))
                .flex()
                .items_center()
                .gap(px(12.))
                .px(px(10.))
                .mx(px(-10.))
                .py(px(9.))
                .text_size(px(14.))
                .border_b_1()
                .border_color(rgb(RULE_2))
                .cursor_pointer()
                .when(selected, |row| {
                    row.bg(rgb(BLUE_WASH)).rounded(px(8.)).border_color(rgba(0))
                })
                .when(!selected, |row| row.hover(|hover| hover.bg(rgb(ROW_HOVER))))
                .child(
                    div()
                        .flex()
                        .flex_1()
                        .min_w_0()
                        .items_center()
                        .gap(px(8.))
                        .when_some(
                            if flagged.contains(&control.id.as_str()) {
                                Some(BAD)
                            } else if changed.contains(&control.id) {
                                Some(BLUE)
                            } else {
                                None
                            },
                            |name, color| {
                                name.child(
                                    div().size(px(7.)).flex_none().rounded_full().bg(rgb(color)),
                                )
                            },
                        )
                        .child(
                            div()
                                .id(("check-name", index))
                                .min_w_0()
                                .overflow_hidden()
                                .text_ellipsis()
                                .font_weight(FontWeight::SEMIBOLD)
                                .whitespace_nowrap()
                                .when_some(
                                    control
                                        .builtin()
                                        .map(|_| description_or_default(control))
                                        .filter(|text| !text.is_empty()),
                                    |name, text| {
                                        name.tooltip(move |window, cx| {
                                            gpui_component::tooltip::Tooltip::new(text.clone())
                                                .w(px(340.))
                                                .build(window, cx)
                                        })
                                    },
                                )
                                .child(control.name()),
                        ),
                );
            for os in Os::ALL {
                let text = control.requirement_text(os);
                row = row.child(
                    div()
                        .w(px(92.))
                        .flex_none()
                        .when(text == "reported", |cell| {
                            cell.text_size(px(13.)).text_color(rgb(MUTED))
                        })
                        .child(text),
                );
            }
            table = table.child(
                row.child(
                    div()
                        .w(px(52.))
                        .flex_none()
                        .text_color(rgb(INK_2))
                        .child(control.grace_text()),
                )
                .child(
                    div()
                        .w(px(18.))
                        .flex_none()
                        .text_color(rgb(0xa39c8e))
                        .child("›"),
                )
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.select_check(Some(id.clone()), window, cx);
                })),
            );
        }
        div()
            .py(px(20.))
            .child(tools)
            .child(table)
            .when(form.controls.is_empty(), |view| {
                view.child(small("The manifest lists no checks yet."))
            })
            .when(
                !form.controls.is_empty() && form.visible(self.fv.filter, &search).is_empty(),
                |view| view.child(div().py(px(10.)).child(small("No check matches."))),
            )
    }

    fn add_popover(&self, form: &Form, cx: &Context<Self>) -> Div {
        let search = self.fv.add_search.read(cx).value().trim().to_lowercase();
        let options: Vec<_> = manifest::addable(form)
            .into_iter()
            .filter(|known| {
                search.is_empty()
                    || known.name.to_lowercase().contains(&search)
                    || known.id.contains(&search)
                    || known.line.to_lowercase().contains(&search)
            })
            .collect();
        let mut options_list = div()
            .id("add-options")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .gap(px(2.))
            .overflow_y_scroll()
            .track_scroll(&self.fv.add_scroll);
        let (button_top, window_height) = self.fv.add_anchor.get();
        let place = popover_place(window_height, button_top);
        let list = div()
            .absolute()
            .when(place.above, |popover| popover.bottom(px(POPOVER_TOP)))
            .when(!place.above, |popover| popover.top(px(POPOVER_TOP)))
            .right_0()
            .w(px(420.))
            .max_h(px(place.height))
            .flex()
            .flex_col()
            .gap(px(2.))
            .p(px(10.))
            .rounded(px(12.))
            .border_1()
            .border_color(rgb(RULE))
            .bg(rgb(0xffffff))
            .shadow_lg()
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                this.fv.add_open = false;
                cx.notify();
            }))
            .child(div().mb(px(8.)).child(Input::new(&self.fv.add_search)))
            .child(
                div()
                    .px(px(10.))
                    .pt(px(8.))
                    .pb(px(4.))
                    .text_size(px(11.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(MUTED))
                    .child("Not in the manifest yet"),
            );
        if options.is_empty() {
            options_list = options_list.child(
                div()
                    .px(px(10.))
                    .py(px(8.))
                    .child(small("Every built-in check is in the manifest.")),
            );
        }
        let rows = listed(options, |known| known.group);
        let first = rows.iter().find_map(|row| match row {
            Listed::Item(known) => Some(known.id),
            Listed::Heading(_) => None,
        });
        for (i, row) in rows.into_iter().enumerate() {
            let known = match row {
                Listed::Heading(group) => {
                    options_list = options_list.child(group_heading(group, 10.));
                    continue;
                }
                Listed::Item(known) => known,
            };
            let id = known.id;
            options_list = options_list.child(
                div()
                    .id(("add-option", i))
                    .flex()
                    .flex_col()
                    .px(px(10.))
                    .py(px(7.))
                    .rounded(px(7.))
                    .cursor_pointer()
                    .when(Some(known.id) == first, |option| option.bg(rgb(BLUE_WASH)))
                    .hover(|hover| hover.bg(rgb(BLUE_WASH)))
                    .child(
                        div()
                            .text_size(px(14.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(known.name),
                    )
                    .child(div().text_size(px(12.5)).text_color(rgb(MUTED)).child(
                        if known.scope.is_empty() {
                            known.line.to_owned()
                        } else {
                            format!("{} · {}", known.line, known.scope)
                        },
                    ))
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.add_check(id, window, cx)),
                    ),
            );
        }
        list.child(options_list)
    }

    fn panel(
        &self,
        form: &Form,
        before: Option<&Form>,
        issues: &[FieldError],
        cx: &Context<Self>,
    ) -> Div {
        let shell = || {
            div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .flex_1()
                .min_w_0()
                .min_h_full()
                .p(px(22.))
                .border_l_1()
                .border_color(rgb(RULE))
                .bg(rgb(PANEL_BG))
        };
        let (Some(panel), Some(control)) = (
            &self.fv.panel,
            self.fv.selected.as_ref().and_then(|id| form.control(id)),
        ) else {
            return shell().child(small("Pick a check in the table to see what it asks for."));
        };
        let old = before.and_then(|before| before.control(&control.id));
        let field = |name: &'static str, body: Div, error: Option<String>| {
            column()
                .gap(px(6.))
                .child(
                    div()
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(INK_2))
                        .child(name),
                )
                .child(body)
                .children(error.map(error_line))
        };
        let header = div()
            .flex()
            .items_start()
            .gap(px(10.))
            .child(
                column()
                    .flex_1()
                    .min_w_0()
                    .gap(px(2.))
                    .child(
                        div()
                            .text_size(px(18.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(control.name()),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .font_family(mono())
                            .text_color(rgb(MUTED))
                            .child(control.check.clone()),
                    ),
            )
            .child(
                div()
                    .id("close-panel")
                    .px(px(8.))
                    .cursor_pointer()
                    .text_size(px(20.))
                    .text_color(rgb(BLUE_INK))
                    .child("×")
                    .on_click(
                        cx.listener(|this, _, window, cx| this.select_check(None, window, cx)),
                    ),
            );
        let values =
            div()
                .flex()
                .flex_wrap()
                .gap(px(6.))
                .children(control.output.values().into_iter().map(|value| {
                    div()
                        .px(px(8.))
                        .py(px(3.))
                        .rounded(px(5.))
                        .bg(rgb(CHIP))
                        .font_family(mono())
                        .text_size(px(12.))
                        .text_color(rgb(INK_2))
                        .child(value)
                }));
        let heading = match (&control.output, control.builtin()) {
            (Output::Integer { .. }, Some(known)) if !known.noun.is_empty() => {
                let direction = match (control.mixed_limits(), control.limit_is_max()) {
                    (true, _) => "",
                    (false, true) => " at most",
                    (false, false) => " at least",
                };
                format!("Required: {}{direction}", known.noun)
            }
            _ => "Required".to_owned(),
        };
        let mut requirements = div().grid().grid_cols(1).gap(px(8.));
        let mut os_rows = div().flex().flex_col().gap(px(8.));
        for (i, os) in Os::ALL.into_iter().enumerate() {
            let current = control.requirement(os);
            let was = old
                .map(|old| old.requirement(os))
                .filter(|was| *was != current);
            let body = match &panel.os[i] {
                OsInput::Choice(select) => div()
                    .w_full()
                    .child(Select::new(select).disabled(self.busy)),
                OsInput::Limit(input) => {
                    let limited = matches!(current, Requirement::Max(_) | Requirement::Min(_));
                    if limited || panel.opened[i] {
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.))
                            .child(
                                div()
                                    .w(px(14.))
                                    .flex_none()
                                    .text_size(px(14.))
                                    .text_color(rgb(INK_2))
                                    .child(control.limit_symbol(os)),
                            )
                            .child(
                                div()
                                    .w(px(72.))
                                    .child(Input::new(input).disabled(self.busy)),
                            )
                            .child(small(control.limit_unit()))
                            .when_some(was, |row, was| {
                                row.child(div().text_size(px(13.)).text_color(rgb(BLUE_INK)).child(
                                    match was {
                                        Requirement::Max(n) | Requirement::Min(n) => {
                                            format!("was {n}")
                                        }
                                        _ => "was not required".to_owned(),
                                    },
                                ))
                            })
                            .child(ghost(("unset", i), "Not required").on_click(cx.listener(
                                move |this, _, window, cx| {
                                    let (Some(index), Some(id)) =
                                        (this.selected_index(), this.fv.selected.clone())
                                    else {
                                        return;
                                    };
                                    if let Some(panel) = this.fv.panel.as_mut() {
                                        panel.opened[i] = false;
                                    }
                                    let result = manifest::set_requirement(
                                        &this.draft,
                                        index,
                                        os,
                                        &Requirement::Reported,
                                    );
                                    this.edit_field(
                                        Field::Requirement(id, os),
                                        result,
                                        Rebuild::No,
                                        window,
                                        cx,
                                    );
                                },
                            )))
                    } else {
                        div()
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .child(small(match current {
                                Requirement::Values(_) => control.requirement_text(os),
                                _ => "Not required".to_owned(),
                            }))
                            .when_some(was, |row, was| {
                                row.child(div().text_size(px(13.)).text_color(rgb(BLUE_INK)).child(
                                    match was {
                                        Requirement::Max(n) | Requirement::Min(n) => {
                                            format!("was {n}")
                                        }
                                        _ => "was not required".to_owned(),
                                    },
                                ))
                            })
                            .child(ghost(("set", i), "Set limit").on_click(cx.listener(
                                move |this, _, window, cx| {
                                    let (Some(index), Some(id)) =
                                        (this.selected_index(), this.fv.selected.clone())
                                    else {
                                        return;
                                    };
                                    let typed =
                                        match this.fv.panel.as_ref().map(|panel| &panel.os[i]) {
                                            Some(OsInput::Limit(input)) => {
                                                input.read(cx).value().trim().to_owned()
                                            }
                                            _ => String::new(),
                                        };
                                    let control = Form::parse(&this.draft)
                                        .ok()
                                        .and_then(|form| form.controls.into_iter().nth(index));
                                    match (typed.parse::<i64>(), control) {
                                        (Ok(n), Some(control)) => {
                                            let result = manifest::set_requirement(
                                                &this.draft,
                                                index,
                                                os,
                                                &control.limit(os, n),
                                            );
                                            this.edit_field(
                                                Field::Requirement(id, os),
                                                result,
                                                Rebuild::No,
                                                window,
                                                cx,
                                            );
                                        }
                                        _ => {
                                            if let Some(panel) = this.fv.panel.as_mut() {
                                                panel.opened[i] = true;
                                            }
                                            if !typed.is_empty() {
                                                this.fv.pending.record(
                                                    Field::Requirement(id, os),
                                                    Err("Type a whole number, or choose Not required."
                                                        .into()),
                                                );
                                            }
                                            cx.notify();
                                        }
                                    }
                                },
                            )))
                    }
                }
            };
            os_rows = os_rows.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        div()
                            .w(px(72.))
                            .flex_none()
                            .text_size(px(13.))
                            .text_color(rgb(INK_2))
                            .child(os.name()),
                    )
                    .child(
                        column()
                            .flex_1()
                            .min_w_0()
                            .gap(px(4.))
                            .child(body)
                            .children(
                                error_of(issues, &Field::Requirement(control.id.clone(), os))
                                    .map(error_line),
                            ),
                    ),
            );
        }
        requirements = requirements.child(os_rows);
        let id_body = match &panel.id {
            Some(input) => div()
                .font_family(mono())
                .child(Input::new(input).disabled(self.busy)),
            None => div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .child(
                    div()
                        .px(px(12.))
                        .py(px(7.))
                        .rounded(px(7.))
                        .border_1()
                        .border_color(rgb(RULE))
                        .bg(rgb(CHIP))
                        .font_family(mono())
                        .text_color(rgb(INK_2))
                        .child(control.id.clone()),
                )
                .child(small("A built-in check keeps its ID.")),
        };
        shell()
            .child(header)
            .child(field(
                "ID",
                id_body,
                error_of(issues, &Field::Id(control.id.clone())),
            ))
            .child(field(
                "Description",
                self.description_field(panel, control, cx),
                None,
            ))
            .child(field(
                "Reference",
                div().child(Input::new(&panel.reference).disabled(self.busy)),
                None,
            ))
            .child(field(
                "Possible results",
                column()
                    .gap(px(6.))
                    .child(values)
                    .child(small("The check defines these. Change them in TOML.")),
                None,
            ))
            .child(field_heading(heading, requirements))
            .child(field(
                "Time to fix",
                self.duration(&panel.grace, Some("after the first failed result")),
                error_of(issues, &Field::Grace(control.id.clone())),
            ))
            .child(div().flex_1())
            .child(
                div()
                    .id("remove-check")
                    .cursor_pointer()
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(BAD))
                    .child("Remove this check")
                    .on_click(cx.listener(|this, _, window, cx| this.remove_check(window, cx))),
            )
    }

    fn apply_bar(&self, cx: &Context<Self>) -> Div {
        let list = self.change_list();
        let changes = list.len();
        let form = Form::parse(&self.draft).ok();
        let problems = self.problems();
        let checking = self.fv.check.result(&self.draft).is_none();
        let can_review = self.review_open();
        let shown = list.iter().take(2).cloned().collect::<Vec<_>>().join(" · ");
        let summary = if changes > 2 {
            format!("{shown} · and {} more", changes - 2)
        } else {
            shown
        };
        let blocked = form.as_ref().and_then(|form| {
            let first = problems.first(form)?;
            let more = match problems.len() {
                1 => String::new(),
                rest => format!(" · and {} more", rest - 1),
            };
            Some(format!("Fix first. {first}{more}"))
        });
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap(px(12.))
            .px(px(28.))
            .py(px(12.))
            .border_t_1()
            .border_color(rgb(RULE))
            .bg(rgb(SIDE))
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(if changes == 0 {
                        "No changes".to_owned()
                    } else {
                        plural(changes, "change", "changes")
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_size(px(13.))
                    .text_color(rgb(if blocked.is_some() { BAD } else { MUTED }))
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(match blocked {
                        Some(blocked) => blocked,
                        None if changes == 0 => "Form and TOML edit the same text.".to_owned(),
                        None if checking => "Checking the manifest...".to_owned(),
                        None => summary,
                    }),
            )
            .child(
                Button::new("discard")
                    .label("Discard")
                    .disabled(self.busy || changes == 0)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.replace_draft(this.active.clone());
                        this.error = None;
                        this.show_draft(window, cx);
                        this.build_form(window, cx);
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
            )
    }
}

fn field_heading(heading: String, body: Div) -> Div {
    column()
        .gap(px(6.))
        .child(
            div()
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(INK_2))
                .child(heading),
        )
        .child(body)
}

/// What a click on a check row does to the open panel.
#[derive(Debug, PartialEq, Eq)]
enum PanelSwitch {
    /// The open check. Its panel and its unread input stay.
    Keep,
    /// Another check, while the panel holds input that is not a value yet.
    Refuse,
    /// Another check, with nothing unread in the panel.
    Replace,
}

/// What a click on a view tab does.
#[derive(Debug, PartialEq, Eq)]
enum ViewSwitch {
    /// The view that is already open. Nothing changes.
    Stay,
    /// Leaving the Form while an input holds text that is not a value yet.
    Refuse,
    /// Another view, with no unread input to lose.
    Switch,
}

fn view_switch(form_now: bool, to_form: bool, unread: bool) -> ViewSwitch {
    if form_now == to_form {
        ViewSwitch::Stay
    } else if form_now && unread {
        ViewSwitch::Refuse
    } else {
        ViewSwitch::Switch
    }
}

/// A heading, or an item under it, in a list that shows its items by group.
enum Listed<T> {
    Heading(manifest::Group),
    Item(T),
}

/// The items under their group headings, in the order of the headings.
fn listed<T>(
    items: impl IntoIterator<Item = T>,
    group: impl Fn(&T) -> manifest::Group,
) -> Vec<Listed<T>> {
    manifest::by_group(items, group)
        .into_iter()
        .flat_map(|(group, items)| {
            std::iter::once(Listed::Heading(group)).chain(items.into_iter().map(Listed::Item))
        })
        .collect()
}

fn group_heading(group: manifest::Group, inset: f32) -> Div {
    div()
        .px(px(inset))
        .pt(px(16.))
        .pb(px(6.))
        .text_size(px(11.5))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(MUTED))
        .child(group.label())
}

fn panel_switch(selected: Option<&str>, requested: Option<&str>, blocked: bool) -> PanelSwitch {
    if requested == selected {
        PanelSwitch::Keep
    } else if blocked {
        PanelSwitch::Refuse
    } else {
        PanelSwitch::Replace
    }
}

/// The check's description, or the open-pact text for a built-in check that has none, so the
/// admin edits one text that the device user also reads.
fn description_or_default(control: &manifest::Control) -> String {
    match manifest::default_about(&control.check) {
        Some(default) if control.description.is_empty() => default.to_owned(),
        _ => control.description.clone(),
    }
}

/// The description to write for a typed text. The default text writes an empty description, so
/// the manifest keeps no copy of the text that the CLI gives.
fn stored_description<'a>(text: &'a str, default: Option<&'a str>) -> &'a str {
    if default == Some(text) { "" } else { text }
}

/// The Description text that an open edit keeps for the selected check. An edit of another
/// check, or no selected check, keeps nothing.
fn kept_description<'a>(
    edit: Option<&'a (String, String)>,
    selected: Option<&str>,
) -> Option<&'a str> {
    let (id, text) = edit?;
    (selected == Some(id.as_str())).then_some(text.as_str())
}

#[cfg(test)]
mod tests {
    use super::{
        PanelSwitch, PopoverPlace, ViewSwitch, kept_description, panel_switch, popover_place,
        stored_description, view_switch,
    };

    #[test]
    fn an_open_description_edit_applies_only_to_its_check() {
        let edit = ("screen_lock".to_owned(), "Typed text.".to_owned());
        assert_eq!(
            kept_description(Some(&edit), Some("screen_lock")),
            Some("Typed text.")
        );
        assert_eq!(kept_description(Some(&edit), Some("firewall")), None);
        assert_eq!(kept_description(Some(&edit), None), None);
        assert_eq!(kept_description(None, Some("screen_lock")), None);
    }

    fn place(above: bool, height: f32) -> PopoverPlace {
        PopoverPlace { above, height }
    }

    #[test]
    fn the_add_check_options_open_below_and_fit_the_window() {
        assert_eq!(popover_place(860., 100.), place(false, 708.));
        assert_eq!(popover_place(860., 608.), place(false, 200.));
    }

    #[test]
    fn the_add_check_options_open_above_when_the_window_ends_just_below_the_button() {
        assert_eq!(popover_place(860., 650.), place(true, 630.));
        assert_eq!(popover_place(860., 700.), place(true, 680.));
    }

    #[test]
    fn saving_the_default_text_writes_an_empty_description() {
        let default = Some("The default text.");
        assert_eq!(stored_description("The default text.", default), "");
        assert_eq!(
            stored_description("Our own text.", default),
            "Our own text."
        );
        assert_eq!(stored_description("Our own text.", None), "Our own text.");
    }

    #[test]
    fn the_add_check_options_keep_200_px_in_a_window_that_is_too_small() {
        assert_eq!(popover_place(300., 150.), place(true, 200.));
        assert_eq!(popover_place(300., 120.), place(false, 200.));
    }

    #[test]
    fn clicking_the_open_check_keeps_its_panel_even_with_unread_input() {
        assert_eq!(panel_switch(Some("a"), Some("a"), true), PanelSwitch::Keep);
        assert_eq!(panel_switch(Some("a"), Some("a"), false), PanelSwitch::Keep);
    }

    #[test]
    fn clicking_the_active_view_changes_nothing() {
        assert_eq!(view_switch(true, true, false), ViewSwitch::Stay);
        assert_eq!(view_switch(true, true, true), ViewSwitch::Stay);
        assert_eq!(view_switch(false, false, false), ViewSwitch::Stay);
    }

    #[test]
    fn leaving_the_form_waits_while_an_input_holds_unread_text() {
        assert_eq!(view_switch(true, false, true), ViewSwitch::Refuse);
        assert_eq!(view_switch(true, false, false), ViewSwitch::Switch);
        assert_eq!(view_switch(false, true, false), ViewSwitch::Switch);
    }

    #[test]
    fn another_check_waits_while_the_panel_holds_unread_input() {
        assert_eq!(
            panel_switch(Some("a"), Some("b"), true),
            PanelSwitch::Refuse
        );
        assert_eq!(
            panel_switch(Some("a"), Some("b"), false),
            PanelSwitch::Replace
        );
        assert_eq!(panel_switch(None, Some("b"), false), PanelSwitch::Replace);
    }

    #[test]
    fn clearing_valid_from_empties_the_draft_date() {
        let draft = include_str!("../../../tests/fixtures/manifest.toml");
        let cleared = super::valid_from_draft(draft, None).unwrap();
        let form = runner::manifest::Form::parse(&cleared).unwrap();
        assert_eq!(form.valid_from, "");
    }

    #[test]
    fn picking_valid_from_writes_the_day() {
        let draft = include_str!("../../../tests/fixtures/manifest.toml");
        let picked = super::valid_from_draft(draft, Some("2026-11-05".to_owned())).unwrap();
        let form = runner::manifest::Form::parse(&picked).unwrap();
        assert_eq!(form.valid_from, "2026-11-05");
    }
}
