//! The Manifest screen: the Form view with its sections, check table and panel, and the TOML view.
//! Both edit the same text, `AppView::draft`. Every form edit rewrites it with toml_edit.
use super::*;
use gpui_component::{
    highlighter::{Diagnostic, DiagnosticSeverity},
    input::{Editor, Position, Textarea, TextareaState},
};
use runner::manifest::{
    self, Control, Filter, Form, Os, Output, Requirement, SOURCES, Span, TRUST_LEVELS, Unit,
};
use std::rc::Rc;

type Units = Entity<SelectState<Vec<SharedString>>>;
/// Turns the app state and a new value into the new draft.
type Apply = Rc<dyn Fn(&AppView, &str) -> Result<String, String>>;

const SPANS: &[Unit] = &Unit::SPANS;
const INTERVALS: &[Unit] = &Unit::INTERVALS;
const CHIP: u32 = 0xefebe3;
const ROW_HOVER: u32 = 0xfaf8f4;
const PANEL_BG: u32 = 0xfbfaf7;

pub struct DurationField {
    amount: Entity<InputState>,
    unit: Units,
}

pub struct FormInputs {
    issuer: Entity<InputState>,
    valid_from: Entity<InputState>,
    controller: Entity<InputState>,
    max_age: DurationField,
    retention: DurationField,
    unknown_grace: DurationField,
    probe: Entity<InputState>,
    probe_name: Entity<InputState>,
    interval: DurationField,
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
    id: Entity<InputState>,
    source: Units,
    source_ref: Entity<InputState>,
    rationale: Entity<TextareaState>,
    os: [OsInput; 3],
    /// A number field is open for this OS before any number is typed.
    pending: [bool; 3],
    grace: DurationField,
}

pub struct FormState {
    pub inputs: Option<FormInputs>,
    pub panel: Option<Panel>,
    /// The id of the selected check.
    pub selected: Option<String>,
    pub filter: Filter,
    pub add_open: bool,
    pub adding_recipient: bool,
    pub jump: usize,
    pub scroll: ScrollHandle,
    search: Entity<InputState>,
    add_search: Entity<InputState>,
    chip: Entity<InputState>,
    subs: Vec<Subscription>,
    panel_subs: Vec<Subscription>,
    _permanent: Vec<Subscription>,
}

impl FormState {
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
                            this.edit_form(result, true, window, cx);
                        }
                        cx.notify();
                    }
                },
            ),
        ];
        Self {
            inputs: None,
            panel: None,
            selected: None,
            filter: Filter::All,
            add_open: false,
            adding_recipient: false,
            jump: 0,
            scroll: ScrollHandle::new(),
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
    div()
        .flex()
        .items_center()
        .gap(px(16.))
        .child(
            div()
                .w(px(150.))
                .flex_none()
                .text_size(px(13.))
                .text_color(rgb(INK_2))
                .child(key),
        )
        .child(control)
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

fn tag(source: &str) -> Div {
    let (wash, ink) = match source {
        "customer_contract" => (0xeae4f3, 0x5b3e86),
        "standard" => (0xe3eef0, 0x2d5e66),
        "law" => (0xfbeedc, 0x7a4708),
        _ => (0xeceae5, INK_2),
    };
    div().w(px(92.)).flex_none().child(
        div()
            .px(px(8.))
            .py(px(2.))
            .rounded_full()
            .bg(rgb(wash))
            .text_color(rgb(ink))
            .text_size(px(11.5))
            .font_weight(FontWeight::SEMIBOLD)
            .child(manifest::source_tag(source)),
    )
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

impl AppView {
    /// Applies an edit of the form to the draft. `rebuild` makes new inputs from the new text,
    /// for edits that change which inputs exist.
    pub fn edit_form(
        &mut self,
        result: Result<String, String>,
        rebuild: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok(text) => {
                self.error = None;
                self.draft = text;
                self.show_draft(window, cx);
                if rebuild {
                    self.build_form(window, cx);
                }
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    /// Puts the draft into the TOML editor and marks the line of a parse error in it.
    pub fn show_draft(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let draft = self.draft.clone();
        let error = draft.parse::<toml_edit::DocumentMut>().err();
        self.editor.update(cx, |state, cx| {
            if state.value().as_ref() != draft {
                state.set_value(draft.clone(), window, cx);
            }
            let text = state.text().clone();
            if let Some(marks) = state.diagnostics_mut() {
                marks.reset(&text);
                if let Some(error) = &error {
                    let line = manifest::error_line(&draft, error).saturating_sub(1) as u32;
                    let width = draft
                        .lines()
                        .nth(line as usize)
                        .map_or(1, |l| l.chars().count()) as u32;
                    marks.push(
                        Diagnostic::new(
                            Position::new(line, 0)..Position::new(line, width.max(1)),
                            error.message().to_owned(),
                        )
                        .with_severity(DiagnosticSeverity::Error),
                    );
                }
            }
            cx.notify();
        });
    }

    fn bind_text(
        &mut self,
        input: &Entity<InputState>,
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
                    this.edit_form(result, false, window, cx);
                }
            },
        );
        self.fv.subs.push(subscription);
    }

    fn text_input(
        &mut self,
        value: &str,
        apply: Apply,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        let input = cx.new(|cx| InputState::new(window, cx).default_value(value.to_owned()));
        self.bind_text(&input, apply, window, cx);
        input
    }

    fn duration_field(
        &mut self,
        raw: &str,
        units: &'static [Unit],
        panel: bool,
        apply: Apply,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> DurationField {
        let span = Span::parse(raw).filter(|span| units.contains(&span.unit));
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
        let changed = {
            let (amount, unit) = (amount.clone(), unit.clone());
            move |this: &mut AppView, window: &mut Window, cx: &mut Context<AppView>| {
                let typed = amount.read(cx).value().trim().to_owned();
                let Ok(count) = typed.parse::<u64>() else {
                    this.error = Some("Type a whole number.".into());
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
                this.edit_form(result, false, window, cx);
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
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> DurationField {
        self.duration_field(
            raw,
            SPANS,
            false,
            Rc::new(move |this, value| manifest::set_top_text(&this.draft, key, value)),
            window,
            cx,
        )
    }

    /// Makes the inputs of the form and of the selected check from the draft.
    pub fn build_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.fv.subs.clear();
        self.fv.inputs = None;
        let Ok(form) = Form::parse(&self.draft) else {
            self.fv.panel = None;
            self.fv.panel_subs.clear();
            return;
        };
        let top = |key: &'static str| -> Apply {
            Rc::new(move |this, value| manifest::set_top_text(&this.draft, key, value))
        };
        let issuer = self.text_input(&form.issuer, top("issuer"), window, cx);
        let controller = self.text_input(&form.data_controller, top("data_controller"), window, cx);
        let date: Apply = Rc::new(|this, value| match manifest::parse_date(value) {
            Some(date) => manifest::set_top_text(
                &this.draft,
                "valid_from",
                &date.format("%Y-%m-%d").to_string(),
            ),
            None => Err("Type the date as 1 Oct 2026 or 2026-10-01.".into()),
        });
        let valid_from = self.text_input(&manifest::date_text(&form.valid_from), date, window, cx);
        let max_age = self.top_span(&form.max_age, "claim_max_age", window, cx);
        let retention = self.top_span(&form.retention, "claim_retention", window, cx);
        let unknown_grace = self.top_span(&form.unknown_grace, "unknown_grace", window, cx);
        let schedule = form.schedule.clone().unwrap_or(manifest::Schedule {
            mode: String::new(),
            probe: String::new(),
            name: String::new(),
            interval: String::new(),
        });
        let schedule_key = |key: &'static str| -> Apply {
            Rc::new(move |this, value| manifest::set_schedule(&this.draft, key, value))
        };
        let probe = self.text_input(&schedule.probe, schedule_key("vpn_probe"), window, cx);
        let probe_name =
            self.text_input(&schedule.name, schedule_key("vpn_probe_name"), window, cx);
        let interval = self.duration_field(
            &schedule.interval,
            INTERVALS,
            false,
            schedule_key("interval"),
            window,
            cx,
        );
        self.fv.inputs = Some(FormInputs {
            issuer,
            valid_from,
            controller,
            max_age,
            retention,
            unknown_grace,
            probe,
            probe_name,
            interval,
        });
        if self
            .fv
            .selected
            .as_ref()
            .is_some_and(|id| form.control(id).is_none())
        {
            self.fv.selected = None;
        }
        self.build_panel(window, cx);
    }

    pub fn select_check(
        &mut self,
        id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.fv.selected = id;
        self.fv.add_open = false;
        self.build_panel(window, cx);
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

    fn build_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.fv.panel_subs.clear();
        self.fv.panel = None;
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
        let id = cx.new(|cx| InputState::new(window, cx).default_value(control.id.clone()));
        let renamed = cx.subscribe_in(
            &id,
            window,
            |this, input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let value = input.read(cx).value().trim().to_owned();
                    let Some(index) = this.selected_index() else {
                        return;
                    };
                    let result = manifest::set_control_text(&this.draft, index, "id", &value);
                    if result.is_ok() {
                        this.fv.selected = Some(value);
                    }
                    this.edit_form(result, false, window, cx);
                }
            },
        );
        self.fv.panel_subs.push(renamed);
        let mut keys: Vec<String> = SOURCES
            .iter()
            .map(|(key, _, _)| (*key).to_owned())
            .collect();
        if !keys.contains(&control.source) {
            keys.push(control.source.clone());
        }
        let source_labels: Vec<SharedString> = keys
            .iter()
            .map(|key| manifest::source_name(key).into())
            .collect();
        let source = cx.new(|cx| SelectState::new(source_labels.clone(), None, window, cx));
        source.update(cx, |state, cx| {
            state.set_selected_value(
                &SharedString::from(manifest::source_name(&control.source)),
                window,
                cx,
            )
        });
        let source_subscription = cx.subscribe_in(
            &source,
            window,
            move |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                let SelectEvent::Confirm(Some(label)) = event else {
                    return;
                };
                let Some(key) = keys
                    .iter()
                    .find(|key| manifest::source_name(key) == label.as_ref())
                else {
                    return;
                };
                let Some(index) = this.selected_index() else {
                    return;
                };
                let result = manifest::set_control_text(&this.draft, index, "source", key);
                this.edit_form(result, false, window, cx);
            },
        );
        self.fv.panel_subs.push(source_subscription);
        let source_ref = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Reference")
                .default_value(control.source_ref.clone())
        });
        let rationale = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(2)
                .default_value(control.rationale.clone())
        });
        let reference = cx.subscribe_in(
            &source_ref,
            window,
            |this, input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let Some(index) = this.selected_index() else {
                        return;
                    };
                    let result = manifest::set_control_text(
                        &this.draft,
                        index,
                        "source_ref",
                        input.read(cx).value().trim(),
                    );
                    this.edit_form(result, false, window, cx);
                }
            },
        );
        self.fv.panel_subs.push(reference);
        let reason = cx.subscribe_in(
            &rationale,
            window,
            |this, state, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    let Some(index) = this.selected_index() else {
                        return;
                    };
                    let result = manifest::set_control_text(
                        &this.draft,
                        index,
                        "rationale",
                        state.read(cx).value().trim(),
                    );
                    this.edit_form(result, false, window, cx);
                }
            },
        );
        self.fv.panel_subs.push(reason);
        let grace = self.duration_field(
            &control.grace,
            SPANS,
            true,
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
            source,
            source_ref,
            rationale,
            os,
            pending: [false; 3],
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
                let max = control.limit_is_max();
                let subscription = cx.subscribe_in(
                    &input,
                    window,
                    move |this, input, event: &InputEvent, window, cx| {
                        if matches!(event, InputEvent::Change) {
                            let Some(index) = this.selected_index() else {
                                return;
                            };
                            let typed = input.read(cx).value().trim().to_owned();
                            let Ok(number) = typed.parse::<i64>() else {
                                if !typed.is_empty() {
                                    this.error = Some("Type a whole number.".into());
                                    cx.notify();
                                }
                                return;
                            };
                            let requirement = if max {
                                Requirement::Max(number)
                            } else {
                                Requirement::Min(number)
                            };
                            let result =
                                manifest::set_requirement(&this.draft, index, os, &requirement);
                            this.edit_form(result, false, window, cx);
                        }
                    },
                );
                self.fv.panel_subs.push(subscription);
                OsInput::Limit(input)
            }
            _ => {
                let mut picks: Vec<(SharedString, Pick)> = control
                    .output
                    .values()
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
                        this.edit_form(result, false, window, cx);
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
        match (Form::parse(&self.active), Form::parse(&self.draft)) {
            (Ok(before), Ok(after)) => {
                let mut list = manifest::changes(&before, &after);
                if list.is_empty() && self.active != self.draft {
                    list.push("Other edits in the TOML".into());
                }
                list
            }
            _ if self.active != self.draft => vec!["The TOML text changed".into()],
            _ => Vec::new(),
        }
    }

    fn add_check(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        match manifest::add_control(&self.draft, id) {
            Ok((text, _)) => {
                self.fv.add_open = false;
                self.fv.filter = Filter::All;
                self.fv.selected = Some(id.to_owned());
                self.edit_form(Ok(text), true, window, cx);
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
        self.edit_form(result, true, window, cx);
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
                        if this.busy {
                            return;
                        }
                        this.form = true;
                        this.build_form(window, cx);
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
            .child(self.apply_bar(cx))
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
            .child(self.agreement(&form, inputs, disabled, cx))
            .child(self.results(&form, inputs, cx))
            .child(self.sent(&form, cx))
            .child(self.sending(&form, inputs, cx))
            .child(self.checks(&form, before.as_ref(), cx));
        div()
            .flex()
            .flex_1()
            .min_h_0()
            .child(scroll)
            .child(self.panel(&form, before.as_ref(), cx))
    }

    fn agreement(
        &self,
        form: &Form,
        inputs: &FormInputs,
        disabled: bool,
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
                                this.edit_form(result, true, window, cx);
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
                kv_row(
                    "Issuer",
                    div()
                        .w(px(440.))
                        .child(Input::new(&inputs.issuer).disabled(disabled)),
                ),
                kv_row(
                    "Valid from",
                    div()
                        .w(px(150.))
                        .child(Input::new(&inputs.valid_from).disabled(disabled)),
                ),
                kv_row(
                    "Data controller",
                    div()
                        .w(px(440.))
                        .child(Input::new(&inputs.controller).disabled(disabled)),
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

    fn results(&self, form: &Form, inputs: &FormInputs, cx: &Context<Self>) -> Div {
        let trust = seg2(
            TRUST_LEVELS
                .iter()
                .enumerate()
                .map(|(i, (key, name))| {
                    seg2_item(("trust", i), *name, form.trust == *key).on_click(cx.listener(
                        move |this, _, window, cx| {
                            let result =
                                manifest::set_top_text(&this.draft, "min_trust_level", key);
                            this.edit_form(result, false, window, cx);
                        },
                    ))
                })
                .collect(),
        );
        section(
            "Results",
            "How old a result may be, and how long the gateway keeps it.",
            rows(vec![
                kv_row(
                    "A result is valid for",
                    self.duration(&inputs.max_age, None),
                ),
                kv_row(
                    "Results are kept for",
                    self.duration(&inputs.retention, None),
                ),
                kv_row(
                    "Unknown is allowed for",
                    self.duration(&inputs.unknown_grace, Some("then it counts as failed")),
                ),
                kv_row("Device key at least", trust),
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
                            this.edit_form(result, false, window, cx);
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

    fn sending(&self, form: &Form, inputs: &FormInputs, cx: &Context<Self>) -> Div {
        let mode = form
            .schedule
            .as_ref()
            .map(|s| s.mode.as_str())
            .unwrap_or_default();
        let send = seg2(
            [("always", "Always"), ("vpn", "Only on the company VPN")]
                .into_iter()
                .enumerate()
                .map(|(i, (key, name))| {
                    seg2_item(("send", i), name, mode == key).on_click(cx.listener(
                        move |this, _, window, cx| {
                            let result = manifest::set_send_mode(&this.draft, key);
                            this.edit_form(result, true, window, cx);
                        },
                    ))
                })
                .collect(),
        );
        let mut list = vec![kv_row("Send", send)];
        if form.schedule.is_none() {
            list.push(div().child(small(
                "Devices send nothing by themselves. The owner sends by hand.",
            )));
        }
        if mode == "vpn" {
            list.push(kv_row(
                "VPN answers at",
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(
                        div()
                            .w(px(150.))
                            .font_family(mono())
                            .child(Input::new(&inputs.probe).disabled(self.busy)),
                    )
                    .child(small("shown as"))
                    .child(
                        div()
                            .w(px(180.))
                            .font_family(mono())
                            .child(Input::new(&inputs.probe_name).disabled(self.busy)),
                    ),
            ));
        }
        if form.schedule.is_some() {
            list.push(kv_row(
                "Every",
                self.duration(&inputs.interval, Some("and at once on a change")),
            ));
        }
        section(
            "Sending",
            "When devices send results on their own.",
            rows(list),
        )
    }

    fn checks(&self, form: &Form, before: Option<&Form>, cx: &Context<Self>) -> Div {
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
        let add = div()
            .relative()
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
                    .child(head("From", 92.))
                    .child(head("macOS", 92.))
                    .child(head("Windows", 92.))
                    .child(head("Linux", 92.))
                    .child(head("Grace", 52.))
                    .child(div().w(px(18.)).flex_none()),
            );
        for index in visible {
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
                        .when(changed.contains(&control.id), |name| {
                            name.child(div().size(px(7.)).flex_none().rounded_full().bg(rgb(BLUE)))
                        })
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .whitespace_nowrap()
                                .child(control.name()),
                        ),
                )
                .child(tag(&control.source));
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
        let mut list = div()
            .absolute()
            .top(px(40.))
            .right_0()
            .w(px(420.))
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
            list = list.child(
                div()
                    .px(px(10.))
                    .py(px(8.))
                    .child(small("Every built-in check is in the manifest.")),
            );
        }
        for (i, known) in options.into_iter().enumerate() {
            let id = known.id;
            list = list.child(
                div()
                    .id(("add-option", i))
                    .flex()
                    .flex_col()
                    .px(px(10.))
                    .py(px(7.))
                    .rounded(px(7.))
                    .cursor_pointer()
                    .when(i == 0, |option| option.bg(rgb(BLUE_WASH)))
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
        list
    }

    fn panel(&self, form: &Form, before: Option<&Form>, cx: &Context<Self>) -> Div {
        let shell = || {
            div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .w(px(380.))
                .flex_none()
                .h_full()
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
        let field = |name: &'static str, body: Div| {
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
        let heading = match (&control.output, manifest::builtin(control.builtin_id())) {
            (Output::Integer { .. }, Some(known)) if !known.noun.is_empty() => format!(
                "Required: {} {}",
                known.noun,
                if control.limit_is_max() {
                    "at most"
                } else {
                    "at least"
                }
            ),
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
                    if limited || panel.pending[i] {
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.))
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
                                    let Some(index) = this.selected_index() else {
                                        return;
                                    };
                                    if let Some(panel) = this.fv.panel.as_mut() {
                                        panel.pending[i] = false;
                                    }
                                    let result = manifest::set_requirement(
                                        &this.draft,
                                        index,
                                        os,
                                        &Requirement::Reported,
                                    );
                                    this.edit_form(result, false, window, cx);
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
                                    let Some(index) = this.selected_index() else {
                                        return;
                                    };
                                    let typed =
                                        match this.fv.panel.as_ref().map(|panel| &panel.os[i]) {
                                            Some(OsInput::Limit(input)) => {
                                                input.read(cx).value().trim().to_owned()
                                            }
                                            _ => String::new(),
                                        };
                                    let max = Form::parse(&this.draft)
                                        .ok()
                                        .and_then(|form| {
                                            form.controls.get(index).map(|c| c.limit_is_max())
                                        })
                                        .unwrap_or(true);
                                    match typed.parse::<i64>() {
                                        Ok(n) => {
                                            let requirement = if max {
                                                Requirement::Max(n)
                                            } else {
                                                Requirement::Min(n)
                                            };
                                            let result = manifest::set_requirement(
                                                &this.draft,
                                                index,
                                                os,
                                                &requirement,
                                            );
                                            this.edit_form(result, false, window, cx);
                                        }
                                        Err(_) => {
                                            if let Some(panel) = this.fv.panel.as_mut() {
                                                panel.pending[i] = true;
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
                    .child(div().flex_1().min_w_0().child(body)),
            );
        }
        requirements = requirements.child(os_rows);
        let unit_note = control.limit_unit();
        let _ = unit_note;
        shell()
            .child(header)
            .child(field(
                "ID",
                div()
                    .font_family(mono())
                    .child(Input::new(&panel.id).disabled(self.busy)),
            ))
            .child(field(
                "Asked for by",
                div()
                    .flex()
                    .gap(px(8.))
                    .child(
                        div()
                            .w(px(170.))
                            .flex_none()
                            .child(Select::new(&panel.source).disabled(self.busy)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(Input::new(&panel.source_ref).disabled(self.busy)),
                    ),
            ))
            .child(field(
                "Why the contractor should care",
                div().child(Textarea::new(&panel.rationale).disabled(self.busy)),
            ))
            .child(field(
                "Possible results",
                column()
                    .gap(px(6.))
                    .child(values)
                    .child(small("The check defines these. Change them in TOML.")),
            ))
            .child(field_heading(heading, requirements))
            .child(field(
                "Time to fix",
                self.duration(&panel.grace, Some("after the first failed result")),
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
        let can_review = !(self.busy
            || changes == 0
            || self.draft.parse::<toml_edit::DocumentMut>().is_err()
            || self.error.is_some());
        let shown = list.iter().take(2).cloned().collect::<Vec<_>>().join(" · ");
        let summary = if changes > 2 {
            format!("{shown} · and {} more", changes - 2)
        } else {
            shown
        };
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
                    .text_color(rgb(MUTED))
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(if changes == 0 {
                        "Form and TOML edit the same text.".to_owned()
                    } else {
                        summary
                    }),
            )
            .child(
                Button::new("discard")
                    .label("Discard")
                    .disabled(self.busy || changes == 0)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.draft = this.active.clone();
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
