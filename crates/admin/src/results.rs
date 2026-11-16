//! The Results screen: every check result the gateway stores, the filters above the table, and
//! the detail panel of one result. It only runs `claims list` and `claims show` through kubectl.
use super::*;
use runner::results::{
    self, Claim, ClaimControl, ClaimDetail, ClaimList, ControlStatus, Filters, OLD_GATEWAY, Period,
    ResultFilter,
};

const PANEL_BG: u32 = 0xfbfaf7;
const ROW_HOVER: u32 = 0xfaf8f4;
const ALL_DEVICES: &str = "All devices";

/// What a gateway command answered, as the screen shows it.
pub enum Fetch<T> {
    Idle,
    Loading,
    Ready(T),
    Failed(String),
}

/// What the Results screen holds for one gateway. It has no window or entity, so a test can drive it.
pub struct ResultsState {
    pub filters: Filters,
    pub list: Fetch<ClaimList>,
    /// The command the list ran, shown quietly under the table.
    pub command: String,
    pub selected: Option<u64>,
    pub detail: Fetch<ClaimDetail>,
    list_generation: u64,
    detail_generation: u64,
}

impl Default for ResultsState {
    fn default() -> Self {
        Self {
            filters: Filters::default(),
            list: Fetch::Idle,
            command: String::new(),
            selected: None,
            detail: Fetch::Idle,
            list_generation: 0,
            detail_generation: 0,
        }
    }
}

impl ResultsState {
    /// Starts a list read. Only the reply of the newest read is kept.
    fn next_list_generation(&mut self) -> u64 {
        self.list_generation += 1;
        self.list_generation
    }

    fn next_detail_generation(&mut self) -> u64 {
        self.detail_generation += 1;
        self.detail_generation
    }

    fn list_is_current(&self, generation: u64) -> bool {
        self.list_generation == generation
    }

    fn detail_is_current(&self, generation: u64) -> bool {
        self.detail_generation == generation
    }

    /// Drops everything that belongs to the gateway the screen read. Its replies still on the way are ignored.
    /// The result and period filters stay.
    pub fn forget_gateway(&mut self) {
        self.filters.device = None;
        self.list = Fetch::Idle;
        self.command.clear();
        self.selected = None;
        self.detail = Fetch::Idle;
        self.next_list_generation();
        self.next_detail_generation();
    }
}

pub struct ResultsView {
    pub state: ResultsState,
    pub device: Choice,
    pub period: Choice,
    /// The device menu: each label and the device code it stands for. The first is "All devices".
    pub devices: Vec<(SharedString, Option<String>)>,
    pub subscriptions: Vec<Subscription>,
}

impl ResultsView {
    pub fn new(window: &mut Window, cx: &mut Context<AppView>) -> Self {
        let device = cx.new(|cx| SelectState::new(Vec::<SharedString>::new(), None, window, cx));
        let period = cx.new(|cx| {
            let items: Vec<SharedString> = Period::ALL.map(|p| p.label().into()).into();
            SelectState::new(items, None, window, cx)
        });
        let subscriptions = vec![
            cx.subscribe_in(
                &device,
                window,
                |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                    let SelectEvent::Confirm(Some(label)) = event else {
                        return;
                    };
                    let Some((_, code)) = this
                        .results
                        .devices
                        .iter()
                        .find(|(known, _)| known == label)
                    else {
                        return;
                    };
                    let mut filters = this.results.state.filters.clone();
                    filters.device = code.clone();
                    this.apply_filters(filters, window, cx);
                },
            ),
            cx.subscribe_in(
                &period,
                window,
                |this, _, event: &SelectEvent<Vec<SharedString>>, window, cx| {
                    let SelectEvent::Confirm(Some(label)) = event else {
                        return;
                    };
                    let Some(period) = Period::ALL
                        .into_iter()
                        .find(|p| p.label() == label.as_ref())
                    else {
                        return;
                    };
                    let mut filters = this.results.state.filters.clone();
                    filters.period = period;
                    this.apply_filters(filters, window, cx);
                },
            ),
        ];
        Self {
            state: ResultsState::default(),
            device,
            period,
            devices: vec![(ALL_DEVICES.into(), None)],
            subscriptions,
        }
    }
}

fn device_label(device: &Device) -> String {
    if device.note.trim().is_empty() {
        device.code.clone()
    } else {
        format!("{} · {}", device.note.trim(), device.code)
    }
}

impl AppView {
    /// Fills the device menu with the approved and waiting devices, and shows the filters in both
    /// menus.
    pub fn sync_result_devices(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut devices: Vec<(SharedString, Option<String>)> = vec![(ALL_DEVICES.into(), None)];
        if let Some(overview) = &self.overview {
            for device in overview
                .devices
                .iter()
                .filter(|d| matches!(d.state.as_str(), "approved" | "pending"))
            {
                devices.push((device_label(device).into(), Some(device.code.clone())));
            }
        }
        if let Some(code) = &self.results.state.filters.device
            && !devices
                .iter()
                .any(|(_, known)| known.as_ref() == Some(code))
        {
            devices.push((code.clone().into(), Some(code.clone())));
        }
        let labels: Vec<SharedString> = devices.iter().map(|(label, _)| label.clone()).collect();
        self.results.devices = devices;
        self.results.device.update(cx, |state, cx| {
            state.set_items(labels, window, cx);
        });
        self.show_filter_choices(window, cx);
    }

    /// Selects the menu entries that the current filters name.
    fn show_filter_choices(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let device = self
            .results
            .devices
            .iter()
            .find(|(_, code)| *code == self.results.state.filters.device)
            .map(|(label, _)| label.clone());
        self.results.device.update(cx, |state, cx| match device {
            Some(label) => state.set_selected_value(&label, window, cx),
            None => state.set_selected_index(None, window, cx),
        });
        let period: SharedString = self.results.state.filters.period.label().into();
        self.results.period.update(cx, |state, cx| {
            state.set_selected_value(&period, window, cx)
        });
    }

    /// Opens the screen with the filters it had, and reads the results again.
    pub fn open_results(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.screen = Screen::Results;
        self.sync_result_devices(window, cx);
        self.reload_results(window, cx);
    }

    /// Opens the screen for one device, as the Overview rows ask.
    pub fn show_device_results(
        &mut self,
        code: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.results.state.filters = Filters {
            device: Some(code),
            ..Filters::default()
        };
        self.results.state.selected = None;
        self.results.state.detail = Fetch::Idle;
        self.open_results(window, cx);
    }

    /// Changes the filters and reads the list again. The same filters read nothing.
    pub fn apply_filters(&mut self, filters: Filters, window: &mut Window, cx: &mut Context<Self>) {
        if filters == self.results.state.filters {
            return;
        }
        self.results.state.filters = filters;
        self.show_filter_choices(window, cx);
        self.reload_results(window, cx);
    }

    pub fn reload_results(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let generation = self.results.state.next_list_generation();
        self.results.state.list = Fetch::Loading;
        let now = results::now();
        let filters = self.results.state.filters.clone();
        self.results.state.command = Admin::claims_command(&filters, now);
        let admin = self.admin.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { admin.claims(&filters, now) })
                .await;
            let _ = this.update_in(cx, |this, _, cx| {
                if !this.results.state.list_is_current(generation) {
                    return;
                }
                this.results.state.list = match result {
                    Ok(list) => Fetch::Ready(list),
                    Err(error) => Fetch::Failed(error),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub fn open_claim(&mut self, id: u64, window: &mut Window, cx: &mut Context<Self>) {
        let generation = self.results.state.next_detail_generation();
        self.results.state.selected = Some(id);
        self.results.state.detail = Fetch::Loading;
        let admin = self.admin.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { admin.claim(id) })
                .await;
            let _ = this.update_in(cx, |this, _, cx| {
                if !this.results.state.detail_is_current(generation) {
                    return;
                }
                this.results.state.detail = match result {
                    Ok(detail) => Fetch::Ready(detail),
                    Err(error) => Fetch::Failed(error),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn close_claim(&mut self, cx: &mut Context<Self>) {
        self.results.state.next_detail_generation();
        self.results.state.selected = None;
        self.results.state.detail = Fetch::Idle;
        cx.notify();
    }

    /// Clears the Results screen when a new connection is saved, so no panel shows another gateway's data.
    pub fn forget_results_gateway(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.results.state.forget_gateway();
        self.sync_result_devices(window, cx);
    }

    pub fn results_screen(&self, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .flex_1()
            .h_full()
            .min_w_0()
            .child(self.results_main(cx))
            .when_some(self.results.state.selected, |screen, _| {
                screen.child(self.result_panel(cx))
            })
    }

    fn results_main(&self, cx: &Context<Self>) -> Stateful<Div> {
        let state = &self.results.state;
        let loading = matches!(state.list, Fetch::Loading);
        let field = |name: &'static str, body: AnyElement| {
            column().gap_1p5().child(label(name)).child(body)
        };
        let bar = div()
            .flex()
            .flex_wrap()
            .items_end()
            .gap_4()
            .child(field(
                "Device",
                div()
                    .w(px(280.))
                    .child(Select::new(&self.results.device).placeholder(ALL_DEVICES))
                    .into_any_element(),
            ))
            .child(field(
                "Result",
                seg(ResultFilter::ALL
                    .into_iter()
                    .enumerate()
                    .map(|(i, result)| {
                        seg_item(
                            ("result-filter", i),
                            result.label(),
                            state.filters.result == result,
                        )
                        .on_click(cx.listener(
                            move |this, _, window, cx| {
                                let mut filters = this.results.state.filters.clone();
                                filters.result = result;
                                this.apply_filters(filters, window, cx);
                            },
                        ))
                    })
                    .collect())
                .into_any_element(),
            ))
            .child(field(
                "Period",
                div()
                    .w(px(150.))
                    .child(Select::new(&self.results.period))
                    .into_any_element(),
            ))
            .child(
                Button::new("results-refresh")
                    .label("Refresh")
                    .small()
                    .disabled(loading)
                    .on_click(cx.listener(|this, _, window, cx| this.reload_results(window, cx))),
            );
        let body: AnyElement = match &state.list {
            Fetch::Idle => div().into_any_element(),
            Fetch::Loading => note("Loading results...").into_any_element(),
            Fetch::Failed(error) if error == OLD_GATEWAY => {
                banner(error.clone(), 0x7a4708, 0xfbeedc).into_any_element()
            }
            Fetch::Failed(error) => error_block(error.clone()).into_any_element(),
            Fetch::Ready(list) if list.claims.is_empty() => self.no_results(cx).into_any_element(),
            Fetch::Ready(list) => self.result_table(list, cx).into_any_element(),
        };
        let unreadable = match &state.list {
            Fetch::Ready(list) => results::unreadable_text(list.unreadable),
            _ => None,
        };
        column()
            .id("results-main")
            .flex_1()
            .h_full()
            .min_w_0()
            .overflow_y_scroll()
            .gap(px(18.))
            .px(px(28.))
            .py(px(24.))
            .child(title("Results"))
            .child(bar)
            .child(body)
            .children(unreadable.map(note))
            .when(!state.command.is_empty(), |view| {
                view.child(runs("runs", state.command.clone()))
            })
            .children(self.status.clone().map(note))
            .children(self.error.clone().map(|error| banner(error, BAD, BAD_WASH)))
    }

    fn no_results(&self, cx: &Context<Self>) -> Div {
        if self.results.state.filters.is_default() {
            return column().child(note("No results yet."));
        }
        column()
            .items_start()
            .child(
                div()
                    .text_color(rgb(INK_2))
                    .child("No results for these filters."),
            )
            .child(
                Button::new("clear-result-filters")
                    .label("Clear filters")
                    .small()
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.apply_filters(Filters::default(), window, cx);
                    })),
            )
    }

    fn result_table(&self, list: &ClaimList, cx: &Context<Self>) -> Div {
        let head = div()
            .flex()
            .gap_3()
            .py(px(10.))
            .border_b_1()
            .border_color(rgb(RULE_2))
            .text_size(px(12.))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(MUTED))
            .child(div().w(px(140.)).flex_none().child("Time"))
            .child(div().flex_1().min_w_0().child("Device"))
            .child(div().w(px(100.)).flex_none().child("Result"))
            .child(div().flex_1().min_w_0().child("Failed checks"));
        let mut table = table().child(head);
        for (index, claim) in list.claims.iter().enumerate() {
            table = table.child(self.result_row(index, claim, cx));
        }
        table
    }

    fn result_row(&self, index: usize, claim: &Claim, cx: &Context<Self>) -> Stateful<Div> {
        let selected = self.results.state.selected == Some(claim.id);
        let id = claim.id;
        let (words, tone) = results::result_tag(claim.result.as_deref());
        let note_text = claim
            .device_note
            .as_deref()
            .filter(|text| !text.trim().is_empty())
            .unwrap_or("No note");
        div()
            .id(("claim", index))
            .flex()
            .gap_3()
            .px(px(10.))
            .mx(px(-10.))
            .py(px(10.))
            .border_b_1()
            .border_color(rgb(RULE_2))
            .cursor_pointer()
            .when(selected, |row| {
                row.bg(rgb(BLUE_WASH)).rounded(px(8.)).border_color(rgba(0))
            })
            .when(!selected, |row| row.hover(|hover| hover.bg(rgb(ROW_HOVER))))
            .child(
                div()
                    .w(px(140.))
                    .flex_none()
                    .child(readable_local(&claim.received_at)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(note_text.to_owned())
                    .child(
                        div()
                            .font_family(mono())
                            .text_size(px(12.))
                            .text_color(rgb(MUTED))
                            .child(claim.code()),
                    ),
            )
            .child(
                div()
                    .w(px(100.))
                    .flex_none()
                    .flex()
                    .items_start()
                    .child(pill(words, tone)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_size(px(13.))
                    .text_color(rgb(INK_2))
                    .child(claim.failed_text()),
            )
            .on_click(cx.listener(move |this, _, window, cx| this.open_claim(id, window, cx)))
    }

    fn result_panel(&self, cx: &Context<Self>) -> Stateful<Div> {
        let shell = div()
            .id("result-panel")
            .flex()
            .flex_col()
            .gap(px(14.))
            .w(px(400.))
            .flex_none()
            .h_full()
            .overflow_y_scroll()
            .p(px(22.))
            .border_l_1()
            .border_color(rgb(RULE))
            .bg(rgb(PANEL_BG));
        let header = div()
            .flex()
            .items_center()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .text_size(px(18.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Result"),
            )
            .child(
                ghost("close-result", "Close")
                    .on_click(cx.listener(|this, _, _, cx| this.close_claim(cx))),
            );
        let shell = shell.child(header);
        match &self.results.state.detail {
            Fetch::Idle => shell,
            Fetch::Loading => shell.child(note("Loading result...")),
            Fetch::Failed(error) => shell.child(error_block(error.clone())),
            Fetch::Ready(detail) => shell.child(detail_body(detail)),
        }
    }
}

fn fact(name: &'static str, value: impl IntoElement) -> Div {
    div()
        .flex()
        .items_start()
        .gap_3()
        .py(px(6.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .child(
            div()
                .w(px(96.))
                .flex_none()
                .text_size(px(13.))
                .text_color(rgb(MUTED))
                .child(name),
        )
        .child(div().flex_1().min_w_0().text_color(rgb(INK_2)).child(value))
}

fn detail_body(detail: &ClaimDetail) -> Div {
    let (words, tone) = results::result_tag(detail.result.as_deref());
    let device = div()
        .flex()
        .flex_col()
        .child(
            detail
                .device_note
                .as_deref()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or("No note")
                .to_owned(),
        )
        .child(
            div()
                .font_family(mono())
                .text_size(px(12.))
                .text_color(rgb(MUTED))
                .child(detail.code()),
        );
    let mut body = column()
        .gap(px(14.))
        .child(
            column()
                .gap_0()
                .child(fact("Claim id", detail.id.to_string()))
                .child(fact("Time", readable_local(&detail.received_at)))
                .child(fact("Device", device))
                .child(fact("Manifest", hash_chip(&detail.manifest_hash)))
                .child(fact("Result", div().flex().child(pill(words, tone)))),
        )
        .child(label("Checks"));
    if detail.controls.is_empty() {
        body = body.child(note("This result lists no checks."));
    }
    for control in detail.ordered() {
        body = body.child(control_block(control));
    }
    body
}

fn control_block(control: &ClaimControl) -> Div {
    let (words, tone) = results::status_tag(control.status);
    let mut facts = format!(
        "Value {} · Required {} · Grace {}",
        control.value_text(),
        control.required_text(),
        control.grace_text()
    );
    if control.status == ControlStatus::NotRequired {
        facts = format!("Value {}", control.value_text());
    }
    let when = (control.first_failed_at.is_some() || control.deadline.is_some()).then(|| {
        format!(
            "First failed {} · Deadline {}",
            control.first_failed_text(),
            control.deadline_text()
        )
    });
    column()
        .gap(px(3.))
        .pb(px(10.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(control.name()),
                )
                .child(pill(words, tone)),
        )
        .child(note(facts))
        .children(when.map(note))
}

#[cfg(test)]
mod tests {
    // A glob import would bring gpui's `test` attribute into scope and shadow `#[test]`.
    use super::{Fetch, Filters, Period, ResultFilter, ResultsState};

    #[test]
    fn forgetting_a_gateway_drops_its_panel_and_late_replies() {
        let mut state = ResultsState {
            filters: Filters {
                device: Some("7c09e1f4a2b8".to_owned()),
                result: ResultFilter::Denied,
                period: Period::Month,
            },
            list: Fetch::Loading,
            selected: Some(4814),
            detail: Fetch::Loading,
            ..ResultsState::default()
        };
        let list = state.next_list_generation();
        let detail = state.next_detail_generation();

        state.forget_gateway();

        assert_eq!(
            state.filters,
            Filters {
                device: None,
                result: ResultFilter::Denied,
                period: Period::Month,
            }
        );
        assert!(matches!(state.list, Fetch::Idle));
        assert_eq!(state.selected, None);
        assert!(matches!(state.detail, Fetch::Idle));
        assert!(!state.list_is_current(list));
        assert!(!state.detail_is_current(detail));

        let fresh_list = state.next_list_generation();
        let fresh_detail = state.next_detail_generation();
        assert!(state.list_is_current(fresh_list));
        assert!(state.detail_is_current(fresh_detail));
    }
}
