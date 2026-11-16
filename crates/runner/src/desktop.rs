use crate::text::{Tone, short_hash};
use gpui::{prelude::*, *};
use gpui_component::{
    Root, Sizable, Theme, ThemeMode,
    button::{Button, ButtonVariants},
};

pub const PAPER: u32 = 0xf5f3ee;
pub const INK: u32 = 0x16202b;
pub const INK_2: u32 = 0x3b4757;
pub const MUTED: u32 = 0x5b6573;
pub const RULE: u32 = 0xe2ddd2;
pub const RULE_2: u32 = 0xeeeae2;
pub const BLUE: u32 = 0x2f64c8;
pub const BLUE_INK: u32 = 0x1f4fa8;
pub const BLUE_WASH: u32 = 0xe9eef8;
pub const BAD: u32 = 0xb3261e;
pub const BAD_WASH: u32 = 0xfbe6e4;
pub const SIDE: u32 = 0xf7f5f0;
pub const SIDE_ON: u32 = 0xe8e3d8;
pub const FIELD_BORDER: u32 = 0xcfc8ba;
const TERM: u32 = 0x1b232d;
const TERM_INK: u32 = 0xd8dee6;
const TERM_DIM: u32 = 0x8a96a6;

/// Text colour, dot colour and background wash for a tone, as in the approved design.
pub fn tone_colors(tone: Tone) -> (u32, u32, u32) {
    match tone {
        Tone::Good => (0x1f5e3a, 0x2e7d4f, 0xe5f2ea),
        Tone::Warn => (0x7a4708, 0xc77a14, 0xfbeedc),
        Tone::Bad => (0x8c1d17, BAD, BAD_WASH),
        Tone::Info => (BLUE_INK, BLUE, BLUE_WASH),
        Tone::Idle => (INK_2, 0x6b7280, 0xeceae5),
    }
}

pub fn mono() -> &'static str {
    if cfg!(windows) {
        "Consolas"
    } else if cfg!(target_os = "macos") {
        "Menlo"
    } else {
        "DejaVu Sans Mono"
    }
}

pub fn column() -> Div {
    div().flex().flex_col().gap_3()
}

pub fn title(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(22.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

pub fn note(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(13.))
        .text_color(rgb(MUTED))
        .child(text.into())
}

pub fn label(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(INK_2))
        .child(text.into())
}

pub fn code(text: impl Into<SharedString>) -> Div {
    div()
        .min_w_0()
        .px(px(7.))
        .py(px(2.))
        .rounded(px(5.))
        .bg(rgb(BLUE_WASH))
        .text_color(rgb(BLUE_INK))
        .text_size(px(12.))
        .font_family(mono())
        .child(text.into())
}

/// The command a button runs, shown quietly as in the design.
pub fn runs(prefix: impl Into<SharedString>, command: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap_2()
        .text_size(px(12.))
        .text_color(rgb(MUTED))
        .child(prefix.into())
        .child(code(command))
}

pub fn table() -> Div {
    div().flex().flex_col().border_t_1().border_color(rgb(RULE))
}

pub fn row(key: impl IntoElement, value: impl IntoElement) -> Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_4()
        .py(px(9.))
        .border_b_1()
        .border_color(rgb(RULE_2))
        .child(key)
        .child(div().text_color(rgb(INK_2)).child(value))
}

pub fn hash_chip(hash: &str) -> Div {
    code(short_hash(hash))
}

pub fn dot(color: u32) -> Div {
    div()
        .size(px(12.))
        .flex_none()
        .rounded_full()
        .bg(rgb(color))
}

pub fn verdict(
    tone: Tone,
    heading: impl Into<SharedString>,
    detail: impl Into<SharedString>,
) -> Div {
    let (ink, dot_color, wash) = tone_colors(tone);
    let detail = detail.into();
    div()
        .flex()
        .items_center()
        .gap_3()
        .px_4()
        .py_3()
        .rounded(px(10.))
        .bg(rgb(wash))
        .child(dot(dot_color))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .gap_0p5()
                .child(
                    div()
                        .text_size(px(18.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(ink))
                        .child(heading.into()),
                )
                .when(!detail.is_empty(), |view| view.child(note(detail))),
        )
}

pub fn banner(text: impl Into<SharedString>, color: u32, wash: u32) -> Div {
    div()
        .p_4()
        .rounded_lg()
        .bg(rgb(wash))
        .text_color(rgb(color))
        .text_lg()
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

/// A parse or validation problem shown as plain red text, not as a heading.
pub fn error_block(text: impl Into<SharedString>) -> Div {
    div()
        .px_3()
        .py_2()
        .rounded(px(8.))
        .bg(rgb(BAD_WASH))
        .text_color(rgb(BAD))
        .text_size(px(13.))
        .font_family(mono())
        .child(text.into())
}

pub fn pill(text: impl Into<SharedString>, tone: Tone) -> Div {
    let (ink, _, wash) = tone_colors(tone);
    div()
        .px(px(9.))
        .py(px(3.))
        .rounded_full()
        .bg(rgb(wash))
        .text_color(rgb(ink))
        .text_size(px(12.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

pub fn actions() -> Div {
    div().flex().justify_end().items_center().gap_2()
}

pub fn ghost(id: impl Into<ElementId>, text: impl Into<SharedString>) -> Button {
    Button::new(id).label(text).ghost().small()
}

pub fn seg_item(id: impl Into<ElementId>, text: &'static str, selected: bool) -> Stateful<Div> {
    div()
        .id(id)
        .px(px(14.))
        .py(px(6.))
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .when(selected, |item| item.bg(rgb(INK)).text_color(rgb(0xffffff)))
        .when(!selected, |item| {
            item.text_color(rgb(INK_2))
                .hover(|hover| hover.bg(rgb(SIDE)))
        })
        .child(text)
}

pub fn seg(items: Vec<Stateful<Div>>) -> Div {
    div()
        .flex()
        .self_start()
        .overflow_hidden()
        .rounded(px(8.))
        .border_1()
        .border_color(rgb(FIELD_BORDER))
        .children(items)
}

pub fn tab_item(id: impl Into<ElementId>, text: String, selected: bool) -> Stateful<Div> {
    div()
        .id(id)
        .px(px(14.))
        .py(px(8.))
        .mb(px(-1.))
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .border_b_2()
        .when(selected, |tab| {
            tab.text_color(rgb(INK)).border_color(rgb(INK))
        })
        .when(!selected, |tab| {
            tab.text_color(rgb(MUTED)).border_color(rgba(0))
        })
        .child(text)
}

pub fn tabs(items: Vec<Stateful<Div>>) -> Div {
    div()
        .flex()
        .gap_1()
        .border_b_1()
        .border_color(rgb(RULE))
        .children(items)
}

pub fn nav_item(id: impl Into<ElementId>, text: &'static str, selected: bool) -> Stateful<Div> {
    div()
        .id(id)
        .px(px(12.))
        .py(px(8.))
        .rounded(px(7.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .when(selected, |item| item.bg(rgb(SIDE_ON)).text_color(rgb(INK)))
        .when(!selected, |item| {
            item.text_color(rgb(INK_2))
                .hover(|hover| hover.bg(rgb(0xefece4)))
        })
        .child(text)
}

pub fn terminal(runner: &crate::Runner) -> Div {
    let logs = runner.logs();
    let mut panel = div()
        .flex()
        .flex_col()
        .gap_1()
        .text_size(px(12.5))
        .font_family(mono())
        .text_color(rgb(TERM_INK));
    if logs.is_empty() {
        panel = panel.child(div().text_color(rgb(TERM_DIM)).child("No commands yet."));
    }
    for log in logs {
        if let Some(input) = &log.stdin {
            panel = panel.child(
                div()
                    .text_color(rgb(TERM_DIM))
                    .child(format!("stdin\n{input}")),
            );
        }
        panel = panel
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().text_color(rgb(0x8fb4f0)).child("$"))
                    .child(log.display()),
            )
            .child(div().text_color(rgb(TERM_DIM)).child(log.stdout))
            .child(div().text_color(rgb(0xe3b776)).child(log.stderr))
            .child(
                div()
                    .text_color(rgb(TERM_DIM))
                    .child(format!("Exit {:?}", log.exit)),
            );
    }
    panel
}

/// A quiet dark strip at the bottom of the window. Its header opens and closes the command log.
pub fn terminal_drawer(
    open: bool,
    runner: &crate::Runner,
    toggle: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> Div {
    div()
        .flex()
        .flex_col()
        .flex_none()
        .bg(rgb(TERM))
        .border_t_1()
        .border_color(rgb(0x0e141b))
        .child(
            div()
                .id("terminal")
                .flex()
                .justify_between()
                .px_4()
                .py(px(7.))
                .cursor_pointer()
                .text_size(px(11.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(TERM_DIM))
                .on_click(toggle)
                .child("TERMINAL")
                .child(if open { "hide" } else { "show" }),
        )
        .when(open, |drawer| {
            drawer.child(
                div()
                    .id("terminal-log")
                    .max_h(px(220.))
                    .overflow_y_scroll()
                    .px_4()
                    .pb_3()
                    .child(terminal(runner)),
            )
        })
}

pub fn init(cx: &mut App) {
    gpui_component::init(cx);
    Theme::change(ThemeMode::Light, None, cx);
    Theme::update(cx, |theme| {
        theme.font_size = px(15.);
        theme.primary = rgb(BLUE).into();
        theme.primary_hover = rgb(0x1f4fa8).into();
        theme.primary_active = rgb(0x1f4fa8).into();
        theme.button_primary = rgb(BLUE).into();
        theme.primary_foreground = rgb(0xffffff).into();
        theme.radius = px(8.);
        theme.border = rgb(FIELD_BORDER).into();
    });
}

pub fn launch<V: Render + 'static>(
    name: &'static str,
    width: f32,
    height: f32,
    create: impl FnOnce(&mut Window, &mut App) -> Entity<V> + 'static,
) {
    gpui_platform::application()
        .with_assets(gpui_kit_assets::Assets)
        .run(move |cx| {
            init(cx);
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                        None,
                        size(px(width), px(height)),
                        cx,
                    ))),
                    titlebar: Some(TitlebarOptions {
                        title: Some(name.into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| {
                    let view = create(window, cx);
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )
            .expect("app window");
            cx.activate(true);
        });
}

#[cfg(all(feature = "snapshot", target_os = "macos"))]
pub fn snapshot<V: Render + 'static>(
    output: &std::path::Path,
    name: &str,
    width: f32,
    height: f32,
    create: impl FnOnce(&mut Window, &mut App) -> Entity<V>,
) {
    use std::sync::Arc;
    let mut cx = HeadlessAppContext::with_platform(
        Arc::new(gpui_apple::AppleTextSystem::new()),
        Arc::new(gpui_kit_assets::Assets),
        gpui_platform::current_headless_renderer,
    );
    cx.update(init);
    let handle = cx
        .open_window(size(px(width), px(height)), |window, cx| {
            let view = create(window, cx);
            cx.new(|cx| Root::new(view, window, cx))
        })
        .expect("snapshot window");
    for _ in 0..3 {
        cx.run_until_parked();
        cx.update_window(handle.into(), |_, window, cx| {
            window.refresh();
            window.draw(cx).clear(cx);
        })
        .expect("draw");
    }
    cx.capture_screenshot(handle.into())
        .expect("screenshot")
        .save(output.join(format!("{name}.png")))
        .expect("save screenshot");
    cx.update_window(handle.into(), |_, window, _| window.remove_window())
        .expect("close snapshot window");
}
