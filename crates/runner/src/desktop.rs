use crate::text::{Tone, short_hash};
use crate::update::{self, Platform, UpdateState};
use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Icon, Root, Sizable, Theme, ThemeMode,
    button::{Button, ButtonVariants},
};
use std::time::Duration;

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

/// A slim strip at the top of the window while an update is on offer, running, or failed.
pub fn update_banner(
    state: &UpdateState,
    update: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> Option<Div> {
    let text = state.text()?;
    let (ink, _, wash) = tone_colors(if matches!(state, UpdateState::Failed(..)) {
        Tone::Bad
    } else {
        Tone::Info
    });
    Some(
        div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap_3()
            .px_4()
            .py(px(6.))
            .bg(rgb(wash))
            .text_color(rgb(ink))
            .text_size(px(13.))
            .font_weight(FontWeight::SEMIBOLD)
            .child(div().flex_1().min_w_0().child(text))
            .when_some(state.button(), |strip, label| {
                strip.child(
                    Button::new("update")
                        .label(label)
                        .small()
                        .primary()
                        .disabled(state.running())
                        .on_click(update),
                )
            }),
    )
}

/// Checks for a newer release once now and then every 24 hours, unless
/// `OPEN_PACT_NO_UPDATE_CHECK` turns it off. A failed check stays quiet; the Terminal strip shows it.
pub fn watch_updates<V: 'static>(
    cx: &mut Context<V>,
    runner: crate::Runner,
    state: fn(&mut V) -> &mut UpdateState,
) {
    let disabled = std::env::var("OPEN_PACT_NO_UPDATE_CHECK").ok();
    if !update::checks_enabled(disabled.as_deref()) || Platform::current() == Platform::Other {
        return;
    }
    cx.spawn(async move |this, cx| {
        loop {
            let runner = runner.with_timeout(Duration::from_secs(10));
            let found = cx
                .background_executor()
                .spawn(async move { update::check(&runner).ok().flatten() })
                .await;
            let alive = this.update(cx, |view, cx| {
                let slot = state(view);
                *slot = std::mem::take(slot).after_check(found);
                cx.notify();
            });
            if alive.is_err() {
                break;
            }
            cx.background_executor().timer(update::CHECK_EVERY).await;
        }
    })
    .detach();
}

/// Starts the update command when the banner offers one, and shows its progress in the banner.
/// `current` is the view's own state and `state` reaches it again when the command ends. The
/// command is in the Terminal log.
pub fn start_update<V: 'static>(
    current: &mut UpdateState,
    cx: &mut Context<V>,
    runner: crate::Runner,
    state: fn(&mut V) -> &mut UpdateState,
) {
    let Some(version) = current.startable().map(str::to_owned) else {
        return;
    };
    let exe = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let Some(call) = update::update_invocation(Platform::current(), &exe) else {
        return;
    };
    *current = UpdateState::Running(version.clone());
    cx.notify();
    cx.spawn(async move |this, cx| {
        let result = cx
            .background_executor()
            .spawn(async move { update::run(&runner, &call) })
            .await;
        let _ = this.update(cx, |view, cx| {
            *state(view) = match result {
                Ok(()) => UpdateState::Done(version),
                Err(error) => UpdateState::Failed(version, error),
            };
            cx.notify();
        });
    })
    .detach();
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
    nav_item_with_icon(id, None, text, selected)
}

/// A sidebar entry. The icon, when given, sits 16 px before the label in the entry's text colour.
pub fn nav_item_with_icon(
    id: impl Into<ElementId>,
    icon: Option<gpui_kit_assets::IconName>,
    text: &'static str,
    selected: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap(px(8.))
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
        .when_some(icon, |item, icon| {
            item.child(Icon::new(icon).flex_none().size_4())
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
        theme.highlight_theme = toml_highlight_theme();
    });
}

pub const KEY_INK: &str = "#7A3E9D";
pub const STRING_INK: &str = "#2E7D4F";
pub const COMMENT_INK: &str = "#8A8478";
pub const NUMBER_INK: &str = "#B4560E";

/// The code editor colours of the approved design (.k1, .s1, .c1, .n1 in design.html), applied
/// to the tree-sitter TOML highlights.
pub fn toml_highlight_theme() -> std::sync::Arc<gpui_component::highlighter::HighlightTheme> {
    use gpui_component::highlighter::HighlightTheme;
    let base = HighlightTheme::default_light();
    let mut json = serde_json::to_value(&*base).expect("highlight theme as JSON");
    let style = json["style"].as_object_mut().expect("theme style");
    style.insert("editor.background".into(), "#FBFAF7".into());
    style.insert("editor.foreground".into(), "#16202B".into());
    style.insert("editor.line_number".into(), "#A39C8E".into());
    style.insert("editor.active_line.background".into(), "#F2EFE8".into());
    style.insert("editor.active_line_number".into(), "#5B6573".into());
    let syntax = style
        .entry("syntax")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("syntax colours");
    for (name, hex) in [
        ("type", KEY_INK),
        ("property", KEY_INK),
        ("string", STRING_INK),
        ("string.special", STRING_INK),
        ("comment", COMMENT_INK),
        ("number", NUMBER_INK),
        ("boolean", NUMBER_INK),
        ("operator", "#3B4757"),
        ("punctuation", "#3B4757"),
        ("punctuation.bracket", "#3B4757"),
        ("punctuation.delimiter", "#3B4757"),
    ] {
        syntax.insert(name.into(), serde_json::json!({ "color": hex }));
    }
    std::sync::Arc::new(serde_json::from_value(json).expect("highlight theme from JSON"))
}

/// Both apps hold no background work (the scheduled job is a separate OS task), so closing the
/// last window ends the app. On macOS GPUI would otherwise keep it running with no window, and
/// the Dock icon would not bring one back.
pub const QUIT_MODE: QuitMode = QuitMode::LastWindowClosed;

actions!(open_pact, [Quit, CloseWindow, Minimize]);

/// Cmd+W, Cmd+M and Cmd+Q, with the app menu that shows them.
fn window_keys(cx: &mut App, name: &'static str) {
    cx.bind_keys([
        KeyBinding::new("cmd-w", CloseWindow, None),
        KeyBinding::new("cmd-m", Minimize, None),
        KeyBinding::new("cmd-q", Quit, None),
    ]);
    cx.on_action(|_: &Quit, cx| cx.quit());
    // GPUI holds the active window while it dispatches the key, so the window work runs after it.
    cx.on_action(|_: &CloseWindow, cx| {
        if let Some(handle) = cx.active_window() {
            cx.defer(move |cx| {
                if let Err(error) = handle.update(cx, |_, window, _| window.remove_window()) {
                    eprintln!("Cannot close the window: {error}");
                }
            });
        }
    });
    cx.on_action(|_: &Minimize, cx| {
        if let Some(handle) = cx.active_window() {
            cx.defer(move |cx| {
                if let Err(error) = handle.update(cx, |_, window, _| window.minimize_window()) {
                    eprintln!("Cannot minimize the window: {error}");
                }
            });
        }
    });
    cx.set_menus(vec![
        Menu::new(name).items([MenuItem::action(format!("Quit {name}"), Quit)]),
        Menu::new("Window").items([
            MenuItem::action("Minimize", Minimize),
            MenuItem::action("Close Window", CloseWindow),
        ]),
    ]);
}

pub fn launch<V: Render + 'static>(
    name: &'static str,
    width: f32,
    height: f32,
    create: impl FnOnce(&mut Window, &mut App) -> Entity<V> + 'static,
) {
    gpui_platform::application()
        .with_assets(gpui_kit_assets::Assets)
        .with_quit_mode(QUIT_MODE)
        .run(move |cx| {
            init(cx);
            window_keys(cx, name);
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
