use gpui::{prelude::*, *};
use gpui_component::{Root, Theme, ThemeMode};

pub const PAPER: u32 = 0xf5f3ee;
pub const INK: u32 = 0x16202b;
pub const MUTED: u32 = 0x5b6573;
pub const RULE: u32 = 0xe2ddd2;
pub const BLUE: u32 = 0x2f64c8;

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

pub fn row(key: impl Into<SharedString>, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .justify_between()
        .gap_4()
        .py_1()
        .border_b_1()
        .border_color(rgb(RULE))
        .child(key.into())
        .child(div().text_color(rgb(0x3b4757)).child(value.into()))
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

pub fn terminal(runner: &crate::Runner) -> Div {
    let logs = runner.logs();
    let mut panel = column()
        .p_4()
        .bg(rgb(0x1b232d))
        .text_color(rgb(0xd8dee6))
        .text_size(px(12.));
    if logs.is_empty() {
        panel = panel.child("No commands yet.");
    }
    for log in logs {
        if let Some(input) = &log.stdin {
            panel = panel.child(note(format!("stdin\n{input}")));
        }
        panel = panel
            .child(div().text_color(rgb(0x8fb4f0)).child(log.display()))
            .child(log.stdout)
            .child(div().text_color(rgb(0xe3b776)).child(log.stderr))
            .child(format!("Exit {:?}", log.exit));
    }
    panel
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
