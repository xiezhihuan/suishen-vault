//! 桌面壳：窗口、托盘、全局快捷键、通知、后台心跳。
use crate::state::AppState;
use std::time::Duration;
use tauri::{
    AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, webview::NewWindowResponse,
};
use tauri_plugin_notification::NotificationExt;

/// 通知文案固定，不含客户端、条目、理由。AC-GRT-16
const NOTICE_TITLE: &str = "随身密库";
const NOTICE_BODY: &str = "有新的授权申请，请打开应用核对";

pub fn build_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == "main")
        .cloned()
        .ok_or(tauri::Error::WindowNotFound)?;
    let mut window = WebviewWindowBuilder::from_config(app, &config)?
        // 只允许停留在应用自己的页面，不打开任何新窗口
        .on_navigation(allowed)
        .on_new_window(|_, _| NewWindowResponse::Deny);
    // 仅调试构建可放开截屏，供自动验收界面使用
    if cfg!(debug_assertions) && std::env::var_os("SUISHEN_ALLOW_CAPTURE").is_some() {
        window = window.content_protected(false);
    }
    debug_assert!(matches!(config.url, WebviewUrl::App(_)));
    window.build()
}

fn allowed(url: &tauri::Url) -> bool {
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        // Windows 与 Android 上应用页面的地址
        ("http" | "https", Some("tauri.localhost")) => true,
        ("http", Some("localhost")) => cfg!(dev) && url.port() == Some(1420),
        ("about", None) => url.path() == "blank",
        _ => false,
    }
}

pub fn show(app: &AppHandle, target: Option<&'static str>) {
    if let Some(t) = target {
        app.state::<AppState>().navigate(t);
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        #[cfg(desktop)]
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg(desktop)]
pub fn register_shortcut(app: &AppHandle, keys: &str) -> Result<(), &'static str> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
    let manager = app.global_shortcut();
    let _ = manager.unregister_all();
    if keys.trim().is_empty() {
        return Ok(());
    }
    let parsed: Shortcut = keys
        .parse()
        .map_err(|_| "快捷键格式不正确，例如 CmdOrCtrl+Alt+K")?;
    if parsed.mods.is_empty() {
        return Err("快捷键须包含 Ctrl、Alt、Shift 或 Cmd");
    }
    manager
        .register(parsed)
        .map_err(|_| "快捷键已被其他程序占用，请换一个")
}

#[cfg(mobile)]
pub fn register_shortcut(_: &AppHandle, _: &str) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(desktop)]
pub fn shortcut_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    use tauri_plugin_global_shortcut::{Builder, ShortcutState};
    Builder::new()
        .with_handler(|app, _, event| {
            if event.state == ShortcutState::Pressed {
                show(app, Some("search"));
            }
        })
        .build()
}

#[cfg(desktop)]
pub fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    use tauri::{
        menu::{Menu, MenuItem, PredefinedMenuItem},
        tray::TrayIconBuilder,
    };
    let item = |id: &str, text: &str| MenuItem::with_id(app, id, text, true, None::<&str>);
    let menu = Menu::with_items(
        app,
        &[
            &item("open", "打开随身密库")?,
            &item("search", "搜索")?,
            &item("requests", "查看授权申请")?,
            &PredefinedMenuItem::separator(app)?,
            &item("lock", "立即锁定")?,
            &item("close_all", "全部关闭并撤销授权")?,
            &PredefinedMenuItem::separator(app)?,
            &item("quit", "退出")?,
        ],
    )?;
    TrayIconBuilder::with_id("main")
        .icon(tauri::include_image!("icons/tray.png"))
        .icon_as_template(true)
        .tooltip("随身密库")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show(app, None),
            "search" => show(app, Some("search")),
            "requests" => show(app, Some("requests")),
            "quit" => app.exit(0),
            // 关闭与锁定会等待正在进行的操作，不能占住主线程
            id @ ("lock" | "close_all") => {
                let close = id == "close_all";
                let app = app.clone();
                std::thread::spawn(move || {
                    let state = app.state::<AppState>();
                    if close {
                        state.service.close();
                    } else {
                        state.lock();
                    }
                });
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn notify(app: &AppHandle) {
    let _ = app
        .notification()
        .builder()
        .title(NOTICE_TITLE)
        .body(NOTICE_BODY)
        .show();
}

pub fn start_heartbeat(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let mut shown = None;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let state = app.state::<AppState>();
            let tick = state.tick(crate::screen::locked());
            // 不自动跳到申请页：可能有没保存的编辑，而且突然切页容易误点。界面有醒目横幅。
            if tick.new_request && state.settings().notify {
                notify(&app);
            }
            let scope = state.service.scope();
            if shown != Some(scope) {
                shown = Some(scope);
                #[cfg(desktop)]
                if let Some(tray) = app.tray_by_id("main") {
                    let _ = tray.set_tooltip(Some(tooltip(scope)));
                }
            }
        }
    });
}

#[cfg(desktop)]
fn tooltip(scope: vault_core::ExposureScope) -> &'static str {
    use vault_core::ExposureScope as S;
    match scope {
        S::Closed => "随身密库 · 开放范围：关闭",
        S::Loopback => "随身密库 · 开放范围：仅本机",
        S::Lan => "随身密库 · 开放范围：局域网",
        S::Public => "随身密库 · 开放范围：公网",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_stays_inside_the_app() {
        for ok in ["tauri://localhost/", "http://tauri.localhost/index.html"] {
            assert!(allowed(&ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "https://example.com/",
            "http://localhost:8080/",
            "tauri://evil/",
            "file:///etc/hosts",
            "data:text/html,x",
            "https://tauri.localhost.example.com/",
        ] {
            assert!(!allowed(&bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn notice_is_a_fixed_text() {
        assert!(!NOTICE_BODY.contains('{') && !NOTICE_TITLE.contains('{'));
    }
}
