//! 随身密库 App 壳。规则在 `state`，系统集成在 `shell`，命令在 `commands`。
mod clipboard;
mod commands;
mod error;
mod mcp_config;
mod screen;
mod settings;
mod shell;
mod state;

use state::AppState;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};

/// 密库目录，仅本用户可访问。
fn data_dir(app: &AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // 仅调试构建可改目录，供自动验收使用临时密库
    let dir = match std::env::var_os("SUISHEN_DATA_DIR").filter(|_| cfg!(debug_assertions)) {
        Some(d) => PathBuf::from(d),
        None => app.path().app_data_dir()?,
    };
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn setup(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new(data_dir(app)?);
    #[cfg(desktop)]
    let keys = state.settings().shortcut;
    app.manage(state);
    shell::build_window(app)?;
    #[cfg(desktop)]
    {
        shell::build_tray(app)?;
        // 快捷键被占用时应用照常启动，可在设置里改
        let _ = shell::register_shortcut(app, &keys);
    }
    shell::start_heartbeat(app);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // panic 正文可能带值，一律丢弃。AC-LOG-02
    std::panic::set_hook(Box::new(|_| {}));
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
        shell::show(app, None);
    }));
    #[cfg(desktop)]
    let builder = builder.plugin(shell::shortcut_plugin());
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| setup(app.handle()))
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<AppState>();
                if state.settings().hide_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::poll,
            commands::touch,
            commands::setup_begin,
            commands::setup_confirm,
            commands::cancel_flow,
            commands::unlock,
            commands::lock,
            commands::recovery_begin,
            commands::recovery_reissue,
            commands::recovery_confirm,
            commands::change_password,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::copy_text,
            commands::save_item,
            commands::item_action,
            commands::empty_trash,
            commands::totp_code,
            commands::generate,
            commands::open_service,
            commands::close_service,
            commands::relay_claim,
            commands::relay_forget,
            commands::pairing_begin,
            commands::pairing_accept,
            commands::pairing_cancel,
            commands::list_clients,
            commands::add_client,
            commands::rename_client,
            commands::revoke_client,
            commands::resume_client,
            commands::decide,
            commands::request_state,
            commands::audit,
            commands::mcp_config,
            commands::import_csv,
            commands::delete_csv,
            commands::export_backup,
            commands::pick_package,
            commands::restore_backup,
            commands::migration_import,
            commands::migration_begin,
            commands::migration_cancel,
            commands::migration_confirm,
            commands::wipe_retired,
            commands::set_aside,
            commands::set_settings,
        ])
        .build(tauri::generate_context!())
        .expect("Tauri 启动失败")
        .run(|app, event| match event {
            RunEvent::Exit => app.state::<AppState>().shutdown(),
            #[cfg(target_os = "macos")]
            RunEvent::Reopen { .. } => shell::show(app, None),
            _ => {}
        });
}
