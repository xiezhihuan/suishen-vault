//! 主窗口专用的进程内命令。HTTP 与 stdio 没有任何管理或批准入口。
//!
//! 命令名同时列在 `build.rs`，并由 `capabilities/main.json` 逐条授予主窗口。
use crate::{
    error::{Ui, UiError, fail},
    settings::Settings,
    state::{AppState, Credential, Decision, DraftIn, OpenScope, Secret, SecretField},
};
use serde::Deserialize;
use serde_json::Value;
#[cfg(not(target_os = "android"))]
use std::path::PathBuf;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
#[cfg(not(target_os = "android"))]
use tauri_plugin_dialog::FilePath;
use vault_core::{GeneratorOptions, generate_password, model::AiField};

type App<'a> = State<'a, AppState>;

#[tauri::command(async)]
pub fn poll(app: App<'_>) -> Value {
    app.poll()
}
#[tauri::command(async)]
pub fn touch(app: App<'_>) {
    app.touch();
}

// ---- 首次设置、解锁、恢复 ----

#[tauri::command(async)]
pub fn setup_begin(app: App<'_>, password: Secret) -> Ui<Value> {
    app.setup_begin(&password.0)
}
#[tauri::command(async)]
pub fn setup_confirm(app: App<'_>, answers: Vec<Secret>) -> Ui<()> {
    app.setup_confirm(&answers)
}
#[tauri::command(async)]
pub fn cancel_flow(app: App<'_>) {
    app.cancel_flow();
}
#[tauri::command(async)]
pub fn unlock(app: App<'_>, password: Secret) -> Ui<()> {
    app.unlock(&password.0)
}
#[tauri::command(async)]
pub fn lock(handle: AppHandle, app: App<'_>) {
    app.lock();
    crate::shell::dismiss_entry_assistant(&handle);
}
#[tauri::command(async)]
pub fn recovery_begin(app: App<'_>, key: Secret, password: Secret) -> Ui<Value> {
    app.recovery_begin(&key.0, &password.0)
}
#[tauri::command(async)]
pub fn recovery_reissue(app: App<'_>, password: Secret) -> Ui<Value> {
    app.recovery_reissue(&password.0)
}
#[tauri::command(async)]
pub fn recovery_confirm(app: App<'_>, answers: Vec<Secret>) -> Ui<()> {
    app.recovery_confirm(&answers)
}
#[tauri::command(async)]
pub fn change_password(app: App<'_>, old: Secret, password: Secret) -> Ui<()> {
    app.change_password(&old.0, &password.0)
}

// ---- 条目 ----

#[tauri::command(async)]
pub fn list_items(app: App<'_>, trash: bool, query: String) -> Ui<Value> {
    app.list(trash, &query)
}
#[tauri::command(async)]
pub fn get_item(app: App<'_>, id: String) -> Ui<Value> {
    app.item(&id)
}
#[tauri::command(async)]
pub fn reveal_field(app: App<'_>, id: String, field: SecretField, index: usize) -> Ui<String> {
    app.reveal(&id, field, index)
}
#[tauri::command(async)]
pub fn copy_field(app: App<'_>, id: String, field: SecretField, index: usize) -> Ui<u32> {
    app.copy_field(&id, field, index)
}
#[tauri::command(async)]
pub fn copy_text(app: App<'_>, text: Secret) -> Ui<u32> {
    app.copy(&text.0)
}
#[tauri::command(async)]
pub fn save_item(app: App<'_>, id: Option<String>, draft: DraftIn) -> Ui<String> {
    app.save_item(id.as_deref(), draft)
}
#[tauri::command(async)]
pub fn item_action(app: App<'_>, id: String, action: String) -> Ui<()> {
    app.item_action(&id, &action)
}
#[tauri::command(async)]
pub fn empty_trash(app: App<'_>) -> Ui<usize> {
    app.empty_trash()
}
#[tauri::command(async)]
pub fn totp_code(app: App<'_>, id: String) -> Ui<Value> {
    app.totp(&id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorIn {
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
}
#[tauri::command(async)]
pub fn generate(options: GeneratorIn) -> Ui<String> {
    let o = GeneratorOptions {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
        avoid_ambiguous: options.avoid_ambiguous,
    };
    Ok(generate_password(&o)?.expose().to_owned())
}

// ---- 服务、客户端、申请 ----

#[tauri::command]
pub async fn open_service(app: App<'_>, scope: OpenScope, minutes: u64, direct: bool) -> Ui<()> {
    #[cfg(target_os = "android")]
    return crate::android::open(&app, scope, minutes, direct).await;
    #[cfg(not(target_os = "android"))]
    app.open_service(scope, minutes, direct).await
}
#[tauri::command]
pub async fn relay_claim(
    app: App<'_>,
    url: String,
    ca: Option<String>,
    code: Secret,
    password: Secret,
) -> Ui<()> {
    app.relay_claim(&url, ca.as_deref(), &code.0, &password.0)
        .await
}
#[tauri::command(async)]
pub fn relay_forget(app: App<'_>) -> Ui<()> {
    app.relay_forget()
}
#[tauri::command(async)]
pub fn pairing_begin(
    app: App<'_>,
    name: String,
    tags: Vec<String>,
    password: Secret,
) -> Ui<String> {
    app.pairing_begin(&name, tags, &password.0)
}
#[tauri::command(async)]
pub fn pairing_accept(app: App<'_>) -> Ui<()> {
    app.pairing_accept()
}
#[tauri::command(async)]
pub fn pairing_cancel(app: App<'_>) -> Ui<()> {
    app.pairing_cancel()
}
#[tauri::command(async)]
pub fn close_service(app: App<'_>) {
    #[cfg(target_os = "android")]
    crate::android::close(&app);
    #[cfg(not(target_os = "android"))]
    app.service.close();
}
#[tauri::command(async)]
pub fn list_clients(app: App<'_>) -> Ui<Value> {
    app.clients()
}
#[tauri::command(async)]
pub fn add_client(
    app: App<'_>,
    name: String,
    tags: Vec<String>,
    direct: bool,
    password: Secret,
) -> Ui<String> {
    app.add_client(&name, tags, direct, &password.0)
}
#[tauri::command(async)]
pub fn rename_client(app: App<'_>, id: String, name: String) -> Ui<()> {
    app.rename_client(&id, &name)
}
#[tauri::command(async)]
pub fn revoke_client(app: App<'_>, id: String) -> Ui<()> {
    app.revoke_client(&id)
}
#[tauri::command(async)]
pub fn resume_client(app: App<'_>, id: String, password: Secret) -> Ui<()> {
    app.resume_client(&id, &password.0)
}
#[tauri::command(async)]
pub fn decide(
    app: App<'_>,
    id: String,
    fields: Vec<AiField>,
    action: Decision,
    password: Secret,
) -> Ui<Option<String>> {
    app.decide(&id, fields, action, &password.0)
}
#[tauri::command(async)]
pub fn request_state(app: App<'_>, id: String) -> Ui<Value> {
    app.request_state(&id)
}
#[tauri::command(async)]
pub fn audit(app: App<'_>, query: String) -> Ui<Value> {
    app.audit(&query)
}
/// 接入配置文本，不含令牌。
#[tauri::command(async)]
pub fn mcp_config(app: App<'_>, client: String, transport: String) -> Ui<Value> {
    app.mcp_config(&client, &transport)
}

// ---- 导入、备份、迁移。路径只由系统文件对话框给出，界面不能指定。 ----

#[cfg(not(target_os = "android"))]
fn chosen(p: Option<FilePath>) -> Option<PathBuf> {
    p.and_then(|p| p.into_path().ok())
}

fn file_label(label: &str) -> Ui<&str> {
    let ok =
        (1..=20).contains(&label.len()) && label.bytes().all(|b| b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(label)
    } else {
        Err(UiError::internal())
    }
}

#[tauri::command(async)]
pub fn select_document(handle: AppHandle, kind: String, label: String) -> Ui<()> {
    file_label(&label)?;
    #[cfg(target_os = "android")]
    return crate::documents::select(&handle, &kind, &label);
    #[cfg(not(target_os = "android"))]
    {
        let _ = (handle, kind);
        fail("platform", "此文件选择方式仅用于 Android")
    }
}

/// 界面取消选择时返回 `None`。
#[tauri::command]
pub async fn import_csv(handle: AppHandle, app: App<'_>) -> Ui<Option<Value>> {
    #[cfg(target_os = "android")]
    return crate::documents::csv(&handle, &app).map(Some);
    #[cfg(not(target_os = "android"))]
    let pick = handle
        .dialog()
        .file()
        .set_title("选择要导入的 CSV")
        .add_filter("CSV", &["csv"])
        .blocking_pick_file();
    #[cfg(not(target_os = "android"))]
    chosen(pick).map(|p| app.import_csv(&p)).transpose()
}
#[tauri::command(async)]
pub fn delete_csv(app: App<'_>) -> Ui<()> {
    app.delete_csv()
}
#[tauri::command]
pub async fn export_backup(handle: AppHandle, app: App<'_>, label: String) -> Ui<bool> {
    file_label(&label)?;
    #[cfg(target_os = "android")]
    return crate::documents::export(&handle, "backup", |p| app.export_backup(p)).map(|()| true);
    #[cfg(not(target_os = "android"))]
    let name = format!("随身密库-备份-{}.svbak", file_label(&label)?);
    #[cfg(not(target_os = "android"))]
    let dest = handle
        .dialog()
        .file()
        .set_title("保存加密备份")
        .set_file_name(name)
        .blocking_save_file();
    #[cfg(not(target_os = "android"))]
    match chosen(dest) {
        Some(p) => app.export_backup(&p).map(|()| true),
        None => Ok(false),
    }
}
#[tauri::command]
pub async fn pick_package(handle: AppHandle, app: App<'_>, kind: String) -> Ui<Option<String>> {
    let (title, name, ext) = match kind.as_str() {
        "backup" => ("选择备份文件", "加密备份", "svbak"),
        "migration" => ("选择迁移包", "迁移包", "svmig"),
        _ => return Err(UiError::internal()),
    };
    let pick = handle
        .dialog()
        .file()
        .set_title(title)
        .add_filter(name, &[ext])
        .blocking_pick_file();
    #[cfg(target_os = "android")]
    return pick
        .map(|p| crate::documents::stage_package(&handle, &app, p, name))
        .transpose();
    #[cfg(not(target_os = "android"))]
    Ok(chosen(pick).map(|p| app.set_package(p)))
}
#[tauri::command(async)]
pub fn restore_backup(app: App<'_>, kind: Credential, secret: Secret) -> Ui<usize> {
    app.restore(kind, &secret.0)
}
#[tauri::command(async)]
pub fn migration_import(app: App<'_>, code: Secret, kind: Credential, secret: Secret) -> Ui<Value> {
    app.migration_import(&code.0, kind, &secret.0)
}
#[tauri::command]
pub async fn migration_begin(
    handle: AppHandle,
    app: App<'_>,
    password: Secret,
    label: String,
) -> Ui<Option<String>> {
    file_label(&label)?;
    #[cfg(target_os = "android")]
    return crate::documents::export(&handle, "migration", |p| {
        app.migration_begin(&password.0, p)
    })
    .map(Some);
    #[cfg(not(target_os = "android"))]
    let name = format!("随身密库-迁移-{}.svmig", file_label(&label)?);
    #[cfg(not(target_os = "android"))]
    let dest = handle
        .dialog()
        .file()
        .set_title("保存迁移包")
        .set_file_name(name)
        .blocking_save_file();
    #[cfg(not(target_os = "android"))]
    match chosen(dest) {
        Some(p) => app.migration_begin(&password.0, &p).map(Some),
        None => Ok(None),
    }
}
#[tauri::command(async)]
pub fn migration_cancel(app: App<'_>) -> Ui<()> {
    app.migration_cancel()
}
#[tauri::command(async)]
pub fn migration_confirm(app: App<'_>, completion: Secret) -> Ui<()> {
    app.migration_confirm(&completion.0)
}
#[tauri::command(async)]
pub fn wipe_retired(app: App<'_>) -> Ui<()> {
    app.wipe_retired()
}
#[tauri::command(async)]
pub fn set_aside(app: App<'_>) -> Ui<String> {
    app.set_aside()
}

// ---- 设置 ----

#[tauri::command(async)]
pub fn set_settings(handle: AppHandle, app: App<'_>, settings: Settings) -> Ui<()> {
    let old = app.settings();
    app.set_settings(settings.clone())?;
    if settings.shortcut != old.shortcut
        && let Err(e) = crate::shell::register_shortcut(&handle, &settings.shortcut)
    {
        // 新快捷键不可用：恢复原来的，不留下半生效的设置
        let _ = crate::shell::register_shortcut(&handle, &old.shortcut);
        app.set_settings(Settings {
            shortcut: old.shortcut,
            ..settings
        })?;
        return fail("shortcut", e);
    }
    Ok(())
}

#[tauri::command(async)]
pub fn pasteboard_stamp() -> Option<String> {
    crate::clipboard::stamp()
}

/// IPC 仍只返回区间。Rust 用字节，WebView 的 slice 用 UTF-16 码元。
#[tauri::command(async)]
pub fn parse_paste(app: App<'_>, source: Secret) -> Ui<Vec<vault_core::paste::Span>> {
    use vault_core::paste::{Recognizer, Rules};
    app.unlocked(|_| {
        let text = source.0.expose();
        let mut spans = Rules.recognize(text)?;
        let mut offset = 0;
        for span in &mut spans {
            let n = text[span.start..span.end].encode_utf16().count();
            span.start = offset;
            offset += n;
            span.end = offset;
        }
        Ok(spans)
    })
}
#[tauri::command(async)]
pub fn save_paste(
    app: App<'_>,
    drafts: Vec<DraftIn>,
    allow_duplicates: bool,
    clipboard: Option<Secret>,
    stamp: Option<String>,
) -> Ui<usize> {
    app.unlocked(|e| {
        if drafts.is_empty() || drafts.len() > 256 {
            return fail("paste_size", "一次可确认 1 到 256 条");
        }
        let rows: Vec<_> = drafts
            .into_iter()
            .map(|d| d.into_draft(Default::default()))
            .collect();
        if let Some(index) = rows
            .iter()
            .position(|d| !vault_core::paste::fits_storage(d))
        {
            return fail(
                "paste_format",
                &format!(
                    "请核对第 {} 条的标题和网址，去掉多余空白或控制字符。原文仍在左侧。",
                    index + 1
                ),
            );
        }
        if !allow_duplicates && e.vault().has_duplicate_logins(&rows)? {
            return fail(
                "duplicate",
                "已有相同域名和账号，或本批中有重复。仍要另存为新条目吗？",
            );
        }
        let n = e.vault_mut().add_many(&rows)?.len();
        if let (Some(original), Some(stamp)) = (clipboard, stamp) {
            crate::clipboard::clear_matching(&original.0, &stamp)
        }
        Ok(n)
    })
}
#[tauri::command(async)]
pub fn draft_permission(app: App<'_>, id: String, enabled: bool) -> Ui<()> {
    app.unlocked(|e| Ok(e.allow_drafts(crate::state::client_id(&id)?, enabled)?))
}
#[tauri::command(async)]
pub fn draft_inbox(app: App<'_>) -> Ui<Value> {
    app.unlocked(|e| Ok(e.draft_inbox()?))
}
#[tauri::command(async)]
pub fn accept_draft(app: App<'_>, id: String, secret: Secret) -> Ui<String> {
    app.unlocked(|e| {
        Ok(e.vault_mut()
            .accept_draft(crate::state::item_id(&id)?, secret.0)?
            .to_hex())
    })
}
#[tauri::command(async)]
pub fn reject_drafts(app: App<'_>, id: Option<String>) -> Ui<()> {
    app.unlocked(|e| {
        Ok(e.vault()
            .reject_drafts(id.as_deref().map(crate::state::item_id).transpose()?)?)
    })
}

#[derive(Deserialize)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
#[serde(tag = "use", rename_all = "snake_case", deny_unknown_fields)]
pub enum Biometric {
    Enroll {
        password: Secret,
    },
    Remove,
    Unlock,
    Approve {
        id: String,
        fields: Vec<AiField>,
        for_ai: bool,
    },
}

#[tauri::command(async)]
pub fn biometric(app: App<'_>, operation: Biometric) -> Ui<Option<String>> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, operation);
        fail("platform", "这台设备没有启用生物识别")
    }
    #[cfg(target_os = "android")]
    {
        use crate::android;
        use vault_core::Auth;
        match operation {
            Biometric::Enroll { password } => {
                app.unlocked(|e| Ok(e.vault_mut().reauthenticate(Auth::Password(&password.0))?))?;
                let key = android::authenticate(true)?;
                app.unlocked(|e| Ok(e.vault_mut().enroll_device_key(&password.0, &key)?))?;
            }
            Biometric::Remove => {
                app.unlocked(|e| Ok(e.vault_mut().remove_device_key()?))?;
                android::call::<()>("forgetKey", ())?;
            }
            Biometric::Unlock => {
                app.unlock_with(Auth::DeviceKey(&android::authenticate(false)?))?
            }
            Biometric::Approve { id, fields, for_ai } => {
                let action = if for_ai {
                    Decision::Issue
                } else {
                    Decision::View
                };
                return app.decide_with(
                    &id,
                    fields,
                    action,
                    Auth::DeviceKey(&android::authenticate(false)?),
                );
            }
        }
        Ok(None)
    }
}
