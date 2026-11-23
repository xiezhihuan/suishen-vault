//! 主窗口专用的进程内命令。HTTP 和 stdio 均没有管理或批准入口。
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tauri::State;
use vault_core::{Auth, SecretString, SystemClock, Vault, model::AiField, search::ClientId};
use vault_service::{DEFAULT_PORT, Engine, LocalApproval, ServiceError, ServiceHandle};

type Ui<T> = Result<T, &'static str>;
fn message(e: ServiceError) -> &'static str {
    match e.1 {
        "unlock_failed" => "主密码验证失败或正在等待重试",
        "invalid_fields" => "请选择申请中的字段",
        "unknown_request" | "gone" | "not_ready" => "申请已失效，请刷新",
        "invalid_params" => "请检查名称和标签",
        _ => "操作未完成，请检查密库和服务状态",
    }
}
#[tauri::command]
fn app_status(service: State<'_, ServiceHandle>) -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),"scope":service.scope(),"remaining":service.remaining_seconds()})
}
#[tauri::command]
async fn open_service(
    service: State<'_, ServiceHandle>,
    path: String,
    password: String,
    minutes: u64,
) -> Ui<()> {
    if ![0, 15, 60, 480].contains(&minutes) {
        return Err("关闭时间无效");
    }
    let password = SecretString::new(password);
    let engine = tauri::async_runtime::spawn_blocking(move || {
        let clock = Arc::new(SystemClock::default());
        let mut v = Vault::open_with_clock(Path::new(&path), clock.clone())
            .map_err(|_| "无法打开密库文件")?;
        v.unlock(Auth::Password(&password))
            .map_err(|_| "解锁失败，请核对主密码或稍后重试")?;
        Engine::new(v, clock).map_err(message)
    })
    .await
    .map_err(|_| "无法打开密库")??;
    service
        .open_loopback(
            engine,
            DEFAULT_PORT,
            (minutes != 0).then(|| Duration::from_secs(minutes * 60)),
        )
        .await
        .map_err(|_| "无法启动服务，请检查回环端口是否已占用")?;
    Ok(())
}
#[tauri::command]
fn close_service(service: State<'_, ServiceHandle>) {
    service.close()
}
#[tauri::command]
fn service_panel(service: State<'_, ServiceHandle>) -> Ui<Value> {
    service
        .local(|e| Ok(json!({"clients":e.clients(),"requests":e.pending()})))
        .map_err(message)
}
#[tauri::command]
fn add_client(
    service: State<'_, ServiceHandle>,
    name: String,
    tags: Vec<String>,
    password: String,
) -> Ui<String> {
    let password = SecretString::new(password);
    service
        .local(|e| {
            e.verify_user(Auth::Password(&password))?;
            let (_, t) = e.add_client(&name, tags)?;
            Ok(t.expose().into())
        })
        .map_err(message)
}
#[tauri::command]
fn client_action(
    service: State<'_, ServiceHandle>,
    id: String,
    resume: bool,
    password: String,
) -> Ui<()> {
    let id = ClientId(
        hex::decode(id)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("客户端无效")?,
    );
    let password = SecretString::new(password);
    service
        .local(|e| {
            if resume {
                e.resume_search(id, Auth::Password(&password))
            } else {
                e.revoke_client(id)
            }
        })
        .map_err(message)
}
#[tauri::command]
fn decide(
    service: State<'_, ServiceHandle>,
    id: String,
    fields: Vec<AiField>,
    action: String,
    password: String,
) -> Ui<Option<String>> {
    let password = SecretString::new(password);
    service
        .local(|e| match action.as_str() {
            "deny" => e.deny(&id).map(|_| None),
            "revoke" => e.revoke(&id).map(|_| None),
            "view" | "issue" => Ok(Some(
                match e.approve(&id, fields, Auth::Password(&password), action == "issue")? {
                    LocalApproval::Code(c) => c.expose().into(),
                    LocalApproval::View(v) => String::from_utf8(v.to_vec())
                        .map_err(|_| ServiceError(500, "unavailable"))?,
                },
            )),
            _ => Err(ServiceError(400, "invalid_params")),
        })
        .map_err(message)
}
#[tauri::command]
fn audit_history(service: State<'_, ServiceHandle>, password: String, query: String) -> Ui<String> {
    let password = SecretString::new(password);
    service
        .local(|e| e.audit_history(Auth::Password(&password), &query))
        .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
        .map_err(message)
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    std::panic::set_hook(Box::new(|_| {}));
    tauri::Builder::default()
        .manage(ServiceHandle::new())
        .invoke_handler(tauri::generate_handler![
            app_status,
            open_service,
            close_service,
            service_panel,
            add_client,
            client_action,
            decide,
            audit_history
        ])
        .run(tauri::generate_context!())
        .expect("Tauri 启动失败");
}
