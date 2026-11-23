//! Tauri 壳。目前只显示版本与开放范围，不含密库功能。

use serde::Serialize;
use vault_core::ExposureScope;
use vault_service::ServiceHandle;

#[derive(Debug, Serialize)]
struct AppStatus {
    version: &'static str,
    scope: ExposureScope,
}

fn status_of(service: &ServiceHandle) -> AppStatus {
    AppStatus {
        version: env!("CARGO_PKG_VERSION"),
        scope: service.scope(),
    }
}

#[tauri::command]
fn app_status(service: tauri::State<'_, ServiceHandle>) -> AppStatus {
    status_of(&service)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[allow(clippy::expect_used)]
pub fn run() {
    tauri::Builder::default()
        .manage(ServiceHandle::new())
        .invoke_handler(tauri::generate_handler![app_status])
        .run(tauri::generate_context!())
        .expect("Tauri 启动失败");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_reports_closed_on_start() {
        assert_eq!(
            status_of(&ServiceHandle::new()).scope,
            ExposureScope::Closed
        );
    }
}
