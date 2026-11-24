//! Android 私有桥接。插件没有 WebView capability，设备密钥仅供 Rust 使用。
use crate::{
    error::{Ui, UiError},
    state::{AppState, OpenScope},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    ffi::c_void,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering::SeqCst},
    },
};
use tauri::{
    Manager, Wry,
    plugin::{PluginHandle, TauriPlugin},
};
use vault_core::{ExposureScope, Key};
use zeroize::Zeroizing;

static PLUGIN: OnceLock<PluginHandle<Wry>> = OnceLock::new();
static VISIBLE: AtomicBool = AtomicBool::new(false);
static SHOW_REQUESTS: AtomicBool = AtomicBool::new(false);
static CLOSE_SEQ: AtomicU64 = AtomicU64::new(0);
static LOCKING: AtomicU64 = AtomicU64::new(0);
static UI_SEQ: AtomicU64 = AtomicU64::new(0);
static NOTIFICATION_STARTED: AtomicBool = AtomicBool::new(false);
static OPENING: tauri::async_runtime::Mutex<()> = tauri::async_runtime::Mutex::const_new(());

pub fn plugin() -> TauriPlugin<Wry> {
    tauri::plugin::Builder::new("vaultphone")
        .setup(|_, api| {
            let handle = api.register_android_plugin("dev.suishen.vault", "VaultPlugin")?;
            let _ = PLUGIN.set(handle);
            Ok(())
        })
        .build()
}

pub fn call<T: DeserializeOwned>(name: &str, args: impl Serialize) -> Ui<T> {
    PLUGIN
        .get()
        .ok_or_else(UiError::internal)?
        .run_mobile_plugin(name, args)
        .map_err(|_| UiError::new("android", "系统操作未完成，请检查权限或重试"))
}

pub fn visible() -> Ui<()> {
    (VISIBLE.load(SeqCst) && LOCKING.load(SeqCst) == 0)
        .then_some(())
        .ok_or_else(UiError::locked)
}

pub fn authenticate(enroll: bool) -> Ui<Key> {
    visible()?;
    let seq = UI_SEQ.load(SeqCst);
    let bytes = Zeroizing::new(
        call::<Vec<u8>>("authenticate", serde_json::json!({ "enroll": enroll })).map_err(|_| {
            UiError::new(
                "biometric",
                "生物识别未完成。可改用主密码，或到设置中重新登记。",
            )
        })?,
    );
    visible()?;
    if seq != UI_SEQ.load(SeqCst) {
        return Err(UiError::locked());
    }
    Ok(Key::from_slice(&bytes)?)
}

pub async fn open(state: &AppState, scope: OpenScope, minutes: u64, direct: bool) -> Ui<()> {
    let seq = CLOSE_SEQ.load(SeqCst);
    let _opening = OPENING.lock().await;
    visible()?;
    let result = async {
        call::<()>("startService", ())
            .map_err(|_| UiError::new("notification", "请允许开放状态通知，然后重试"))?;
        NOTIFICATION_STARTED.store(true, SeqCst);
        visible()?;
        if CLOSE_SEQ.load(SeqCst) != seq {
            return Err(UiError::locked());
        }
        state.open_service(scope, minutes, direct).await?;
        if CLOSE_SEQ.load(SeqCst) != seq {
            return Err(UiError::locked());
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        state.service.close();
        if call::<()>("stopService", ()).is_ok() {
            NOTIFICATION_STARTED.store(false, SeqCst);
        }
    }
    result
}

pub fn close(state: &AppState) {
    CLOSE_SEQ.fetch_add(1, SeqCst);
    state.service.close();
}

// 心跳也处理到期、设备身份被接管、通知权限被收回。
pub fn heartbeat(state: &AppState) {
    if SHOW_REQUESTS.swap(false, SeqCst) {
        state.navigate("requests");
    }
    let Ok(_opening) = OPENING.try_lock() else {
        return;
    };
    let mut open = state.service.scope() != ExposureScope::Closed;
    if open && !call::<bool>("canNotify", ()).unwrap_or(false) {
        close(state);
        open = false;
    }
    if !open && NOTIFICATION_STARTED.load(SeqCst) && call::<()>("stopService", ()).is_ok() {
        NOTIFICATION_STARTED.store(false, SeqCst);
    }
}

fn later(f: impl FnOnce(&AppState) + Send + 'static) {
    if let Some(plugin) = PLUGIN.get() {
        let app = plugin.app().clone();
        std::thread::spawn(move || {
            if let Some(state) = app.try_state::<AppState>() {
                f(&state);
            }
        });
    }
}

// JNI 实例方法签名对应 MainActivity.kt 中的 object Native，既不解引用也不保存 JNI 引用。
// 锁库不能占用 Android 主线程（Rust 工作者可能正在等待系统剪贴板）。
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_dev_suishen_vault_Native_visibility(
    _: *mut c_void,
    _: *mut c_void,
    visible: u8,
) {
    VISIBLE.store(visible != 0, SeqCst);
    if visible == 0 {
        UI_SEQ.fetch_add(1, SeqCst);
        if let Some(app) = PLUGIN.get().map(|p| p.app().clone())
            && app.try_state::<AppState>().is_some()
        {
            LOCKING.fetch_add(1, SeqCst);
            std::thread::spawn(move || {
                app.state::<AppState>().lock();
                LOCKING.fetch_sub(1, SeqCst);
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.eval("window.dispatchEvent(new Event('suishen:background'))");
                }
            });
        }
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_dev_suishen_vault_Native_closeAll(_: *mut c_void, _: *mut c_void) {
    CLOSE_SEQ.fetch_add(1, SeqCst);
    later(|s| s.service.close());
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_dev_suishen_vault_Native_requests(_: *mut c_void, _: *mut c_void) {
    SHOW_REQUESTS.store(true, SeqCst);
}
