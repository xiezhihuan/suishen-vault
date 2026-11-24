//! 系统文件选择器会让 Activity 进入后台。只保留用户选定的 URI，回来解锁后再读写。
use crate::{
    error::{Ui, UiError},
    state::{AppState, report_json},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tauri_plugin_fs::{FsExt, OpenOptions};
use vault_core::policy::{MAX_CSV_BYTES, MAX_PACKAGE_BYTES};

static PICKS: LazyLock<Mutex<HashMap<String, FilePath>>> = LazyLock::new(Default::default);
static PACKAGE: Mutex<Option<tempfile::TempPath>> = Mutex::new(None);

fn io_error(_: io::Error) -> UiError {
    UiError::new("document", "无法读写所选文件，请重新选择")
}
fn content(path: FilePath) -> Ui<FilePath> {
    match &path {
        FilePath::Url(url) if url.scheme() == "content" => Ok(path),
        _ => Err(UiError::new("document", "请选择系统文档提供程序中的文件")),
    }
}
pub fn selected() -> Vec<String> {
    PICKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}
pub fn select(handle: &AppHandle, kind: &str, label: &str) -> Ui<()> {
    let picker = handle.dialog().file();
    PICKS.lock().map_err(|_| UiError::internal())?.remove(kind);
    let result = match kind {
        "csv" => picker.add_filter("CSV", &["csv"]).blocking_pick_file(),
        "backup" => picker
            .set_file_name(format!("随身密库-{label}.svbak"))
            .blocking_save_file(),
        "migration" => picker
            .set_file_name(format!("随身密库-{label}.svmig"))
            .blocking_save_file(),
        _ => return Err(UiError::internal()),
    };
    if let Some(path) = result {
        PICKS
            .lock()
            .map_err(|_| UiError::internal())?
            .insert(kind.into(), content(path)?);
    }
    Ok(())
}
fn take(kind: &str) -> Ui<FilePath> {
    PICKS
        .lock()
        .map_err(|_| UiError::internal())?
        .remove(kind)
        .ok_or_else(|| UiError::new("document", "请先选择文件"))
}
fn cache(handle: &AppHandle) -> Ui<PathBuf> {
    let path = handle
        .path()
        .app_cache_dir()
        .map_err(|_| UiError::internal())?;
    std::fs::create_dir_all(&path).map_err(io_error)?;
    Ok(path)
}
fn input(handle: &AppHandle, path: FilePath) -> Ui<File> {
    handle
        .fs()
        .open(content(path)?, OpenOptions::new().read(true).clone())
        .map_err(io_error)
}
pub fn csv(handle: &AppHandle, app: &AppState) -> Ui<Value> {
    let reader = input(handle, take("csv")?)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    reader
        .take(MAX_CSV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    app.unlocked(|e| Ok(report_json(&e.vault_mut().import_csv_bytes(&bytes, None)?)))
}
pub fn export<T>(handle: &AppHandle, kind: &str, make: impl FnOnce(&Path) -> Ui<T>) -> Ui<T> {
    let uri = take(kind)?;
    let dir = tempfile::tempdir_in(cache(handle)?).map_err(io_error)?;
    let path = dir.path().join("package");
    let result = make(&path)?;
    let mut dest = handle
        .fs()
        .open(uri, OpenOptions::new().write(true).truncate(true).clone())
        .map_err(io_error)?;
    let mut source = File::open(&path).map_err(io_error)?;
    io::copy(&mut source, &mut dest).map_err(io_error)?;
    dest.flush().map_err(io_error)?;
    Ok(result)
}
pub fn stage_package(handle: &AppHandle, app: &AppState, path: FilePath, name: &str) -> Ui<String> {
    let mut source = input(handle, path)?.take(MAX_PACKAGE_BYTES + 1);
    let mut staged = tempfile::NamedTempFile::new_in(cache(handle)?).map_err(io_error)?;
    if io::copy(&mut source, &mut staged).map_err(io_error)? > MAX_PACKAGE_BYTES {
        return Err(vault_core::Error::TooLarge.into());
    }
    let path = staged.into_temp_path();
    app.selected_package(path.to_path_buf(), name);
    *PACKAGE.lock().map_err(|_| UiError::internal())? = Some(path);
    Ok(name.into())
}
