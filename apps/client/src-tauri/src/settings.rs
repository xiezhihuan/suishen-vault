//! 非机密设置。开放范围刻意不在其中：重启后一律关闭。
use crate::error::{Ui, UiError, fail};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

const FILE: &str = "settings.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_seconds: u32,
    pub hide_to_tray: bool,
    pub notify: bool,
    /// 空字符串表示不注册。
    pub shortcut: String,
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_seconds: 30,
            hide_to_tray: true,
            notify: true,
            shortcut: "CmdOrCtrl+Alt+K".into(),
            port: vault_service::DEFAULT_PORT,
        }
    }
}

impl Settings {
    pub fn check(&self) -> Ui<()> {
        if !(1..=60).contains(&self.auto_lock_minutes) {
            return fail("settings", "自动锁定时间须在 1 到 60 分钟之间");
        }
        if !(10..=120).contains(&self.clipboard_seconds) {
            return fail("settings", "剪贴板清除时间须在 10 到 120 秒之间");
        }
        if self.port < 1024 {
            return fail("settings", "端口须在 1024 到 65535 之间");
        }
        if self.shortcut.chars().count() > 64 {
            return fail("settings", "快捷键格式不正确");
        }
        Ok(())
    }

    /// 读不出或不合规时用默认值，不阻止启动。
    pub fn load(dir: &Path) -> Self {
        fs::read(dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            .filter(|s| s.check().is_ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Ui<()> {
        let write = || {
            let tmp = dir.join(format!("{FILE}.tmp"));
            fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
            fs::rename(&tmp, dir.join(FILE))
        };
        write().map_err(|_: std::io::Error| UiError::new("settings", "设置没有保存成功"))
    }
}
