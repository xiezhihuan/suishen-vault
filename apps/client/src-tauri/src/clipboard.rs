//! 剪贴板：标记为敏感，到时只清除自己写入的内容。AC-VLT-09 AC-LOG-05
use crate::error::{Ui, UiError};
use std::time::{Duration, Instant, SystemTime};
use vault_core::SecretString;

/// 识别“剪贴板里还是本次复制的内容”。
#[derive(PartialEq, Eq)]
struct Mark(u64);

pub struct Copied {
    mark: Mark,
    since: Instant,
    wall: SystemTime,
    ttl: Duration,
}

impl Copied {
    /// 单调时钟在休眠时可能不走，所以同时看系统时钟。
    pub fn due(&self) -> bool {
        self.since.elapsed() >= self.ttl || self.wall.elapsed().map_or(true, |d| d >= self.ttl)
    }
    /// 仍是本次内容才清除。
    pub fn clear(self) {
        if imp::mark() == self.mark {
            imp::clear();
        }
    }
}

pub fn copy(text: &SecretString, ttl: Duration) -> Ui<Copied> {
    imp::set(text.expose()).ok_or_else(|| UiError::new("clipboard", "无法写入剪贴板"))?;
    Ok(Copied {
        mark: imp::mark(),
        since: Instant::now(),
        wall: SystemTime::now(),
        ttl,
    })
}

#[cfg(desktop)]
mod imp {
    use super::Mark;
    use arboard::Clipboard;

    #[cfg(target_os = "macos")]
    pub fn mark() -> Mark {
        // 只看变更次数，不读取剪贴板内容，不会触发系统的粘贴隐私提示。
        Mark(objc2_app_kit::NSPasteboard::generalPasteboard().changeCount() as u64)
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    pub fn mark() -> Mark {
        // SAFETY: 无参数，只返回当前窗口站的剪贴板序号。
        Mark(
            unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() }
                .into(),
        )
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    pub fn mark() -> Mark {
        Mark(0)
    }

    #[cfg(target_os = "macos")]
    pub fn set(text: &str) -> Option<()> {
        use arboard::SetExtApple;
        Clipboard::new()
            .ok()?
            .set()
            .exclude_from_history()
            .text(text)
            .ok()
    }

    #[cfg(windows)]
    pub fn set(text: &str) -> Option<()> {
        use arboard::SetExtWindows;
        Clipboard::new()
            .ok()?
            .set()
            .exclude_from_monitoring()
            .exclude_from_cloud()
            .exclude_from_history()
            .text(text)
            .ok()
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    pub fn set(text: &str) -> Option<()> {
        Clipboard::new().ok()?.set_text(text).ok()
    }

    pub fn clear() {
        if let Ok(mut c) = Clipboard::new() {
            let _ = c.clear();
        }
    }
}

// Android 由后续任务用系统剪贴板服务实现，这里明确报错，不假装成功。
#[cfg(mobile)]
mod imp {
    use super::Mark;
    pub fn mark() -> Mark {
        Mark(0)
    }
    pub fn set(_: &str) -> Option<()> {
        None
    }
    pub fn clear() {}
}
