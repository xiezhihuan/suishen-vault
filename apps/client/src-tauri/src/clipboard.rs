//! 剪贴板：标记为敏感，到时只清除自己写入的内容。AC-VLT-09 AC-LOG-05
use crate::error::{Ui, UiError};
use std::time::{Duration, Instant, SystemTime};
use vault_core::SecretString;

/// 识别“剪贴板里还是本次复制的内容”。
#[derive(PartialEq, Eq)]
struct Mark(u64);

pub struct Copied {
    #[cfg(not(target_os = "android"))]
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
        #[cfg(not(target_os = "android"))]
        if imp::mark() == self.mark {
            imp::clear();
        }
    }
}

pub fn copy(text: &SecretString, ttl: Duration) -> Ui<Copied> {
    #[cfg(target_os = "android")]
    crate::android::call::<()>(
        "copy",
        serde_json::json!({"text":text.expose(), "ms":ttl.as_millis() as u64}),
    )?;
    #[cfg(not(target_os = "android"))]
    imp::set(text.expose()).ok_or_else(|| UiError::new("clipboard", "无法写入剪贴板"))?;
    Ok(Copied {
        #[cfg(not(target_os = "android"))]
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

#[cfg(target_os = "android")]
mod imp {
    use super::Mark;
    pub fn mark() -> Mark {
        Mark(crate::android::call("clipStamp", ()).unwrap_or(0))
    }
}

#[cfg(all(mobile, not(target_os = "android")))]
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

/// 系统复制序号。不支持变更检测的系统不提供“保存后清空”。
pub fn stamp() -> Option<String> {
    let mark = imp::mark().0;
    (mark != 0).then(|| mark.to_string())
}

#[cfg(any(target_os = "macos", windows, test))]
fn matches_paste(
    original: &SecretString,
    expected: &str,
    current: Option<SecretString>,
    stamp: Option<String>,
) -> bool {
    stamp.as_deref() == Some(expected) && current.is_some_and(|text| text.ct_eq(original.expose()))
}

pub fn clear_matching(original: &SecretString, expected: &str) {
    #[cfg(any(target_os = "macos", windows))]
    {
        if stamp().as_deref() != Some(expected) {
            return;
        }
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let current = clipboard.get_text().ok().map(SecretString::new);
            if matches_paste(original, expected, current, stamp()) {
                let _ = clipboard.clear();
            }
        }
    }
    #[cfg(target_os = "android")]
    if let Ok(stamp) = expected.parse::<u64>() {
        let _ = crate::android::call::<()>(
            "clearMatching",
            serde_json::json!({"text": original.expose(), "stamp":stamp}),
        );
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "android")))]
    let _ = (original, expected);
}

#[cfg(test)]
mod paste_tests {
    use super::*;
    #[test]
    fn must_match_both_content_and_copy_generation() {
        let source = SecretString::from("  Fake:🔐  ");
        for (value, mark, ok) in [
            (Some("  Fake:🔐  "), Some("1"), true),
            (Some("  Fake:🔐  "), Some("2"), false),
            (Some("Fake:🔐"), Some("1"), false),
            (None, Some("1"), false),
            (Some("  Fake:🔐  "), None, false),
        ] {
            assert_eq!(
                matches_paste(
                    &source,
                    "1",
                    value.map(SecretString::from),
                    mark.map(str::to_owned)
                ),
                ok
            );
        }
    }
}
