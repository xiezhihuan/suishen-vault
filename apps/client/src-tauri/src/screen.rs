//! 系统是否处于锁屏状态。查不到时按未锁屏处理，闲置与休眠锁定不受影响。

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn locked() -> bool {
    use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFString, CFType};
    let Some(dict) = objc2_core_graphics::CGSessionCopyCurrentDictionary() else {
        return false;
    };
    // SAFETY: 系统文档约定该字典的键为 CFString，值为 CF 类型。
    let dict: &CFDictionary<CFString, CFType> = unsafe { dict.cast_unchecked() };
    dict.get(&CFString::from_static_str("CGSSessionScreenIsLocked"))
        .is_some_and(|v| {
            v.downcast_ref::<CFBoolean>()
                .map(CFBoolean::as_bool)
                .or_else(|| {
                    v.downcast_ref::<CFNumber>()
                        .and_then(CFNumber::as_i64)
                        .map(|n| n != 0)
                })
                .unwrap_or(false)
        })
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn locked() -> bool {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSFreeMemory, WTSINFOEXW,
        WTSQuerySessionInformationW, WTSSessionInfoEx,
    };
    let mut buf: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: 输出参数指向本函数的局部变量；成功时由系统分配缓冲区，下面释放。
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buf,
            &mut len,
        )
    };
    if ok == 0 || buf.is_null() {
        return false;
    }
    // SAFETY: 长度足够时缓冲区内容为 WTSINFOEXW，未对齐读取避免对齐假设。
    unsafe {
        let r = len as usize >= size_of::<WTSINFOEXW>() && {
            let info = buf.cast::<WTSINFOEXW>().read_unaligned();
            // 0 为锁定，1 为未锁定（Windows 8 及以后）。
            info.Level == 1 && info.Data.WTSInfoExLevel1.SessionFlags == 0
        };
        WTSFreeMemory(buf.cast());
        r
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn locked() -> bool {
    false
}
