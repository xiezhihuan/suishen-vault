//! 解锁失败退避。失败次数先落盘再运行 KDF，杀进程不能绕过计数。

use crate::policy;

pub(crate) fn delay_ms(failures: u32) -> u64 {
    let Some(n) = failures.checked_sub(policy::UNLOCK_FREE_FAILURES) else {
        return 0;
    };
    if n == 0 {
        return 0;
    }
    let max = policy::UNLOCK_MAX_DELAY.as_secs();
    let secs = 1u64.checked_shl(n).filter(|s| *s < max).unwrap_or(max);
    secs * 1000
}

/// 进程内以单调时钟为准；打开密库时用落盘的系统时间换算一次剩余等待。
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    until_mono: u64,
}

impl Backoff {
    pub(crate) fn from_stored(failures: u32, fail_at_wall: i64, wall: i64, mono: u64) -> Self {
        let delay = delay_ms(failures);
        // 时钟被调早时按刚刚失败处理，最多再等一轮
        let elapsed = u64::try_from(wall.saturating_sub(fail_at_wall)).unwrap_or(0);
        Self {
            until_mono: mono.saturating_add(delay.saturating_sub(elapsed)),
        }
    }

    pub(crate) fn remaining(&self, mono: u64) -> u64 {
        self.until_mono.saturating_sub(mono)
    }

    pub(crate) fn failed(&mut self, failures: u32, mono: u64) {
        self.until_mono = mono.saturating_add(delay_ms(failures));
    }

    pub(crate) fn reset(&mut self) {
        self.until_mono = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_grows_and_is_capped() {
        assert_eq!([0, 1, 2].map(delay_ms), [0, 0, 0]);
        assert_eq!([3, 4, 5].map(delay_ms), [2000, 4000, 8000]);
        assert_eq!(delay_ms(11), 300_000);
        assert_eq!(delay_ms(u32::MAX), 300_000);
        for n in 0..200 {
            assert!(delay_ms(n) <= delay_ms(n + 1));
        }
    }

    #[test]
    fn stored_backoff_survives_restart_and_clock_changes() {
        let b = Backoff::from_stored(5, 10_000, 13_000, 0);
        assert_eq!(b.remaining(0), 5000);
        // 回拨系统时钟不会缩短，也不会无限延长
        let b = Backoff::from_stored(5, 10_000, 1, 0);
        assert_eq!(b.remaining(0), 8000);
    }
}
