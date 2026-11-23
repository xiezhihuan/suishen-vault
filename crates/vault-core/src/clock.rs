//! 时钟。抽象出来是为了测试过期、退避与时钟回拨。

use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// 系统时钟，Unix 毫秒。可能被用户调整。
    fn wall_ms(&self) -> i64;
    /// 单调时钟，毫秒。macOS 上休眠时不走。
    fn mono_ms(&self) -> u64;
}

pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn wall_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0)
    }

    fn mono_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// 某一时刻，同时记录两个时钟。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stamp {
    wall: i64,
    mono: u64,
}

impl Stamp {
    pub(crate) fn now(clock: &dyn Clock) -> Self {
        Self {
            wall: clock.wall_ms(),
            mono: clock.mono_ms(),
        }
    }

    /// 任一时钟超过有效期即过期；系统时钟早于起点也算过期。
    pub(crate) fn expired(self, now: Stamp, ttl_ms: u64) -> bool {
        let wall = now.wall.checked_sub(self.wall);
        let wall_bad = wall.is_none_or(|d| d < 0 || d as u64 >= ttl_ms);
        wall_bad || now.mono.saturating_sub(self.mono) >= ttl_ms
    }
}
