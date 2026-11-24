use std::{collections::HashMap, sync::Mutex, time::Instant};

const MAX_SOURCES: usize = 4096;

/// 按来源与全局的每分钟请求上限。来源只留在内存里，不写日志。
pub struct Limiter {
    per_source: u32,
    total: u32,
    window: Mutex<Window>,
}

struct Window {
    start: Instant,
    total: u32,
    sources: HashMap<String, u32>,
}

impl Limiter {
    pub fn new(per_source: u32, total: u32) -> Self {
        Self {
            per_source,
            total,
            window: Mutex::new(Window {
                start: Instant::now(),
                total: 0,
                sources: HashMap::new(),
            }),
        }
    }

    pub fn allow(&self, source: &str) -> bool {
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if w.start.elapsed().as_secs() >= 60 {
            w.start = Instant::now();
            w.total = 0;
            w.sources.clear();
        }
        let full = w.sources.len() >= MAX_SOURCES;
        let n = match w.sources.get_mut(source) {
            Some(n) => n,
            None if full => return false,
            None => w.sources.entry(source.to_owned()).or_default(),
        };
        // 超限的来源不占用全局名额
        if *n >= self.per_source {
            return false;
        }
        *n += 1;
        if w.total >= self.total {
            return false;
        }
        w.total += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_noisy_source_does_not_starve_others() {
        let l = Limiter::new(3, 5);
        assert_eq!((0..10).filter(|_| l.allow("a")).count(), 3);
        assert_eq!((0..10).filter(|_| l.allow("b")).count(), 2);
        assert!(!l.allow("c"));
    }
}
