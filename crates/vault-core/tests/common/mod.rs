//! 测试公用设施。所有口令都是假的。
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::SeqCst};

use vault_core::model::{ItemDraft, ItemKind};
use vault_core::*;

pub const PW: &str = "fake-master-鲸鱼-0001";
pub const PW2: &str = "fake-master-海豚-0002";
pub const T0: i64 = 1_800_000_000_000;

pub struct TestClock {
    wall: AtomicI64,
    mono: AtomicU64,
}

impl TestClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            wall: AtomicI64::new(T0),
            mono: AtomicU64::new(1_000_000),
        })
    }

    /// 两个时钟一起走。
    pub fn advance(&self, ms: i64) {
        self.wall.fetch_add(ms, SeqCst);
        self.mono.fetch_add(ms.max(0) as u64, SeqCst);
    }

    /// 只改系统时钟（用户调表，或单调时钟在休眠中停走）。
    pub fn shift_wall(&self, ms: i64) {
        self.wall.fetch_add(ms, SeqCst);
    }
}

impl Clock for TestClock {
    fn wall_ms(&self) -> i64 {
        self.wall.load(SeqCst)
    }
    fn mono_ms(&self) -> u64 {
        self.mono.load(SeqCst)
    }
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub clock: Arc<TestClock>,
    pub recovery: String,
}

impl Env {
    pub fn path(&self) -> PathBuf {
        self.dir.path().join("v.svault")
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn open(&self) -> Result<Vault> {
        Vault::open_with_clock(&self.path(), self.clock.clone())
    }

    pub fn unlocked(&self) -> Vault {
        let mut v = self.open().unwrap();
        v.unlock(Auth::Password(&PW.into())).unwrap();
        v
    }

    pub fn recovery_key(&self) -> RecoveryKey {
        RecoveryKey::parse(&self.recovery).ok().unwrap()
    }
}

pub fn answers(key: &str, challenge: [u32; 2]) -> [String; 2] {
    challenge.map(|i| key.split('-').nth(i as usize).unwrap().to_owned())
}

pub fn create_at(path: &Path, clock: Arc<TestClock>) -> (Vault, String) {
    let s = Setup::begin(&PW.into()).ok().unwrap();
    let key = s.recovery_key().expose().to_owned();
    let a = answers(&key, s.challenge());
    let v = s.confirm(path, [&a[0], &a[1]], clock).ok().unwrap();
    (v, key)
}

pub fn new_env() -> (Env, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new();
    let (v, recovery) = create_at(&dir.path().join("v.svault"), clock.clone());
    (
        Env {
            dir,
            clock,
            recovery,
        },
        v,
    )
}

pub fn login(title: &str, url: &str, user: &str, pw: &str) -> ItemDraft {
    let mut d = ItemDraft::new(ItemKind::Login, title);
    d.secrets.urls = vec![url.into()];
    d.secrets.username = Some(user.into());
    d.secrets.password = Some(pw.into());
    d
}

pub fn note(title: &str, body: &str) -> ItemDraft {
    let mut d = ItemDraft::new(ItemKind::Note, title);
    d.secrets.body = Some(body.into());
    d
}

/// 取错误；`Vault` 等类型没有 `Debug`，不能直接 `unwrap_err`。
pub fn err<T>(r: Result<T>) -> Error {
    match r {
        Ok(_) => panic!("本应失败"),
        Err(e) => e,
    }
}

/// 直接打开数据库改字节，模拟拿到文件的攻击者。
pub fn sql(path: &Path, f: impl FnOnce(&rusqlite::Connection)) {
    let c = rusqlite::Connection::open(path).unwrap();
    f(&c);
    c.close().unwrap();
}
