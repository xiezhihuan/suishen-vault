//! 跳板唯一落盘的内容：当前设备公钥、已被取代的公钥、未用的配对码派生密钥。
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vault_tunnel::{PairCode, PublicKey, handshake::Proven, handshake::Verdict};

pub const CODE_TTL: Duration = Duration::from_secs(600);
const MAX_RETIRED: usize = 64;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    current: Option<String>,
    retired: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pairing {
    key: String,
    expires: u64,
}

#[derive(Clone)]
pub struct State(PathBuf);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs())
}

fn bad() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

impl State {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self(dir.into())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn read<T: for<'a> Deserialize<'a>>(&self, name: &str) -> io::Result<Option<T>> {
        match fs::read(self.path(name)) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|_| bad()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 写临时文件、落盘、改名。权限 0600，属主与目录一致（管理员可能以 root 运行命令）。
    fn write<T: Serialize>(&self, name: &str, value: &T) -> io::Result<()> {
        let tmp = self.path(&format!("{name}.tmp"));
        let _ = fs::remove_file(&tmp);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(&serde_json::to_vec(value).map_err(|_| bad())?)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, chown};
            let dir = fs::metadata(&self.0)?;
            if f.metadata()?.uid() != dir.uid() {
                chown(&tmp, Some(dir.uid()), Some(dir.gid()))?;
            }
        }
        fs::rename(&tmp, self.path(name))?;
        sync_dir(&self.0)
    }

    fn saved(&self) -> io::Result<Saved> {
        Ok(self.read("state.json")?.unwrap_or_default())
    }

    /// 当前设备。读不出时按“没有”处理，即拒绝所有设备。
    pub fn current(&self) -> Option<PublicKey> {
        let text = self.saved().ok()?.current?;
        hex::decode(text).ok()?.try_into().ok()
    }

    /// 生成新的一次性配对码，旧的立即作废。
    pub fn issue_code(&self) -> io::Result<PairCode> {
        let code = PairCode::generate().map_err(|_| bad())?;
        self.write(
            "pairing.json",
            &Pairing {
                key: hex::encode(code.key()),
                expires: now() + CODE_TTL.as_secs(),
            },
        )?;
        Ok(code)
    }

    pub fn unpair(&self) -> io::Result<()> {
        self.write("state.json", &Saved::default())?;
        self.remove_code()
    }

    fn remove_code(&self) -> io::Result<()> {
        match fs::remove_file(self.path("pairing.json")) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => sync_dir(&self.0),
        }
    }

    /// 核对成功即作废。配对码有 100 位，猜不到，所以错误不计数，
    /// 否则任何人都能把管理员刚生成的码刷掉。
    fn consume_code(&self, proven: &Proven) -> io::Result<bool> {
        let Some(p) = self.read::<Pairing>("pairing.json")? else {
            return Ok(false);
        };
        let left = p.expires.saturating_sub(now());
        if left == 0 || left > CODE_TTL.as_secs() {
            self.remove_code()?;
            return Ok(false);
        }
        let key = hex::decode(&p.key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(bad)?;
        if !proven.knows_code(&key) {
            return Ok(false);
        }
        self.remove_code()?;
        Ok(true)
    }

    /// 决定一台已证明私钥的设备能否成为当前设备。调用方须保证不并发。
    pub fn admit(&self, proven: &Proven) -> Verdict {
        self.try_admit(proven).unwrap_or(Verdict::Rejected)
    }

    fn try_admit(&self, proven: &Proven) -> io::Result<Verdict> {
        let mut s = self.saved()?;
        let key = hex::encode(proven.key);
        if proven.claims() {
            if !self.consume_code(proven)? {
                return Ok(Verdict::Rejected);
            }
            s.retired.retain(|k| *k != key);
            if let Some(old) = s.current.replace(key.clone())
                && old != key
            {
                s.retired.push(old);
            }
            let extra = s.retired.len().saturating_sub(MAX_RETIRED);
            s.retired.drain(..extra);
            self.write("state.json", &s)?;
            return Ok(Verdict::Accepted);
        }
        Ok(if s.current.as_ref() == Some(&key) {
            Verdict::Accepted
        } else if s.retired.contains(&key) {
            Verdict::Superseded
        } else {
            Verdict::Rejected
        })
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_tunnel::{Identity, handshake};

    async fn proven(me: &Identity, code: Option<&PairCode>) -> Proven {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let device = async {
            let _ = handshake::prove(&mut a, "h", me, code, false).await;
        };
        let relay = async {
            let r = handshake::challenge(&mut b, "h").await;
            drop(b);
            r
        };
        tokio::join!(device, relay).1.unwrap().unwrap()
    }

    // AC-REL-02 AC-REL-03 AC-REL-04
    #[tokio::test]
    async fn takeover_needs_a_fresh_code_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::new(dir.path());
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_eq!(state.admit(&proven(&a, None).await), Verdict::Rejected);
        let wrong = PairCode::generate().unwrap();
        assert_eq!(
            state.admit(&proven(&a, Some(&wrong)).await),
            Verdict::Rejected,
            "没有签发过配对码"
        );
        let code = state.issue_code().unwrap();
        assert_eq!(
            state.admit(&proven(&a, Some(&wrong)).await),
            Verdict::Rejected
        );
        assert_eq!(
            state.admit(&proven(&a, Some(&code)).await),
            Verdict::Accepted
        );
        assert_eq!(
            state.admit(&proven(&b, Some(&code)).await),
            Verdict::Rejected,
            "配对码只能用一次"
        );
        let state = State::new(dir.path());
        assert_eq!(state.admit(&proven(&a, None).await), Verdict::Accepted);
        let code = state.issue_code().unwrap();
        assert_eq!(
            state.admit(&proven(&b, Some(&code)).await),
            Verdict::Accepted
        );
        let state = State::new(dir.path());
        assert_eq!(state.admit(&proven(&a, None).await), Verdict::Superseded);
        assert_eq!(state.admit(&proven(&b, None).await), Verdict::Accepted);
        // 重置后谁也不认，也不再区分“曾经登记过”
        state.unpair().unwrap();
        assert_eq!(state.admit(&proven(&a, None).await), Verdict::Rejected);
        assert_eq!(state.admit(&proven(&b, None).await), Verdict::Rejected);
    }

    #[tokio::test]
    async fn expired_replaced_and_damaged_codes_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::new(dir.path());
        let a = Identity::generate().unwrap();
        let old = state.issue_code().unwrap();
        let code = state.issue_code().unwrap();
        assert_eq!(
            state.admit(&proven(&a, Some(&old)).await),
            Verdict::Rejected
        );
        state
            .write(
                "pairing.json",
                &Pairing {
                    key: hex::encode(code.key()),
                    expires: now(),
                },
            )
            .unwrap();
        assert_eq!(
            state.admit(&proven(&a, Some(&code)).await),
            Verdict::Rejected
        );
        let code = state.issue_code().unwrap();
        fs::write(dir.path().join("state.json"), b"{").unwrap();
        assert_eq!(
            state.admit(&proven(&a, Some(&code)).await),
            Verdict::Rejected,
            "状态文件损坏时一律拒绝"
        );
    }

    #[test]
    fn disk_holds_no_usable_code() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::new(dir.path());
        let code = state.issue_code().unwrap().display();
        for f in fs::read_dir(dir.path()).unwrap() {
            let f = f.unwrap();
            let text = fs::read_to_string(f.path()).unwrap();
            assert!(!text.contains(&*code) && !text.contains(&code.replace('-', "")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
    }
}
