//! 创建、解锁、锁定、改密、恢复、退避。
mod common;
use common::*;
use vault_core::search::{AiSearchError, ClientId};
use vault_core::*;

// AC-VLT-01
#[test]
fn setup_writes_nothing_until_recovery_key_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.svault");
    let s = Setup::begin(&PW.into()).ok().unwrap();
    let key = s.recovery_key().expose().to_owned();
    let c = s.challenge();
    assert_ne!(c[0], c[1]);
    assert!(c.iter().all(|i| *i < 9));
    for bad in [["0000", "0000"], ["", ""], ["IIII", "####"]] {
        let e = err(s.check_answers(bad));
        assert_eq!(e, Error::RecoveryConfirmMismatch);
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let a = answers(&key, c);
    let v = s
        .confirm(&path, [&a[0].to_lowercase(), &a[1]], TestClock::new())
        .ok()
        .unwrap();
    assert_eq!(v.lock_state(), LockState::Unlocked);
    drop(v);
    // 只有密库一个文件，没有残留的临时文件
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }
    // 已存在时绝不覆盖
    assert_eq!(
        err({
            let other = Setup::begin(&PW.into()).unwrap();
            let a = answers(other.recovery_key().expose(), other.challenge());
            other.confirm(&path, [&a[0], &a[1]], TestClock::new())
        }),
        Error::AlreadyExists
    );
}

// AC-VLT-07
#[test]
fn weak_master_passwords_cannot_be_set() {
    assert_eq!(err(Setup::begin(&"short".into())), Error::PasswordTooShort);
    assert_eq!(
        err(Setup::begin(&"password123".into())),
        Error::PasswordTooCommon
    );
    let (_e, mut v) = new_env();
    let old = PW.into();
    assert_eq!(
        err(v.change_password(&old, &"1234567890".into())),
        Error::PasswordTooCommon
    );
}

#[test]
fn wrong_password_fails_and_right_one_works_after_reopen() {
    let (e, mut v) = new_env();
    let id = v.add(&note("购物清单", "假内容 一二三")).unwrap();
    drop(v);
    let mut v = e.open().unwrap();
    assert_eq!(v.lock_state(), LockState::Locked);
    assert_eq!(
        err(v.unlock(Auth::Password(&"wrong-password-xyz".into()))),
        Error::UnlockFailed
    );
    assert_eq!(v.lock_state(), LockState::Locked);
    v.unlock(Auth::Password(&PW.into())).unwrap();
    assert!(
        v.get(id)
            .ok()
            .unwrap()
            .secrets
            .body
            .unwrap()
            .ct_eq("假内容 一二三")
    );
}

#[test]
fn two_instances_cannot_open_the_same_vault() {
    let (e, _v) = new_env();
    assert_eq!(err(e.open()), Error::InUse);
}

#[test]
fn missing_and_foreign_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.svault");
    assert_eq!(err(Vault::open(&p)), Error::NotFound);
    assert!(!p.exists(), "打开不存在的文件不得新建");
    for content in [&b""[..], b"not a database at all", &[0u8; 8192]] {
        std::fs::write(&p, content).unwrap();
        assert!(Vault::open(&p).is_err());
        assert!(std::fs::read(&p).unwrap() == content, "不得改动陌生文件");
    }
}

// AC-VLT-05, AC-KEY-05
#[test]
fn lock_states_gate_every_operation() {
    let (_e, mut v) = new_env();
    let id = v
        .add(&login(
            "公司邮箱",
            "https://mail.example.test",
            "fakeuser",
            "Fake-Pw-1",
        ))
        .unwrap();
    let client = ClientId([1; 16]);
    v.search("fakeuser", 10).unwrap();

    v.lock(LockMode::KeepServing);
    assert_eq!(v.lock_state(), LockState::Serving);
    // 服务中：AI 能搜元数据，界面看不到列表与机密
    assert_eq!(v.ai().unwrap().search(client, "公司邮箱").unwrap().len(), 1);
    assert!(v.approval_meta(id).is_ok());
    assert_eq!(err(v.get(id)), Error::Locked);
    assert_eq!(err(v.list(ListFilter::Active)), Error::Locked);
    assert_eq!(err(v.search("公司", 10)), Error::Locked);
    assert_eq!(err(v.add(&note("a", "b"))), Error::Locked);
    assert_eq!(err(v.trash(id)), Error::Locked);
    assert_eq!(err(v.totp_code(id)), Error::Locked);
    assert_eq!(
        err(v.export_backup(std::path::Path::new("/nonexistent/x"))),
        Error::Locked
    );

    v.lock(LockMode::Full);
    assert_eq!(v.lock_state(), LockState::Locked);
    assert_eq!(err(v.ai().map(|_| ())), Error::Locked);
    assert_eq!(err(v.approval_meta(id)), Error::Locked);
    // 锁定后不能凭“保留服务”变回服务中
    v.lock(LockMode::KeepServing);
    assert_eq!(v.lock_state(), LockState::Locked);
}

// AC-KEY-08
#[test]
fn change_password_keeps_ciphertexts_and_invalidates_old() {
    let (e, mut v) = new_env();
    let id = v.add(&note("笔记", "假正文-abcdef")).unwrap();
    drop(v);
    let dump = || {
        let mut rows: Vec<Vec<u8>> = Vec::new();
        sql(&e.path(), |c| {
            for q in ["SELECT blob FROM item", "SELECT blob FROM item_field"] {
                let mut s = c.prepare(q).unwrap();
                rows.extend(s.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()));
            }
        });
        rows
    };
    let before = dump();
    let mut v = e.unlocked();
    assert_eq!(
        err(v.change_password(&"not-the-old-password".into(), &PW2.into())),
        Error::UnlockFailed
    );
    v.change_password(&PW.into(), &PW2.into()).unwrap();
    drop(v);
    assert_eq!(dump(), before, "数据密钥不变，条目不应重新加密");
    let mut v = e.open().unwrap();
    assert_eq!(
        err(v.unlock(Auth::Password(&PW.into()))),
        Error::UnlockFailed
    );
    v.unlock(Auth::Password(&PW2.into())).unwrap();
    assert!(v.get(id).is_ok());
    // 恢复密钥不受影响
    assert!(v.unlock_with_recovery(&e.recovery_key()).is_ok());
}

// AC-KEY-06
#[test]
fn recovery_key_forces_new_password_and_rotates_itself() {
    let (e, mut v) = new_env();
    let id = v.add(&note("笔记", "假正文-recovery")).unwrap();
    let dk = Key::random().ok().unwrap();
    v.enroll_device_key(&PW.into(), &dk).unwrap();
    drop(v);

    let mut v = e.open().unwrap();
    let original = e.recovery_key();
    let ticket = v.unlock_with_recovery(&original).ok().unwrap();
    // 仅凭恢复密钥不能读取
    assert_eq!(v.lock_state(), LockState::Locked);
    assert_eq!(err(v.get(id)), Error::Locked);
    assert_eq!(
        err(v.prepare_password_reset(&ticket, &"short".into())),
        Error::PasswordTooShort
    );
    let p = v.prepare_password_reset(&ticket, &PW2.into()).ok().unwrap();
    let new_key = p.recovery_key().expose().to_owned();
    assert_ne!(new_key, e.recovery);
    assert_eq!(
        err(v.commit_recovery(&p, ["0000", "0000"])),
        Error::RecoveryConfirmMismatch
    );
    // 核对前什么都没变
    v.unlock(Auth::Password(&PW.into())).unwrap();
    v.lock(LockMode::Full);
    let a = answers(&new_key, p.challenge());
    assert_eq!(
        err(v.commit_recovery(&p, [&a[0], &a[1]])),
        Error::UnlockFailed
    );
    assert_eq!(
        err(v.prepare_password_reset(&ticket, &PW2.into())),
        Error::UnlockFailed
    );
    let ticket = v.unlock_with_recovery(&original).ok().unwrap();
    let p = v.prepare_password_reset(&ticket, &PW2.into()).ok().unwrap();
    let new_key = p.recovery_key().expose().to_owned();
    let a = answers(&new_key, p.challenge());
    v.commit_recovery(&p, [&a[0], &a[1]]).unwrap();
    assert_eq!(
        err(v.commit_recovery(&p, [&a[0], &a[1]])),
        Error::UnlockFailed
    );
    assert!(v.get(id).is_ok());
    drop(v);

    let mut v = e.open().unwrap();
    assert!(!v.has_device_key(), "重设主密码后旧设备密钥失效");
    assert_eq!(
        err(v.unlock(Auth::Password(&PW.into()))),
        Error::UnlockFailed
    );
    assert_eq!(
        err(v.unlock_with_recovery(&e.recovery_key())),
        Error::UnlockFailed
    );
    e.clock.advance(600_000);
    v.unlock(Auth::Password(&PW2.into())).unwrap();
    let k = RecoveryKey::parse(&new_key).ok().unwrap();
    assert!(v.unlock_with_recovery(&k).is_ok());
}

#[test]
fn recovery_key_can_be_reissued_with_password() {
    let (e, mut v) = new_env();
    let p = v.prepare_recovery_reissue(&PW.into()).ok().unwrap();
    let key = p.recovery_key().expose().to_owned();
    let a = answers(&key, p.challenge());
    v.commit_recovery(&p, [&a[0], &a[1]]).unwrap();
    assert_eq!(
        err(v.unlock_with_recovery(&e.recovery_key())),
        Error::UnlockFailed
    );
    let k = RecoveryKey::parse(&key).ok().unwrap();
    assert!(v.unlock_with_recovery(&k).is_ok());
    v.unlock(Auth::Password(&PW.into())).unwrap();
}

#[test]
fn device_key_unlocks_and_can_be_removed() {
    let (e, mut v) = new_env();
    let dk = Key::random().ok().unwrap();
    assert_eq!(err(v.unlock(Auth::DeviceKey(&dk))), Error::UnlockFailed);
    v.enroll_device_key(&PW.into(), &dk).unwrap();
    drop(v);
    let mut v = e.open().unwrap();
    v.unlock(Auth::DeviceKey(&dk)).unwrap();
    let other = Key::random().ok().unwrap();
    assert_eq!(err(v.unlock(Auth::DeviceKey(&other))), Error::UnlockFailed);
    v.remove_device_key().unwrap();
    assert!(!v.has_device_key());
    assert_eq!(err(v.unlock(Auth::DeviceKey(&dk))), Error::UnlockFailed);
}

// AC-KEY-07
#[test]
fn failures_back_off_and_survive_restart() {
    let (e, v) = new_env();
    drop(v);
    let wrong: SecretString = "wrong-password-xyz".into();
    let mut v = e.open().unwrap();
    for _ in 0..3 {
        assert_eq!(err(v.unlock(Auth::Password(&wrong))), Error::UnlockFailed);
    }
    // 第 3 次之后要等 2 秒；等待期内正确的口令也不行
    assert_eq!(
        err(v.unlock(Auth::Password(&PW.into()))),
        Error::Backoff(2000)
    );
    // 重启不能绕过
    drop(v);
    let mut v = e.open().unwrap();
    assert_eq!(v.backoff_remaining_ms(), 2000);
    // 恢复密钥走同一个计数
    assert_eq!(
        err(v.unlock_with_recovery(&e.recovery_key())),
        Error::Backoff(2000)
    );
    // 把系统时钟调快也不能绕过本进程内的等待
    e.clock.shift_wall(3_600_000);
    assert_eq!(v.backoff_remaining_ms(), 2000);
    e.clock.advance(2000);
    let k2 = RecoveryKey::parse(&{
        let s = Setup::begin(&PW2.into()).ok().unwrap();
        s.recovery_key().expose().to_owned()
    })
    .ok()
    .unwrap();
    // 主密码错误与恢复密钥错误表现一致
    assert_eq!(err(v.unlock_with_recovery(&k2)), Error::UnlockFailed);
    assert_eq!(v.backoff_remaining_ms(), 4000);
    e.clock.advance(4000);
    v.unlock(Auth::Password(&PW.into())).unwrap();
    assert_eq!(v.backoff_remaining_ms(), 0);
    // 成功后计数清零
    assert_eq!(err(v.unlock(Auth::Password(&wrong))), Error::UnlockFailed);
    assert_eq!(v.backoff_remaining_ms(), 0);
}

#[test]
fn attempt_is_recorded_before_the_kdf_runs() {
    // 失败计数已落盘：直接读数据库确认
    let (e, v) = new_env();
    drop(v);
    let mut v = e.open().unwrap();
    let _ = v.unlock(Auth::Password(&"wrong-password-xyz".into()));
    drop(v);
    sql(&e.path(), |c| {
        let n: i64 = c
            .query_row("SELECT fail_count FROM header", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    });
}

#[test]
fn grant_approval_failures_also_count() {
    let (_e, mut v) = new_env();
    let id = v
        .add(&login(
            "站点甲",
            "https://a.example.test",
            "fakeuser",
            "Fake-Pw-1",
        ))
        .unwrap();
    let f = [model::AiField::Password];
    for _ in 0..3 {
        let r = v.reveal_for_grant(id, &f, Auth::Password(&"wrong-password-xyz".into()));
        assert_eq!(err(r), Error::UnlockFailed);
    }
    assert!(v.backoff_remaining_ms() > 0);
}

#[test]
fn ai_search_needs_at_least_metadata_key() {
    let (e, mut v) = new_env();
    v.add(&note("护照信息", "FAKE-E0000000")).unwrap();
    assert_eq!(
        v.ai().unwrap().search(ClientId([0; 16]), "护"),
        Err(AiSearchError::QueryTooShort)
    );
    drop(v);
    let mut v = e.open().unwrap();
    assert!(v.ai().is_err());
}
