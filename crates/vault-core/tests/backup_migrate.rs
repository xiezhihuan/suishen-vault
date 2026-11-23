//! 备份、恢复、迁移。
mod common;
use common::*;
use proptest::test_runner::{Config, TestRunner};
use vault_core::*;

fn fixture() -> (Env, Vault, model::ItemId) {
    let (e, mut v) = new_env();
    let id = v
        .add(&login(
            "甲站",
            "https://a.example.test",
            "fakeuser-a",
            "Fake-Pw-A1",
        ))
        .unwrap();
    v.add(&note("笔记", "假正文一二三")).unwrap();
    let t = v.add(&note("回收站里的", "假")).unwrap();
    v.trash(t).unwrap();
    (e, v, id)
}

fn same_content(v: &Vault, id: model::ItemId) {
    let i = v.get(id).ok().unwrap();
    assert_eq!(i.meta.title, "甲站");
    assert!(i.secrets.password.unwrap().ct_eq("Fake-Pw-A1"));
    assert_eq!(v.list(ListFilter::Active).unwrap().len(), 2);
    assert_eq!(v.list(ListFilter::Trash).unwrap().len(), 1);
}

// AC-BAK-01
#[test]
fn backup_restores_with_password_or_recovery_key() {
    let (e, mut v, id) = fixture();
    let dk = Key::random().ok().unwrap();
    v.enroll_device_key(&PW.into(), &dk).unwrap();
    let b = e.file("b.svbak");
    v.export_backup(&b).unwrap();
    assert_eq!(err(v.export_backup(&b)), Error::AlreadyExists);

    let d1 = e.file("r1.svault");
    let r = restore_backup(&b, &d1, RestoreAuth::Password(&PW.into())).unwrap();
    assert_eq!(r.items, 3);
    let mut n = Vault::open_with_clock(&d1, e.clock.clone()).unwrap();
    assert!(!n.has_device_key(), "设备密钥不随备份走");
    n.unlock(Auth::Password(&PW.into())).unwrap();
    same_content(&n, id);
    n.add(&note("恢复后可继续写", "假")).unwrap();

    // 忘了主密码：恢复密钥恢复，再强制重设
    let d2 = e.file("r2.svault");
    restore_backup(&b, &d2, RestoreAuth::Recovery(&e.recovery_key())).unwrap();
    let mut n = Vault::open_with_clock(&d2, e.clock.clone()).unwrap();
    assert_eq!(n.lock_state(), LockState::Locked);
    let original = e.recovery_key();
    let t = n.unlock_with_recovery(&original).ok().unwrap();
    let p = n.prepare_password_reset(&t, &PW2.into()).ok().unwrap();
    let a = answers(p.recovery_key().expose(), p.challenge());
    n.commit_recovery(&p, [&a[0], &a[1]]).unwrap();
    same_content(&n, id);

    let wrong = err(restore_backup(
        &b,
        &e.file("r3.svault"),
        RestoreAuth::Password(&PW2.into()),
    ));
    assert_eq!(wrong, Error::UnlockFailed);
    let other = Setup::begin(&PW.into()).ok().unwrap();
    let k = RecoveryKey::parse(other.recovery_key().expose())
        .ok()
        .unwrap();
    let wrong = err(restore_backup(
        &b,
        &e.file("r3.svault"),
        RestoreAuth::Recovery(&k),
    ));
    assert_eq!(wrong, Error::UnlockFailed);
    assert!(!e.file("r3.svault").exists());
}

// AC-BAK-02
#[test]
fn restore_never_touches_existing_files() {
    let (e, v, id) = fixture();
    let b = e.file("b.svbak");
    v.export_backup(&b).unwrap();
    drop(v);
    let before = std::fs::read(e.path()).unwrap();
    let r = restore_backup(&b, &e.path(), RestoreAuth::Password(&PW.into()));
    assert_eq!(err(r), Error::AlreadyExists);
    assert!(std::fs::read(e.path()).unwrap() == before);
    same_content(&e.unlocked(), id);
}

// AC-BAK-02
#[test]
fn every_kind_of_backup_damage_is_rejected() {
    let (e, v, _) = fixture();
    let b = e.file("b.svbak");
    v.export_backup(&b).unwrap();
    let good = std::fs::read(&b).unwrap();
    let (bad, out) = (e.file("bad.svbak"), e.file("out.svault"));
    let try_one = |bytes: &[u8]| {
        std::fs::write(&bad, bytes).unwrap();
        let r = restore_backup(&bad, &out, RestoreAuth::Password(&PW.into()));
        assert!(r.is_err());
        assert!(!out.exists());
        err(r)
    };
    for n in [0, 1, 8, 12, 100, good.len() / 2, good.len() - 1] {
        try_one(&good[..n]);
    }
    try_one(&[&good[..], b"x"].concat());
    // 头部逐字节翻转；正文抽样
    let mut runner = TestRunner::new(Config {
        cases: 60,
        failure_persistence: None,
        ..Config::default()
    });
    let len = good.len();
    runner
        .run(&(0..len, 0u8..8, proptest::bool::ANY), |(i, bit, head)| {
            let i = if head { i % 400 } else { i };
            let mut x = good.clone();
            x[i] ^= 1 << bit;
            std::fs::write(&bad, &x).unwrap();
            assert!(
                restore_backup(&bad, &out, RestoreAuth::Password(&PW.into())).is_err(),
                "第 {i} 字节"
            );
            assert!(!out.exists());
            Ok(())
        })
        .unwrap();
    // 没有残留的临时文件
    for f in std::fs::read_dir(e.dir.path()).unwrap() {
        let n = f.unwrap().file_name().into_string().unwrap();
        assert!(!n.contains(".tmp-"), "{n}");
    }
}

#[test]
fn backup_with_downgraded_kdf_is_rejected() {
    let (e, v, _) = fixture();
    let b = e.file("b.svbak");
    v.export_backup(&b).unwrap();
    let mut x = std::fs::read(&b).unwrap();
    // 魔数 8 + 版本 4 + vault_id 16 + 纪元 8 + 槽数 4 + 槽类型 1 + kdf 4 → m
    let m = 8 + 4 + 16 + 8 + 4 + 1 + 4;
    assert_eq!(x[m..m + 4], 65536u32.to_be_bytes());
    for bad in [8u32, 65535, u32::MAX] {
        x[m..m + 4].copy_from_slice(&bad.to_be_bytes());
        std::fs::write(e.file("d.svbak"), &x).unwrap();
        let r = restore_backup(
            &e.file("d.svbak"),
            &e.file("o.svault"),
            RestoreAuth::Password(&PW.into()),
        );
        assert_eq!(err(r), Error::KdfParamsRejected);
    }
}

#[test]
fn old_backup_still_opens_with_old_password_only() {
    let (e, mut v, _) = fixture();
    let b = e.file("b.svbak");
    v.export_backup(&b).unwrap();
    v.change_password(&PW.into(), &PW2.into()).unwrap();
    let r = restore_backup(&b, &e.file("a.svault"), RestoreAuth::Password(&PW2.into()));
    assert_eq!(err(r), Error::UnlockFailed);
    // 设计 8.5：改主密码对旧副本无效
    assert!(restore_backup(&b, &e.file("a.svault"), RestoreAuth::Password(&PW.into())).is_ok());
}

// AC-MIG-01、AC-MIG-02、AC-MIG-03、AC-MIG-04
#[test]
fn full_migration() {
    let (e, mut v, id) = fixture();
    let dk = Key::random().ok().unwrap();
    v.enroll_device_key(&PW.into(), &dk).unwrap();
    let pkg = e.file("m.svmig");
    let wrong: SecretString = "wrong-password-xyz".into();
    assert_eq!(
        err(v.begin_migration(Auth::Password(&wrong), &pkg)),
        Error::UnlockFailed
    );
    assert_eq!(v.device_state(), DeviceState::Active);
    let code = v
        .begin_migration(Auth::Password(&PW.into()), &pkg)
        .ok()
        .unwrap();
    assert_eq!(code.expose().len(), 28 + 6);

    // 旧设备：只读、AI 不可用、不能保留服务
    assert_eq!(v.device_state(), DeviceState::Migrating);
    assert_eq!(err(v.add(&note("a", "b"))), Error::ReadOnly);
    assert_eq!(err(v.trash(id)), Error::ReadOnly);
    assert_eq!(
        err(v.change_password(&PW.into(), &PW2.into())),
        Error::ReadOnly
    );
    assert_eq!(err(v.ai().map(|_| ())), Error::ReadOnly);
    let g = v.reveal_for_grant(id, &[model::AiField::Password], Auth::Password(&PW.into()));
    assert_eq!(err(g), Error::ReadOnly);
    same_content(&v, id);
    v.lock(LockMode::KeepServing);
    assert_eq!(v.lock_state(), LockState::Locked);

    // 新设备
    let c = MigrationCode::parse(code.expose()).ok().unwrap();
    let new_path = e.file("new.svault");
    let mut imp = import_migration(
        &pkg,
        &c,
        RestoreAuth::Password(&PW.into()),
        &new_path,
        e.clock.clone(),
    )
    .ok()
    .unwrap();
    assert_eq!(imp.items, 3);
    assert_eq!(imp.vault.lock_state(), LockState::Locked);
    assert!(!imp.vault.has_device_key());
    imp.vault.unlock(Auth::Password(&PW.into())).unwrap();
    assert_eq!(imp.vault.device_state(), DeviceState::Active);
    same_content(&imp.vault, id);
    imp.vault.add(&note("新设备可写", "假")).unwrap();

    // 旧设备重启后输入完成码
    drop(v);
    let mut v = e.open().unwrap();
    assert_eq!(v.device_state(), DeviceState::Migrating);
    assert_eq!(
        err(v.confirm_migration(imp.completion_code.expose())),
        Error::Locked
    );
    v.unlock(Auth::Password(&PW.into())).unwrap();
    for bad in ["", "0000-0000", "不是码", code.expose()] {
        assert_eq!(err(v.confirm_migration(bad)), Error::CompletionMismatch);
    }
    assert_eq!(v.device_state(), DeviceState::Migrating);
    v.confirm_migration(&imp.completion_code.expose().to_lowercase())
        .unwrap();
    assert_eq!(v.device_state(), DeviceState::Retired);
    assert_eq!(v.lock_state(), LockState::Locked);

    // 停用后什么都不能做，重启后仍然如此
    drop(v);
    let mut v = e.open().unwrap();
    assert_eq!(err(v.unlock(Auth::Password(&PW.into()))), Error::Retired);
    assert_eq!(
        err(v.unlock_with_recovery(&e.recovery_key())),
        Error::Retired
    );
    assert_eq!(err(v.cancel_migration()), Error::NotMigrating);
    v.wipe_retired().unwrap();
    assert!(!e.path().exists());
    assert!(!e.path().with_extension("svault-journal").exists());
}

#[test]
fn editing_the_retired_flag_does_not_revive_the_old_device() {
    for flag in [1, 2] {
        let (e, mut v, _) = fixture();
        let pkg = e.file("m.svmig");
        let code = v
            .begin_migration(Auth::Password(&PW.into()), &pkg)
            .ok()
            .unwrap();
        let c = MigrationCode::parse(code.expose()).ok().unwrap();
        let imp = import_migration(
            &pkg,
            &c,
            RestoreAuth::Password(&PW.into()),
            &e.file("n.svault"),
            e.clock.clone(),
        )
        .ok()
        .unwrap();
        v.confirm_migration(imp.completion_code.expose()).unwrap();
        drop(v);
        sql(&e.path(), |c| {
            c.execute("UPDATE header SET device_state = ?1", [flag])
                .unwrap();
        });
        let mut v = e.open().unwrap();
        assert_eq!(err(v.unlock(Auth::Password(&PW.into()))), Error::Retired);
        assert!(matches!(
            v.unlock_with_recovery(&e.recovery_key()),
            Err(Error::Retired | Error::ReadOnly)
        ));
    }
}

#[test]
fn migrating_flag_cannot_be_cleared_by_editing() {
    let (e, mut v, _) = fixture();
    v.begin_migration(Auth::Password(&PW.into()), &e.file("m.svmig"))
        .ok()
        .unwrap();
    drop(v);
    sql(&e.path(), |c| {
        c.execute("UPDATE header SET device_state = 1", []).unwrap();
    });
    assert_eq!(
        err(e.open().unwrap().unlock(Auth::Password(&PW.into()))),
        Error::Tampered
    );
}

// AC-MIG-01
#[test]
fn package_needs_both_code_and_password() {
    let (e, mut v, _) = fixture();
    let pkg = e.file("m.svmig");
    let code = v
        .begin_migration(Auth::Password(&PW.into()), &pkg)
        .ok()
        .unwrap();
    let good = MigrationCode::parse(code.expose()).ok().unwrap();
    let out = e.file("n.svault");
    let run = |c: &MigrationCode, a: RestoreAuth<'_>| {
        import_migration(&pkg, c, a, &out, e.clock.clone()).map(|_| ())
    };
    assert_eq!(
        err(run(&good, RestoreAuth::Password(&PW2.into()))),
        Error::UnlockFailed
    );
    // 另一次迁移的码
    let (e2, mut v2, _) = fixture();
    let other = v2
        .begin_migration(Auth::Password(&PW.into()), &e2.file("m.svmig"))
        .ok()
        .unwrap();
    let other = MigrationCode::parse(other.expose()).ok().unwrap();
    assert_eq!(
        err(run(&other, RestoreAuth::Password(&PW.into()))),
        Error::UnlockFailed
    );
    // 抄错一位
    let mut typo: Vec<char> = code.expose().chars().collect();
    typo[0] = if typo[0] == 'A' { 'B' } else { 'A' };
    assert_eq!(
        err(MigrationCode::parse(&typo.iter().collect::<String>())),
        Error::CodeFormat
    );
    // 迁移包不能当备份用
    let r = restore_backup(&pkg, &out, RestoreAuth::Password(&PW.into()));
    assert_eq!(err(r), Error::Tampered);
    // 篡改
    let bytes = std::fs::read(&pkg).unwrap();
    for i in [0, 9, 45, 70, bytes.len() / 2, bytes.len() - 1] {
        let mut x = bytes.clone();
        x[i] ^= 1;
        std::fs::write(e.file("t.svmig"), &x).unwrap();
        let r = import_migration(
            &e.file("t.svmig"),
            &good,
            RestoreAuth::Password(&PW.into()),
            &out,
            e.clock.clone(),
        );
        assert!(r.is_err());
    }
    assert!(!out.exists());
    // 恢复密钥也可以
    run(&good, RestoreAuth::Recovery(&e.recovery_key())).unwrap();
}

// AC-MIG-02
#[test]
fn migration_can_be_cancelled_and_failed_export_rolls_back() {
    let (e, mut v, id) = fixture();
    // 写包失败：自动回到活跃
    let r = v.begin_migration(Auth::Password(&PW.into()), &e.file("no/such/dir/m.svmig"));
    assert!(r.is_err());
    assert_eq!(v.device_state(), DeviceState::Active);
    v.add(&note("仍可写", "假")).unwrap();

    let code = v
        .begin_migration(Auth::Password(&PW.into()), &e.file("m.svmig"))
        .ok()
        .unwrap();
    assert_eq!(err(v.wipe_retired()), Error::ReadOnly);
    let mut v = e.open().unwrap();
    assert_eq!(err(v.cancel_migration()), Error::Locked);
    v.unlock(Auth::Password(&PW.into())).unwrap();
    v.cancel_migration().unwrap();
    v.set_ai_hidden(id, true).unwrap();
    // 取消后旧的完成码作废
    let c = MigrationCode::parse(code.expose()).ok().unwrap();
    let imp = import_migration(
        &e.file("m.svmig"),
        &c,
        RestoreAuth::Password(&PW.into()),
        &e.file("n.svault"),
        e.clock.clone(),
    )
    .ok()
    .unwrap();
    assert_eq!(
        err(v.confirm_migration(imp.completion_code.expose())),
        Error::NotMigrating
    );
    v.begin_migration(Auth::Password(&PW.into()), &e.file("m2.svmig"))
        .ok()
        .unwrap();
    assert_eq!(
        err(v.confirm_migration(imp.completion_code.expose())),
        Error::CompletionMismatch
    );
}
