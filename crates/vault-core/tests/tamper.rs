//! 拿到数据库文件的人逐行改动：必须安全失败。
mod common;
use common::*;
use rusqlite::Connection;
use vault_core::*;

/// 两条账号、一条笔记。返回关闭后的环境。
fn fixture() -> Env {
    let (e, mut v) = new_env();
    v.add(&login(
        "甲站",
        "https://a.example.test",
        "fakeuser-a",
        "Fake-Pw-A1",
    ))
    .unwrap();
    v.add(&login(
        "乙站",
        "https://b.example.test",
        "fakeuser-b",
        "Fake-Pw-B1",
    ))
    .unwrap();
    v.add(&note("笔记", "假正文一二三")).unwrap();
    e
}

fn swap_column(c: &Connection, table: &str, col: &str, key: &str) {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = c
        .prepare(&format!(
            "SELECT {key}, {col} FROM {table} ORDER BY {key} LIMIT 2"
        ))
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for (k, v) in [(&rows[0].0, &rows[1].1), (&rows[1].0, &rows[0].1)] {
        c.execute(
            &format!("UPDATE {table} SET {col} = ?1 WHERE {key} = ?2"),
            rusqlite::params![v, k],
        )
        .unwrap();
    }
}

/// 解锁并读出全部内容。
fn full_read(e: &Env) -> Result<usize> {
    let mut v = e.open()?;
    v.unlock(Auth::Password(&PW.into()))?;
    let mut n = 0;
    for m in v
        .list(ListFilter::Active)?
        .iter()
        .chain(&v.list(ListFilter::Trash)?)
    {
        v.get(m.id)?;
        n += 1;
    }
    Ok(n)
}

fn expect(what: &str, want: Error, f: impl FnOnce(&Connection)) {
    let e = fixture();
    sql(&e.path(), f);
    assert_eq!(err(full_read(&e)), want, "{what}");
}

// AC-KEY-03
#[test]
fn swaps_rollbacks_and_edits_are_detected() {
    use Error::Tampered as T;
    expect("交换两条的元数据", T, |c| {
        swap_column(c, "item", "blob", "item_id")
    });
    expect("交换两个字段的密文", T, |c| {
        swap_column(c, "item_field", "blob", "field_id")
    });
    expect("改元数据 rev", T, |c| {
        c.execute("UPDATE item SET rev = rev + 1", []).unwrap();
    });
    expect("改字段 rev", T, |c| {
        c.execute("UPDATE item_field SET rev = 2", []).unwrap();
    });
    expect("删一条", T, |c| {
        c.execute(
            "DELETE FROM item WHERE item_id = (SELECT min(item_id) FROM item)",
            [],
        )
        .unwrap();
    });
    expect("删一个字段", T, |c| {
        c.execute(
            "DELETE FROM item_field WHERE field_id = (SELECT min(field_id) FROM item_field)",
            [],
        )
        .unwrap();
    });
    expect("删全部", T, |c| {
        c.execute_batch("DELETE FROM item; DELETE FROM item_field;")
            .unwrap();
    });
    expect("复制一条", T, |c| {
        c.execute(
            "INSERT INTO item SELECT zeroblob(16), rev, blob FROM item LIMIT 1",
            [],
        )
        .unwrap();
    });
    expect("字段挪到别的条目", T, |c| {
        c.execute(
            "UPDATE item_field SET item_id = (SELECT max(item_id) FROM item)",
            [],
        )
        .unwrap();
    });
    expect("删清单", T, |c| {
        c.execute("DELETE FROM manifest", []).unwrap();
    });
    expect("改清单序号", T, |c| {
        c.execute("UPDATE manifest SET gen = gen + 1", []).unwrap();
    });
    expect("改纪元", T, |c| {
        c.execute("UPDATE header SET epoch = epoch + 1", [])
            .unwrap();
    });
    expect("截断密文", T, |c| {
        c.execute("UPDATE item SET blob = substr(blob, 1, 20)", [])
            .unwrap();
    });
    expect("空密文", T, |c| {
        c.execute("UPDATE item_field SET blob = x''", []).unwrap();
    });
    expect("条目 ID 长度不对", T, |c| {
        c.execute(
            "UPDATE item SET item_id = x'00' WHERE item_id = (SELECT min(item_id) FROM item)",
            [],
        )
        .unwrap();
    });
    expect("加触发器", T, |c| {
        c.execute_batch("CREATE TRIGGER t AFTER INSERT ON item BEGIN DELETE FROM manifest; END;")
            .unwrap();
    });
    expect("加视图", T, |c| {
        c.execute_batch("CREATE VIEW x AS SELECT 1;").unwrap()
    });
    expect("删恢复槽", T, |c| {
        c.execute("DELETE FROM key_slot WHERE slot = 2", [])
            .unwrap();
    });
    expect("改应用标识", T, |c| {
        c.execute_batch("PRAGMA application_id = 1").unwrap()
    });
    expect("改格式版本", Error::UnsupportedFormat, |c| {
        c.execute_batch("PRAGMA user_version = 2").unwrap();
    });
    expect("降格式版本", Error::UnsupportedFormat, |c| {
        c.execute_batch("PRAGMA user_version = 0").unwrap();
    });
}

/// 只把一条换回它自己的旧版本：AAD 完全合法，靠清单与摘要发现。
#[test]
fn rolling_back_a_single_row_is_detected() {
    let (e, mut v) = new_env();
    let id = v.add(&note("笔记", "假-旧内容")).unwrap();
    v.add(&note("别的", "假")).unwrap();
    drop(v);
    type SavedRow = (Vec<u8>, i64, Vec<u8>, Option<Vec<u8>>);
    let save = |t: &str| {
        let mut out: Vec<SavedRow> = Vec::new();
        sql(&e.path(), |c| {
            let q = if t == "item" {
                "SELECT item_id, rev, blob, NULL FROM item".to_owned()
            } else {
                "SELECT item_id, rev, blob, field_id FROM item_field".to_owned()
            };
            let mut s = c.prepare(&q).unwrap();
            out = s
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
        });
        out
    };
    let (items, fields) = (save("item"), save("item_field"));
    let hexid = id.to_hex();
    let mut v = e.unlocked();
    v.update(id, &note("笔记", "假-新内容")).unwrap();
    drop(v);
    let is = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>() == hexid;
    sql(&e.path(), |c| {
        for (i, rev, blob, _) in items.iter().filter(|r| is(&r.0)) {
            c.execute(
                "UPDATE item SET rev = ?2, blob = ?3 WHERE item_id = ?1",
                rusqlite::params![i, rev, blob],
            )
            .unwrap();
        }
        c.execute(
            "DELETE FROM item_field WHERE lower(hex(item_id)) = ?1",
            [&hexid],
        )
        .unwrap();
        for (i, rev, blob, f) in fields.iter().filter(|r| is(&r.0)) {
            c.execute(
                "INSERT INTO item_field VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![i, f, rev, blob],
            )
            .unwrap();
        }
    });
    assert_eq!(err(full_read(&e)), Error::Tampered);
}

#[test]
fn rows_from_another_vault_do_not_decrypt() {
    let (e1, e2) = (fixture(), fixture());
    sql(&e1.path(), |c| {
        c.execute("ATTACH ?1 AS o", [e2.path().to_str().unwrap()])
            .unwrap();
        c.execute_batch(
            "DELETE FROM item; DELETE FROM item_field; DELETE FROM manifest;
             INSERT INTO item SELECT * FROM o.item;
             INSERT INTO item_field SELECT * FROM o.item_field;
             INSERT INTO manifest SELECT * FROM o.manifest;",
        )
        .unwrap();
    });
    assert_eq!(err(full_read(&e1)), Error::Tampered);
    // 连密钥槽一起换（口令相同）：包裹密文绑定 vault_id，解不开
    sql(&e1.path(), |c| {
        c.execute("ATTACH ?1 AS o", [e2.path().to_str().unwrap()])
            .unwrap();
        c.execute_batch("DELETE FROM key_slot; INSERT INTO key_slot SELECT * FROM o.key_slot;")
            .unwrap();
    });
    assert_eq!(err(full_read(&e1)), Error::UnlockFailed);
}

// AC-KEY-01
#[test]
fn kdf_downgrade_is_rejected_before_unlock() {
    for (what, stmt) in [
        ("内存降到 8 KiB", "UPDATE key_slot SET m = 8 WHERE slot = 1"),
        (
            "内存略低于下限",
            "UPDATE key_slot SET m = 65535 WHERE slot = 1",
        ),
        ("次数降到 1", "UPDATE key_slot SET t = 1 WHERE slot = 1"),
        ("并行降到 1", "UPDATE key_slot SET p = 1 WHERE slot = 1"),
        (
            "内存 4 TiB",
            "UPDATE key_slot SET m = 4294967295 WHERE slot = 1",
        ),
        ("次数过大", "UPDATE key_slot SET t = 1000000 WHERE slot = 1"),
        ("负数", "UPDATE key_slot SET m = -1 WHERE slot = 1"),
        (
            "主密码槽改用 HKDF",
            "UPDATE key_slot SET kdf = 2, m = 0, t = 0, p = 0 WHERE slot = 1",
        ),
        ("未知算法", "UPDATE key_slot SET kdf = 9 WHERE slot = 1"),
        (
            "恢复槽改用 Argon2",
            "UPDATE key_slot SET kdf = 1, m = 65536, t = 3, p = 4 WHERE slot = 2",
        ),
    ] {
        let e = fixture();
        sql(&e.path(), |c| {
            c.execute(stmt, []).unwrap();
        });
        assert_eq!(err(e.open()), Error::KdfParamsRejected, "{what}");
    }
    // 在允许范围内改动参数：AAD 与派生结果都变了，解不开
    for stmt in [
        "UPDATE key_slot SET t = 4 WHERE slot = 1",
        "UPDATE key_slot SET m = 65537 WHERE slot = 1",
        "UPDATE key_slot SET salt = zeroblob(16) WHERE slot = 1",
    ] {
        expect(stmt, Error::UnlockFailed, |c| {
            c.execute(stmt, []).unwrap();
        });
    }
}

// AC-KEY-02
#[test]
fn wrapped_keys_cannot_be_exchanged() {
    for stmt in [
        // 把元数据密钥的包裹当成机密密钥用，或反过来
        "UPDATE key_slot SET wrapped_sdk = wrapped_mdk WHERE slot = 1",
        "UPDATE key_slot SET wrapped_mdk = wrapped_sdk WHERE slot = 1",
        // 用恢复槽的包裹替换主密码槽
        "UPDATE key_slot SET (salt, wrapped_mdk, wrapped_sdk) =
         (SELECT salt, wrapped_mdk, wrapped_sdk FROM key_slot WHERE slot = 2) WHERE slot = 1",
    ] {
        expect(stmt, Error::UnlockFailed, |c| {
            c.execute(stmt, []).unwrap();
        });
    }
}

/// 改主密码后，把旧的主密码槽放回去：旧口令能解开包裹，但清单对不上。
#[test]
fn restoring_an_old_password_slot_is_detected() {
    let e = fixture();
    let mut old: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    sql(&e.path(), |c| {
        old.push(
            c.query_row(
                "SELECT salt, wrapped_mdk, wrapped_sdk FROM key_slot WHERE slot = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap(),
        );
    });
    let mut v = e.unlocked();
    v.change_password(&PW.into(), &PW2.into()).unwrap();
    drop(v);
    sql(&e.path(), |c| {
        c.execute(
            "UPDATE key_slot SET salt = ?1, wrapped_mdk = ?2, wrapped_sdk = ?3 WHERE slot = 1",
            rusqlite::params![old[0].0, old[0].1, old[0].2],
        )
        .unwrap();
    });
    assert_eq!(err(full_read(&e)), Error::Tampered);
}

#[test]
fn corrupt_searchable_field_leaves_vault_locked() {
    // 解锁时建立全文索引，任何损坏的检索字段都不能导致部分解锁。
    let e = fixture();
    let mut v = e.unlocked();
    let ids: Vec<_> = v
        .list(ListFilter::Active)
        .unwrap()
        .iter()
        .map(|m| m.id)
        .collect();
    drop(v);
    sql(&e.path(), |c| {
        c.execute(
            "UPDATE item_field SET blob = zeroblob(120) WHERE lower(hex(item_id)) = ?1",
            [ids[0].to_hex()],
        )
        .unwrap();
    });
    v = e.open().unwrap();
    assert_eq!(v.unlock(Auth::Password(&PW.into())), Err(Error::Tampered));
    assert_eq!(v.lock_state(), LockState::Locked);
    assert_eq!(err(v.get(ids[0])), Error::Locked);
    let out = e.file("x.svbak");
    assert_eq!(err(v.export_backup(&out)), Error::Locked);
    assert!(!out.exists());
}

#[test]
fn failure_counter_tampering_does_not_panic_or_lock_forever() {
    for stmt in [
        "UPDATE header SET fail_count = -1",
        "UPDATE header SET fail_count = 9223372036854775807",
        "UPDATE header SET fail_at_ms = 9223372036854775807, fail_count = 100",
        "UPDATE header SET fail_at_ms = -9223372036854775808, fail_count = 100",
    ] {
        let e = fixture();
        sql(&e.path(), |c| {
            c.execute(stmt, []).unwrap();
        });
        let mut v = e.open().unwrap();
        assert!(v.backoff_remaining_ms() <= 300_000);
        e.clock.advance(300_000);
        v.unlock(Auth::Password(&PW.into())).unwrap();
    }
}
