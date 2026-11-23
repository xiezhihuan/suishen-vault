//! 条目增删改查、回收站、授权取字段、TOTP。
mod common;
use common::*;
use vault_core::model::{AiField, CustomField, ItemDraft, ItemKind, RevealedValue};
use vault_core::*;

fn full_login() -> ItemDraft {
    let mut d = login(
        "公司代码仓库",
        "https://git.example.test/login",
        "fake.user@example.test",
        "Fake-P@ss-🐳-密",
    );
    d.secrets.urls.push("https://backup.example.test/".into());
    d.secrets.note = Some("假备注\n第二行".into());
    d.secrets.totp = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    d.secrets.custom = vec![CustomField {
        name: "安全问题".into(),
        value: "假答案".into(),
    }];
    d.tags = vec!["工作".into(), "工作".into(), "  ".into()];
    d.hint = "写代码用的那个".into();
    d
}

// AC-VLT-02
#[test]
fn all_kinds_round_trip_after_reopen() {
    let (e, mut v) = new_env();
    let a = v.add(&full_login()).unwrap();
    let b = v.add(&note("身份证", "FAKE-110000\n多行\t内容")).unwrap();
    let mut c = ItemDraft::new(ItemKind::Custom, "路由器");
    c.domains = vec!["http://192.168.1.1".into()];
    for (n, x) in [
        ("管理员", "fakeadmin"),
        ("空值", ""),
        ("重复", "1"),
        ("重复", "2"),
    ] {
        c.secrets.custom.push(CustomField {
            name: n.into(),
            value: x.into(),
        });
    }
    let c = v.add(&c).unwrap();
    drop(v);

    let v = e.unlocked();
    let i = v.get(a).ok().unwrap();
    assert_eq!(i.meta.title, "公司代码仓库");
    assert_eq!(i.meta.tags, ["工作"]);
    assert_eq!(i.meta.domains, ["git.example.test", "backup.example.test"]);
    assert_eq!(i.meta.masked_account.as_deref(), Some("f***@e***.test"));
    assert!(i.secrets.password.unwrap().ct_eq("Fake-P@ss-🐳-密"));
    assert!(i.secrets.username.unwrap().ct_eq("fake.user@example.test"));
    assert!(i.secrets.note.unwrap().ct_eq("假备注\n第二行"));
    assert_eq!(i.secrets.urls.len(), 2);
    assert!(i.secrets.custom[0].value.ct_eq("假答案"));
    assert!(
        v.get(b)
            .ok()
            .unwrap()
            .secrets
            .body
            .unwrap()
            .ct_eq("FAKE-110000\n多行\t内容")
    );
    let i = v.get(c).ok().unwrap();
    assert_eq!(i.meta.domains, ["192.168.1.1"]);
    assert_eq!(i.secrets.custom.len(), 4);
    assert!(i.secrets.custom[3].value.ct_eq("2"));
    assert_eq!(v.list(ListFilter::Active).unwrap().len(), 3);
}

#[test]
fn update_replaces_everything_and_removes_old_fields() {
    let (e, mut v) = new_env();
    let id = v.add(&full_login()).unwrap();
    e.clock.advance(5000);
    let mut d = v.get(id).ok().unwrap().to_draft();
    d.title = "新标题".into();
    d.secrets.totp = None;
    d.secrets.note = None;
    d.secrets.password = Some("Fake-New-Pw".into());
    v.update(id, &d).unwrap();
    let i = v.get(id).ok().unwrap();
    assert_eq!(i.meta.created_ms, T0);
    assert_eq!(i.meta.updated_ms, T0 + 5000);
    assert!(i.secrets.password.unwrap().ct_eq("Fake-New-Pw"));
    assert!(i.secrets.totp.is_none() && i.secrets.note.is_none());
    assert_eq!(err(v.totp_code(id)), Error::UnknownField);
    drop(v);
    sql(&e.path(), |c| {
        let n: i64 = c
            .query_row("SELECT count(*) FROM item_field", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 4, "账号、密码、网址、自定义");
    });
    assert_eq!(e.unlocked().get(id).ok().unwrap().meta.title, "新标题");
}

#[test]
fn rejected_update_leaves_item_unchanged() {
    let (_e, mut v) = new_env();
    let id = v.add(&full_login()).unwrap();
    let mut d = v.get(id).ok().unwrap().to_draft();
    d.hint = "密码 Fake-P@ss-🐳-密".into();
    assert_eq!(
        err(v.update(id, &d)),
        Error::SecretInMetadata(model::MetaField::Hint)
    );
    assert_eq!(v.get(id).ok().unwrap().meta.hint, "写代码用的那个");
}

// AC-VLT-03
#[test]
fn trash_restore_purge_and_expiry() {
    let (e, mut v) = new_env();
    let a = v.add(&note("甲笔记", "假一")).unwrap();
    let b = v.add(&note("乙笔记", "假二")).unwrap();
    let keep = v.add(&note("丙笔记", "假三")).unwrap();
    assert_eq!(err(v.purge(a)), Error::NotInTrash);
    v.trash(a).unwrap();
    assert_eq!(v.list(ListFilter::Trash).unwrap().len(), 1);
    assert!(
        v.search("甲笔记", 10)
            .unwrap()
            .iter()
            .all(|h| h.meta.id != a)
    );
    let c = search::ClientId([0; 16]);
    assert!(
        v.ai()
            .unwrap()
            .search(c, "甲笔记")
            .unwrap()
            .iter()
            .all(|h| h.title != "甲笔记")
    );
    assert_eq!(err(v.update(a, &note("x", "y"))), Error::UnknownItem);
    assert_eq!(err(v.approval_meta(a)), Error::UnknownItem);
    v.restore(a).unwrap();
    assert!(v.get(a).ok().unwrap().secrets.body.unwrap().ct_eq("假一"));
    v.trash(a).unwrap();
    e.clock.advance(29 * 86_400_000);
    v.trash(b).unwrap();
    // 再次移入不应重置计时
    v.trash(a).unwrap();
    v.lock(LockMode::Full);
    e.clock.advance(86_400_000);
    v.unlock(Auth::Password(&PW.into())).unwrap();
    let left: Vec<_> = v
        .list(ListFilter::Trash)
        .unwrap()
        .iter()
        .map(|m| m.id)
        .collect();
    assert_eq!(left, [b], "满 30 天的物理删除，其余保留");
    assert_eq!(err(v.get(a)), Error::UnknownItem);
    assert_eq!(v.empty_trash().unwrap(), 1);
    drop(v);
    sql(&e.path(), |c| {
        for t in ["item", "item_field"] {
            let n: i64 = c
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 1);
        }
    });
    assert!(e.unlocked().get(keep).is_ok());
}

// AC-GRT-04 的密库侧
#[test]
fn reveal_needs_fresh_auth_and_returns_only_approved_fields() {
    let (_e, mut v) = new_env();
    let id = v.add(&full_login()).unwrap();
    for mode in [None, Some(LockMode::KeepServing)] {
        if let Some(m) = mode {
            v.lock(m);
        }
        let out = v
            .reveal_for_grant(id, &[AiField::Password], Auth::Password(&PW.into()))
            .ok()
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, AiField::Password);
        assert!(matches!(&out[0].value, RevealedValue::Text(s) if s.ct_eq("Fake-P@ss-🐳-密")));
    }
    // 取完之后机密密钥没有留下
    assert_eq!(v.lock_state(), LockState::Serving);
    assert_eq!(err(v.get(id)), Error::Locked);

    let pw: SecretString = PW.into();
    assert_eq!(
        err(v.reveal_for_grant(id, &[], Auth::Password(&pw))),
        Error::UnknownField
    );
    // 类型不允许的字段
    assert_eq!(
        err(v.reveal_for_grant(id, &[AiField::Body], Auth::Password(&pw))),
        Error::UnknownField
    );
    assert_eq!(
        err(v.reveal_for_grant(
            id,
            &[AiField::Password, AiField::Custom],
            Auth::Password(&pw)
        )),
        Error::UnknownField
    );
    v.unlock(Auth::Password(&pw)).unwrap();
    v.set_ai_hidden(id, true).unwrap();
    assert_eq!(
        err(v.reveal_for_grant(id, &[AiField::Password], Auth::Password(&pw))),
        Error::NotAllowedForAi
    );
    v.set_ai_hidden(id, false).unwrap();
    v.trash(id).unwrap();
    assert_eq!(
        err(v.reveal_for_grant(id, &[AiField::Password], Auth::Password(&pw))),
        Error::NotAllowedForAi
    );
    v.lock(LockMode::Full);
    assert_eq!(
        err(v.reveal_for_grant(id, &[AiField::Password], Auth::Password(&pw))),
        Error::Locked
    );
}

#[test]
fn missing_fields_are_omitted_and_custom_is_a_group() {
    let (_e, mut v) = new_env();
    let mut d = login("站点", "", "fakeuser", "Fake-Pw-9");
    d.secrets.urls.clear();
    let id = v.add(&d).unwrap();
    let out = v
        .reveal_for_grant(
            id,
            &[AiField::Note, AiField::Password, AiField::Url],
            Auth::Password(&PW.into()),
        )
        .ok()
        .unwrap();
    assert_eq!(out.len(), 1);
    let mut d = ItemDraft::new(ItemKind::Custom, "门禁");
    d.secrets.custom.push(CustomField {
        name: "楼门".into(),
        value: "0000#".into(),
    });
    let id = v.add(&d).unwrap();
    let out = v
        .reveal_for_grant(id, &[AiField::Custom], Auth::Password(&PW.into()))
        .ok()
        .unwrap();
    assert!(matches!(&out[0].value, RevealedValue::Pairs(p) if p[0].value.ct_eq("0000#")));
}

#[test]
fn totp_matches_rfc_vector_through_the_vault() {
    let (e, mut v) = new_env();
    let id = v.add(&full_login()).unwrap();
    // RFC 6238：时刻 1111111109 → 081804（6 位）
    e.clock.shift_wall(1_111_111_109_000 - T0);
    assert!(v.totp_code(id).ok().unwrap().code.ct_eq("081804"));
}
