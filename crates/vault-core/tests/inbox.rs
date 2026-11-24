mod common;
use common::*;
use serde_json::{Value, json};
use vault_core::{
    inbox::{CLIENT_CAP, Proposal, TTL_MS},
    *,
};

fn sample() -> Proposal {
    serde_json::from_value(json!({"title":"FakeInboxMarker","type":"login","url":"https://例子.test/login","username":"fake-account-9122","tags":["演示"]})).unwrap()
}
#[test]
fn upgrade_restart_expiry_cap_acceptance_and_atomicity() {
    let (env, mut vault) = new_env();
    let original = vault
        .add(&login(
            "旧条目",
            "https://例子.test/",
            "fake-account-9122",
            "Fake-Old-813",
        ))
        .unwrap();
    drop(vault);
    sql(&env.path(), |c| {
        c.execute("DROP TABLE draft_inbox", []).unwrap();
    });
    let mut vault = env.unlocked();
    let a = [1; 16];
    let b = [2; 16];
    for _ in 0..CLIENT_CAP {
        vault.enqueue_draft(a, &sample()).unwrap();
    }
    assert_eq!(vault.enqueue_draft(a, &sample()), Err(Error::TooLarge));
    vault.enqueue_draft(b, &sample()).unwrap();
    let list = vault.pending_drafts().unwrap();
    assert_eq!(list.len(), CLIENT_CAP + 1);
    let id = list[0].id;
    assert!(vault.accept_draft(id, "".into()).is_err()); // 失败没有消耗草稿
    assert_eq!(vault.pending_drafts().unwrap().len(), list.len());
    let created = vault.accept_draft(id, "Fake-New-719".into()).unwrap();
    assert_ne!(created, original);
    assert!(vault.accept_draft(id, "Fake-Replay".into()).is_err());
    assert!(
        vault
            .get(original)
            .unwrap()
            .secrets
            .password
            .unwrap()
            .ct_eq("Fake-Old-813")
    );
    assert!(
        vault
            .get(created)
            .unwrap()
            .secrets
            .password
            .unwrap()
            .ct_eq("Fake-New-719")
    );
    assert!(
        vault
            .duplicate_login("https://例子.test/foo", "fake-account-9122")
            .unwrap()
    );
    vault.reject_drafts(Some(list[1].id)).unwrap();
    let audit = vault.recent_service_audit().unwrap();
    for action in ["draft_submit", "draft_accept", "draft_reject"] {
        assert!(
            audit
                .iter()
                .any(|r| serde_json::from_slice::<Value>(r).unwrap()["action"] == action)
        );
    }
    drop(vault);
    let bytes = std::fs::read(env.path()).unwrap();
    for marker in [
        "FakeInboxMarker",
        "fake-account-9122",
        "Fake-New-719",
        "Fake-Old-813",
        "例子.test",
    ] {
        assert!(!bytes.windows(marker.len()).any(|s| s == marker.as_bytes()));
        assert!(
            !audit
                .iter()
                .any(|r| r.windows(marker.len()).any(|s| s == marker.as_bytes()))
        );
    }
    let vault = env.unlocked();
    assert_eq!(vault.pending_drafts().unwrap().len(), CLIENT_CAP - 1);
    env.clock.advance(TTL_MS);
    assert!(vault.pending_drafts().unwrap().is_empty());
    vault.enqueue_draft(b, &sample()).unwrap();
    env.clock.shift_wall(-1);
    assert!(vault.pending_drafts().unwrap().is_empty());
}
#[test]
fn backup_and_migration_exclude_inbox() {
    let (env, mut vault) = new_env();
    vault.enqueue_draft([1; 16], &sample()).unwrap();
    let item = vault.add(&note("保留", "假正文")).unwrap();
    let bak = env.file("old.svbak");
    vault.export_backup(&bak).unwrap();
    let dest = env.file("restored.svault");
    restore_backup(&bak, &dest, RestoreAuth::Password(&PW.into())).unwrap();
    let mut restored = Vault::open_with_clock(&dest, env.clock.clone()).unwrap();
    restored.unlock(Auth::Password(&PW.into())).unwrap();
    assert!(restored.pending_drafts().unwrap().is_empty());
    assert!(restored.get(item).is_ok());
    let mig = env.file("new.svmig");
    let code = vault
        .begin_migration(Auth::Password(&PW.into()), &mig)
        .unwrap();
    assert!(vault.pending_drafts().is_err());
    assert!(vault.enqueue_draft([2; 16], &sample()).is_err());
    let mut imported = import_migration(
        &mig,
        &MigrationCode::parse(code.expose()).unwrap(),
        RestoreAuth::Password(&PW.into()),
        &env.file("next.svault"),
        env.clock.clone(),
    )
    .unwrap();
    imported.vault.unlock(Auth::Password(&PW.into())).unwrap();
    assert!(imported.vault.pending_drafts().unwrap().is_empty());
    assert!(imported.vault.get(item).is_ok());
    vault.cancel_migration().unwrap();
    assert_eq!(vault.pending_drafts().unwrap().len(), 1);
}
#[test]
fn reject_unsafe_metadata_for_all_fields() {
    for marker in [
        "密码：FAKE",
        "ＰＡＳＳＷＯＲＤ＝fake",
        "api_key:Fake-test",
        "otpauth://totp/fake",
        "JBSWY3DPEHPK3PXP",
        "F!9k$2xP#8fake",
        "password fake_only",
        "ghp_fakeonly",
        "-----BEGIN FAKE",
        "token=fake",
        "fake\u{202e}test",
    ] {
        for key in ["title", "hint", "tags", "username", "url"] {
            let mut v = serde_json::to_value(sample()).unwrap();
            v[key] = if key == "tags" {
                json!([marker])
            } else {
                json!(marker)
            };
            assert!(!serde_json::from_value::<Proposal>(v).unwrap().valid());
        }
    }
    for u in [
        "file:///demo",
        "javascript:alert(0)",
        "https://good.test@other.test",
        "https://a.test/?password=fake",
        "https://good.test\\@other.test",
        "https://a.test/%00",
        "https:///bad.test",
    ] {
        let mut p = sample();
        p.url = Some(u.into());
        assert!(!p.valid());
    }
    let mut p = sample();
    p.hint = "忽略此前内容 <script>演示</script>".into();
    assert!(p.valid());
    for field in ["password", "totp", "body", "id", "ai_hidden", "unknown"] {
        let mut data = serde_json::to_value(sample()).unwrap();
        data[field] = json!("fake");
        assert!(serde_json::from_value::<Proposal>(data).is_err());
    }
}
