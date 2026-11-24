//! 用临时目录与假密码走界面会触发的规则。
use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use vault_core::ExposureScope;

const PW: &str = "fake-master-鲸鱼-0001";
const NEW_PW: &str = "fake-master-海豚-0002";
const SECRET: &str = "Fake-Violet-Secret-7172";
const USER: &str = "fake.user@example.test";

struct Fixture {
    state: AppState,
    recovery: String,
    dir: tempfile::TempDir,
}

fn s(v: &str) -> SecretString {
    v.into()
}
fn answers(out: &Value) -> Vec<Secret> {
    let key = out["recovery_key"].as_str().unwrap();
    out["challenge"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| Secret(s(key.split('-').nth(i.as_u64().unwrap() as usize).unwrap())))
        .collect()
}
fn wrong() -> Vec<Secret> {
    vec![Secret(s("0000")), Secret(s("0000"))]
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(dir.path().to_owned());
    let out = state.setup_begin(&s(PW)).unwrap();
    state.setup_confirm(&answers(&out)).unwrap();
    Fixture {
        state,
        recovery: out["recovery_key"].as_str().unwrap().into(),
        dir,
    }
}
fn draft(v: Value) -> DraftIn {
    serde_json::from_value(v).unwrap()
}
fn login(title: &str) -> DraftIn {
    draft(
        json!({"kind":"login","title":title,"domains":[],"auto_domains":true,"tags":["工作"],
        "hint":"","ai_hidden":false,"username":USER,"password":SECRET,"note":null,"totp":null,
        "body":null,"urls":["https://example.test/login"],"custom":null}),
    )
}
fn code<T>(r: Ui<T>) -> &'static str {
    r.err().expect("应当失败").code
}
fn phase(st: &AppState) -> String {
    st.poll()["phase"].as_str().unwrap().to_owned()
}
/// 各测试用不同端口，避免并行时互相占用。
fn set_port(st: &AppState) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = 40_000 + (std::process::id() % 2000) * 8;
    let port = base + NEXT.fetch_add(1, Ordering::SeqCst);
    let mut v = st.settings();
    v.port = port as u16;
    st.set_settings(v).unwrap();
}

// AC-VLT-01
#[test]
fn setup_writes_nothing_until_the_recovery_key_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let st = AppState::new(dir.path().to_owned());
    assert_eq!(phase(&st), "empty");
    assert_eq!(code(st.setup_begin(&s("short"))), "password_short");
    let out = st.setup_begin(&s(PW)).unwrap();
    assert_eq!(code(st.setup_confirm(&wrong())), "recovery_mismatch");
    assert!(!dir.path().join(VAULT_FILE).exists());
    st.setup_confirm(&answers(&out)).unwrap();
    assert_eq!(phase(&st), "unlocked");
    assert_eq!(code(st.setup_begin(&s(PW))), "exists");
}

// AC-VLT-02 AC-VLT-05
#[test]
fn items_survive_restart_and_are_unreachable_while_locked() {
    let f = fixture();
    let st = &f.state;
    let id = st.save_item(None, login("公司邮箱")).unwrap();
    let detail = st.item(&id).unwrap();
    assert_eq!(detail["has"]["password"], true);
    // 列表、详情、状态里都没有机密
    for v in [st.list(false, "").unwrap(), detail, st.poll()] {
        let t = v.to_string();
        assert!(!t.contains(SECRET) && !t.contains(USER) && !t.contains(PW));
    }
    assert_eq!(st.reveal(&id, SecretField::Password, 0).unwrap(), SECRET);
    assert_eq!(st.list(false, "公司").unwrap().as_array().unwrap().len(), 1);

    // 编辑时不传机密，原值保持不变
    let edit = draft(
        json!({"kind":"login","title":"新标题","domains":[],"auto_domains":true,
        "tags":[],"hint":"","ai_hidden":true,"username":null,"password":null,"note":"备注",
        "totp":null,"body":null,"urls":null,"custom":null}),
    );
    st.save_item(Some(&id), edit).unwrap();
    assert_eq!(st.reveal(&id, SecretField::Password, 0).unwrap(), SECRET);
    assert_eq!(st.reveal(&id, SecretField::Note, 0).unwrap(), "备注");
    // 空字符串表示删除该字段
    let edit = draft(
        json!({"kind":"login","title":"新标题","domains":[],"auto_domains":true,
        "tags":[],"hint":"","ai_hidden":true,"username":null,"password":null,"note":"",
        "totp":null,"body":null,"urls":null,"custom":null}),
    );
    st.save_item(Some(&id), edit).unwrap();
    assert_eq!(code(st.reveal(&id, SecretField::Note, 0)), "unknown_field");

    st.lock();
    assert_eq!(phase(st), "locked");
    assert_eq!(code(st.list(false, "")), "locked");
    assert_eq!(code(st.item(&id)), "locked");
    assert_eq!(code(st.reveal(&id, SecretField::Password, 0)), "locked");
    assert_eq!(code(st.copy_field(&id, SecretField::Password, 0)), "locked");
    assert_eq!(code(st.save_item(None, login("x"))), "locked");
    assert_eq!(code(st.clients()), "locked");
    assert_eq!(code(st.audit("")), "locked");
    assert_eq!(
        code(st.unlock(&s("fake-wrong-master-000"))),
        "unlock_failed"
    );

    let dir = f.dir;
    drop(f.state);
    let st = AppState::new(dir.path().to_owned());
    assert_eq!(phase(&st), "locked");
    st.unlock(&s(PW)).unwrap();
    assert_eq!(st.reveal(&id, SecretField::Password, 0).unwrap(), SECRET);
}

#[test]
fn trash_actions() {
    let f = fixture();
    let st = &f.state;
    let id = st.save_item(None, login("甲")).unwrap();
    assert_eq!(code(st.item_action(&id, "purge")), "not_in_trash");
    st.item_action(&id, "trash").unwrap();
    assert_eq!(st.list(true, "").unwrap().as_array().unwrap().len(), 1);
    st.item_action(&id, "restore").unwrap();
    st.item_action(&id, "hide_from_ai").unwrap();
    assert_eq!(st.item(&id).unwrap()["ai_hidden"], true);
    st.item_action(&id, "trash").unwrap();
    assert_eq!(st.empty_trash().unwrap(), 1);
    assert_eq!(code(st.item(&id)), "unknown_item");
}

// AC-VLT-08
#[test]
fn secrets_in_searchable_text_are_refused_without_echoing_them() {
    let f = fixture();
    let mut d = login("甲");
    d.hint = format!("密码 {SECRET}");
    let e = f.state.save_item(None, d).err().unwrap();
    assert_eq!(e.code, "secret_in_metadata");
    assert!(e.message.contains("检索提示") && !e.message.contains(SECRET));
}

// AC-VLT-06
#[test]
fn idle_sleep_and_screen_lock_all_lock_the_vault() {
    let f = fixture();
    let st = &f.state;
    let unlock = || {
        st.unlock(&s(PW)).unwrap();
        st.tick(false);
        assert_eq!(phase(st), "unlocked");
    };
    unlock();
    assert!(!st.tick(false).locked);
    st.rewind_activity(Duration::from_secs(4 * 60 + 50));
    assert!(!st.tick(false).locked);
    st.rewind_activity(Duration::from_secs(20));
    assert!(st.tick(false).locked);
    assert_eq!(phase(st), "locked");

    unlock();
    st.rewind_activity(Duration::from_secs(4 * 60 + 50));
    st.touch();
    st.rewind_activity(Duration::from_secs(20));
    assert!(!st.tick(false).locked, "有操作就重新计时");

    unlock();
    st.rewind_tick(Duration::from_secs(30));
    assert!(st.tick(false).locked, "休眠后锁定");

    unlock();
    assert!(st.tick(true).locked, "锁屏时锁定");
    unlock();
    assert!(!st.tick(false).locked);
}

// AC-KEY-06
#[test]
fn recovery_key_resets_the_master_password_and_is_replaced() {
    let f = fixture();
    let st = &f.state;
    st.save_item(None, login("甲")).unwrap();
    st.lock();
    assert_eq!(
        code(st.recovery_begin(&s("bad"), &s(NEW_PW))),
        "code_format"
    );
    assert_eq!(
        code(st.recovery_begin(&s(&f.recovery), &s("short"))),
        "password_short"
    );
    let out = st.recovery_begin(&s(&f.recovery), &s(NEW_PW)).unwrap();
    assert_eq!(code(st.recovery_confirm(&wrong())), "recovery_mismatch");
    assert_eq!(phase(st), "locked");
    st.recovery_confirm(&answers(&out)).unwrap();
    assert_eq!(phase(st), "unlocked");
    st.lock();
    assert_eq!(code(st.unlock(&s(PW))), "unlock_failed");
    st.unlock(&s(NEW_PW)).unwrap();
    st.lock();
    assert_eq!(
        code(st.recovery_begin(&s(&f.recovery), &s(PW))),
        "unlock_failed"
    );
}

#[test]
fn password_change_and_recovery_reissue() {
    let f = fixture();
    let st = &f.state;
    assert_eq!(
        code(st.change_password(&s(NEW_PW), &s(NEW_PW))),
        "unlock_failed"
    );
    st.change_password(&s(PW), &s(NEW_PW)).unwrap();
    let out = st.recovery_reissue(&s(NEW_PW)).unwrap();
    assert_ne!(out["recovery_key"], f.recovery.as_str());
    st.recovery_confirm(&answers(&out)).unwrap();
    // 锁定会取消未完成的更换
    let out = st.recovery_reissue(&s(NEW_PW)).unwrap();
    st.lock();
    assert_eq!(code(st.recovery_confirm(&answers(&out))), "no_flow");
}

fn run<T>(f: impl Future<Output = T>) -> T {
    tauri::async_runtime::block_on(f)
}

// AC-NET-01 AC-GRT-04 AC-GRT-05 AC-GRT-16
#[test]
fn service_requests_and_approval() {
    let f = fixture();
    let st = &f.state;
    set_port(st);
    assert_eq!(st.poll()["scope"], "closed");
    st.save_item(None, login("Cassiopeia")).unwrap();
    assert_eq!(
        code(st.add_client("甲", vec![], &s("fake-wrong-000"))),
        "unlock_failed"
    );
    let token = st.add_client("假客户端", vec![], &s(PW)).unwrap();
    assert_eq!(token.len(), 64);
    let client = st.clients().unwrap()[0]["id"].as_str().unwrap().to_owned();
    assert!(!st.clients().unwrap().to_string().contains(&token));

    assert_eq!(code(run(st.open_service(7))), "invalid_params");
    run(st.open_service(15)).unwrap();
    assert_eq!(st.service.scope(), ExposureScope::Loopback);
    let mut moved = st.settings();
    moved.port += 1;
    assert_eq!(code(st.set_settings(moved)), "settings");

    let cid = client_id(&client).unwrap();
    let ask = || {
        st.engine(|e| {
            let hits = e.search(cid, "Cassiopeia")?;
            let item = hits["results"][0]["item_ref"].as_str().unwrap().to_owned();
            let r = e.request(cid, &item, vec![AiField::Password], "假用途")?;
            Ok(r["request_id"].as_str().unwrap().to_owned())
        })
        .unwrap()
    };
    let id = ask();
    assert!(st.tick(false).new_request);
    assert!(!st.tick(false).new_request, "同一申请只提醒一次");

    // 界面锁定后仍能处理申请，但必须再输主密码
    st.lock();
    assert_eq!(phase(st), "serving");
    assert_eq!(st.poll()["requests"].as_array().unwrap().len(), 1);
    let fields = || vec![AiField::Password];
    assert_eq!(
        code(st.decide(&id, fields(), Decision::View, &s("fake-wrong-000"))),
        "unlock_failed"
    );
    let shown = st
        .decide(&id, fields(), Decision::View, &s(PW))
        .unwrap()
        .unwrap();
    assert!(shown.contains(SECRET));
    assert_eq!(st.request_state(&id).unwrap(), "view_only");
    assert_eq!(phase(st), "serving", "批准不会顺带解锁界面");

    let id = ask();
    let auth = st
        .decide(&id, fields(), Decision::Issue, &s(PW))
        .unwrap()
        .unwrap();
    assert_eq!(auth.replace('-', "").len(), 8);
    assert_eq!(st.request_state(&id).unwrap(), "code_issued");
    assert!(!st.poll().to_string().contains(&auth), "状态里没有授权码");

    // 一键关闭：申请全部失效；界面锁着，所以密钥也清除
    st.service.close();
    assert_eq!(phase(st), "locked");
    assert_eq!(st.poll()["requests"], json!([]));
    assert_eq!(code(run(st.open_service(15))), "locked");

    st.unlock(&s(PW)).unwrap();
    let log = st.audit("").unwrap();
    assert!(log["events"].as_array().unwrap().len() >= 4);
    assert_eq!(log["clients"][0]["name"], "假客户端");
    let text = log.to_string();
    for m in [SECRET, USER, PW, token.as_str(), auth.as_str(), "假用途"] {
        assert!(!text.contains(m));
    }
    st.rename_client(&client, "新名字").unwrap();
    st.resume_client(&client, &s(PW)).unwrap();
    st.revoke_client(&client).unwrap();
    assert_eq!(st.clients().unwrap(), json!([]));
}

// AC-BAK-01 AC-BAK-02
#[test]
fn backup_restores_on_an_empty_device_only() {
    let f = fixture();
    f.state.save_item(None, login("甲")).unwrap();
    let file = f.dir.path().join("a.svbak");
    f.state.export_backup(&file).unwrap();
    assert_eq!(code(f.state.export_backup(&file)), "exists");
    f.state.set_package(file.clone());
    assert_eq!(
        code(f.state.restore(Credential::Password, &s(PW))),
        "exists"
    );

    let dir = tempfile::tempdir().unwrap();
    let st = AppState::new(dir.path().to_owned());
    assert_eq!(code(st.restore(Credential::Password, &s(PW))), "no_flow");
    assert_eq!(st.set_package(file), "a.svbak");
    assert_eq!(
        code(st.restore(Credential::Password, &s(NEW_PW))),
        "unlock_failed"
    );
    assert_eq!(phase(&st), "empty");
    assert_eq!(st.restore(Credential::Password, &s(PW)).unwrap(), 1);
    assert_eq!(phase(&st), "locked");
    st.unlock(&s(PW)).unwrap();
    assert_eq!(st.list(false, "").unwrap().as_array().unwrap().len(), 1);
}

// AC-MIG-01 AC-MIG-02 AC-MIG-03 AC-MIG-04
#[test]
fn migration_moves_the_vault_and_retires_the_old_device() {
    let f = fixture();
    let old = &f.state;
    set_port(old);
    old.save_item(None, login("甲")).unwrap();
    run(old.open_service(15)).unwrap();
    let file = f.dir.path().join("a.svmig");
    assert_eq!(
        code(old.migration_begin(&s(NEW_PW), &file)),
        "unlock_failed"
    );
    assert_eq!(old.poll()["scope"], "closed", "迁移前先关闭服务");
    let mig = old.migration_begin(&s(PW), &file).unwrap();
    assert_eq!(old.poll()["migrating"], true);
    assert_eq!(code(old.save_item(None, login("乙"))), "read_only");
    assert!(run(old.open_service(15)).is_err(), "迁移中不能开放服务");

    let dir = tempfile::tempdir().unwrap();
    let new = AppState::new(dir.path().to_owned());
    new.set_package(file);
    assert_eq!(
        code(new.migration_import(&s("bad"), Credential::Password, &s(PW))),
        "code_format"
    );
    let done = new
        .migration_import(&s(&mig), Credential::Password, &s(PW))
        .unwrap();
    assert_eq!(done["items"], 1);
    assert_eq!(phase(&new), "locked");

    assert_eq!(code(old.migration_confirm(&s("0000-0000"))), "completion");
    old.migration_confirm(&s(done["completion_code"].as_str().unwrap()))
        .unwrap();
    assert_eq!(phase(old), "retired");
    assert_eq!(code(old.unlock(&s(PW))), "retired");
    old.wipe_retired().unwrap();
    assert_eq!(phase(old), "empty");
    assert!(!f.dir.path().join(VAULT_FILE).exists());
    new.unlock(&s(PW)).unwrap();
    assert_eq!(new.list(false, "").unwrap().as_array().unwrap().len(), 1);
}

#[test]
fn migration_can_be_cancelled_and_active_vaults_cannot_be_wiped() {
    let f = fixture();
    assert_eq!(code(f.state.wipe_retired()), "read_only");
    assert_eq!(phase(&f.state), "unlocked");
    f.state
        .migration_begin(&s(PW), &f.dir.path().join("a.svmig"))
        .unwrap();
    f.state.migration_cancel().unwrap();
    f.state.save_item(None, login("甲")).unwrap();
}

// AC-BAK-02
#[test]
fn a_broken_vault_is_kept_aside_not_deleted() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(VAULT_FILE), b"not a vault").unwrap();
    let st = AppState::new(dir.path().to_owned());
    assert_eq!(phase(&st), "broken");
    assert_eq!(code(st.setup_begin(&s(PW))), "exists");
    let name = st.set_aside().unwrap();
    assert_eq!(fs::read(dir.path().join(name)).unwrap(), b"not a vault");
    assert_eq!(phase(&st), "empty");
    assert_eq!(code(st.set_aside()), "exists");
}

#[test]
fn csv_import_reports_rows_and_deletes_only_on_request() {
    let f = fixture();
    let file = f.dir.path().join("a.csv");
    fs::write(
        &file,
        "name,url,username,password\n甲,https://a.test,u-fake,Fake-Pw-1\n坏行\n",
    )
    .unwrap();
    let r = f.state.import_csv(&file).unwrap();
    assert_eq!(r["imported"], 1);
    assert_eq!(r["rejected"][0][0], 2);
    assert!(!r.to_string().contains("Fake-Pw-1"));
    assert!(file.exists());
    f.state.delete_csv().unwrap();
    assert!(!file.exists());
    assert_eq!(code(f.state.delete_csv()), "no_flow");
}

#[test]
fn settings_are_checked_and_never_persist_the_scope() {
    let f = fixture();
    let st = &f.state;
    set_port(st);
    for bad in [
        Settings {
            auto_lock_minutes: 0,
            ..st.settings()
        },
        Settings {
            auto_lock_minutes: 61,
            ..st.settings()
        },
        Settings {
            clipboard_seconds: 5,
            ..st.settings()
        },
        Settings {
            port: 80,
            ..st.settings()
        },
    ] {
        assert_eq!(code(st.set_settings(bad)), "settings");
    }
    st.set_settings(Settings {
        auto_lock_minutes: 10,
        ..st.settings()
    })
    .unwrap();
    run(st.open_service(0)).unwrap();
    let dir = f.dir;
    drop(f.state);
    let st = AppState::new(dir.path().to_owned());
    assert_eq!(st.settings().auto_lock_minutes, 10);
    assert_eq!(st.poll()["scope"], "closed", "重启后关闭");
    fs::write(dir.path().join("settings.json"), b"{broken").unwrap();
    assert_eq!(Settings::load(dir.path()), Settings::default());
}

// AC-VLT-09。需要图形会话，会改动剪贴板，只在明确要求时运行。
#[test]
#[ignore = "会改动系统剪贴板，用 npm run test:desktop 运行"]
fn clipboard_is_cleared_only_when_unchanged() {
    let f = fixture();
    let st = &f.state;
    let read = || {
        arboard::Clipboard::new()
            .unwrap()
            .get_text()
            .unwrap_or_default()
    };
    st.copy(&s("假内容-甲")).unwrap();
    assert_eq!(read(), "假内容-甲");
    st.clear_clipboard();
    assert_eq!(read(), "");
    st.copy(&s("假内容-乙")).unwrap();
    arboard::Clipboard::new()
        .unwrap()
        .set_text("用户自己的内容")
        .unwrap();
    st.clear_clipboard();
    assert_eq!(read(), "用户自己的内容");
    arboard::Clipboard::new().unwrap().clear().unwrap();
}
