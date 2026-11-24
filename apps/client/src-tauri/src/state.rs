//! 应用状态与规则，不依赖 Tauri，可单独测试。
//!
//! 加锁顺序：`core` → Engine。持有 Engine 锁时不得调用 `service` 的方法。
use crate::{
    clipboard::{self, Copied},
    error::{Ui, UiError, fail},
    settings::Settings,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vault_core::{
    Auth, DeviceState, ExposureScope, ListFilter, LockState, MigrationCode, PendingRecovery,
    RecoveryKey, RestoreAuth, SecretString, Setup, SystemClock, Vault,
    import::{Adjustment, CsvFormat, ImportReport, RejectReason},
    import_migration,
    model::{AiField, CustomField, Item, ItemDraft, ItemId, ItemKind, ItemMeta, Secrets},
    restore_backup,
    search::ClientId,
};
use vault_service::{Access, Engine, LocalApproval, Public, ServiceHandle, SharedEngine};

const VAULT_FILE: &str = "vault.svault";
/// 两次心跳间隔超过这个值，视为系统休眠过。
const SLEEP_GAP: Duration = Duration::from_secs(20);

/// 从界面收到的机密。
pub struct Secret(pub SecretString);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(SecretString::new(s)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairIn {
    name: Secret,
    value: Secret,
}

/// 条目表单。机密字段为 `null` 表示保持原值，这样编辑时不必先把机密传给界面。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftIn {
    kind: ItemKind,
    title: String,
    domains: Vec<String>,
    auto_domains: bool,
    tags: Vec<String>,
    hint: String,
    ai_hidden: bool,
    username: Option<Secret>,
    password: Option<Secret>,
    note: Option<Secret>,
    totp: Option<Secret>,
    body: Option<Secret>,
    urls: Option<Vec<Secret>>,
    custom: Option<Vec<PairIn>>,
}

impl DraftIn {
    pub(crate) fn into_draft(self, old: Secrets) -> ItemDraft {
        let pick = |new: Option<Secret>, old: Option<SecretString>| match new {
            Some(s) => (!s.0.is_empty()).then_some(s.0),
            None => old,
        };
        ItemDraft {
            kind: self.kind,
            title: self.title,
            domains: self.domains,
            auto_domains: self.auto_domains,
            tags: self.tags,
            hint: self.hint,
            ai_hidden: self.ai_hidden,
            secrets: Secrets {
                username: pick(self.username, old.username),
                password: pick(self.password, old.password),
                note: pick(self.note, old.note),
                totp: pick(self.totp, old.totp),
                body: pick(self.body, old.body),
                urls: self
                    .urls
                    .map_or(old.urls, |v| v.into_iter().map(|s| s.0).collect()),
                custom: self.custom.map_or(old.custom, |v| {
                    v.into_iter()
                        .map(|p| CustomField {
                            name: p.name.0,
                            value: p.value.0,
                        })
                        .collect()
                }),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretField {
    Username,
    Password,
    Url,
    Note,
    Totp,
    Body,
    CustomName,
    CustomValue,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Credential {
    Password,
    Recovery,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Deny,
    Revoke,
    View,
    Issue,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenScope {
    Loopback,
    Public,
}

/// 尚未完成、只在内存里的流程。
#[derive(Default)]
struct Flow {
    setup: Option<Setup>,
    recovery: Option<PendingRecovery>,
    import: Option<ImportReport>,
    package: Option<PathBuf>,
}

struct Clocked {
    activity: Instant,
    activity_wall: SystemTime,
    last_tick: SystemTime,
    screen_locked: bool,
    last_inbox_sweep: Option<Instant>,
    seen: HashSet<String>,
}

#[derive(Default, Clone, Serialize)]
struct Nav {
    seq: u64,
    target: &'static str,
}

/// 一次心跳的结果，由壳层决定如何呈现。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tick {
    pub locked: bool,
    pub new_request: bool,
}

pub struct AppState {
    dir: PathBuf,
    clock: Arc<SystemClock>,
    pub service: ServiceHandle,
    core: Mutex<Option<SharedEngine>>,
    open_error: Mutex<Option<UiError>>,
    flow: Mutex<Flow>,
    settings: Mutex<Settings>,
    clocked: Mutex<Clocked>,
    nav: Mutex<Nav>,
    copied: Mutex<Option<Copied>>,
}

fn hold<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn clock_start() -> Clocked {
    Clocked {
        activity: Instant::now(),
        activity_wall: SystemTime::now(),
        last_tick: SystemTime::now(),
        screen_locked: false,
        last_inbox_sweep: None,
        seen: HashSet::new(),
    }
}

/// 回车、空格等抄写差异由核心归一化；这里只把两组答案固定成数组。
fn pair(answers: &[Secret]) -> Ui<[&str; 2]> {
    match answers {
        [a, b] => Ok([a.0.expose(), b.0.expose()]),
        _ => fail("recovery_mismatch", "请填写两组"),
    }
}

impl AppState {
    pub fn new(dir: PathBuf) -> Self {
        let settings = Settings::load(&dir);
        let s = Self {
            dir,
            clock: Arc::default(),
            service: ServiceHandle::new(),
            core: Mutex::default(),
            open_error: Mutex::default(),
            flow: Mutex::default(),
            settings: Mutex::new(settings),
            clocked: Mutex::new(clock_start()),
            nav: Mutex::default(),
            copied: Mutex::default(),
        };
        s.open_existing();
        s
    }

    fn path(&self) -> PathBuf {
        self.dir.join(VAULT_FILE)
    }

    /// 启动、恢复、导入后打开密库，处于锁定状态。
    fn open_existing(&self) {
        let path = self.path();
        let mut core = hold(&self.core);
        *core = None;
        *hold(&self.open_error) = None;
        if fs::symlink_metadata(&path).is_err() {
            return;
        }
        match Vault::open_with_clock(&path, self.clock.clone())
            .map_err(UiError::from)
            .and_then(|v| Ok(Engine::attach(v, self.clock.clone())?))
        {
            Ok(e) => *core = Some(Arc::new(Mutex::new(e))),
            Err(e) => *hold(&self.open_error) = Some(e),
        }
    }

    pub fn shared(&self) -> Ui<SharedEngine> {
        hold(&self.core)
            .clone()
            .ok_or_else(|| UiError::new("no_vault", "还没有密库"))
    }

    /// 对 Engine 做一次操作。
    fn engine<T>(&self, f: impl FnOnce(&mut Engine) -> Ui<T>) -> Ui<T> {
        let shared = self.shared()?;
        let mut e = hold(&shared);
        f(&mut e)
    }

    /// 只在完全解锁时执行。
    pub(crate) fn unlocked<T>(&self, f: impl FnOnce(&mut Engine) -> Ui<T>) -> Ui<T> {
        self.engine(|e| {
            if e.vault().lock_state() != LockState::Unlocked {
                return Err(UiError::locked());
            }
            f(e)
        })
    }

    // ---- 状态 ----

    pub fn poll(&self) -> Value {
        let scope = self.service.scope();
        let remaining = self.service.remaining_seconds();
        let mut out = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "scope": scope,
            "remaining": remaining,
            "tunnel": self.service.tunnel(),
            "direct": self.service.direct(),
            "relay": null,
            "pairing": null,
            "requests": [],
            "backoff_ms": 0,
            "migrating": false,
            "settings": &*hold(&self.settings),
            "nav": &*hold(&self.nav),
            "data_dir": self.dir.to_string_lossy(),
        });
        let phase = match self.shared() {
            Ok(shared) => {
                let mut e = hold(&shared);
                out["requests"] = e.pending();
                out["relay"] = e.relay_info();
                out["pairing"] = e.pairing_info();
                out["backoff_ms"] = json!(e.vault().backoff_remaining_ms());
                out["migrating"] = json!(e.vault().device_state() == DeviceState::Migrating);
                match (e.vault().device_state(), e.vault().lock_state()) {
                    (DeviceState::Retired, _) => "retired",
                    (_, LockState::Locked) => "locked",
                    (_, LockState::Serving) => "serving",
                    (_, LockState::Unlocked) => "unlocked",
                }
            }
            Err(_) => match &*hold(&self.open_error) {
                Some(e) => {
                    out["open_error"] = json!(e);
                    "broken"
                }
                None => "empty",
            },
        };
        out["phase"] = json!(phase);
        out
    }

    pub fn navigate(&self, target: &'static str) {
        let mut n = hold(&self.nav);
        n.seq += 1;
        n.target = target;
    }

    pub fn touch(&self) {
        let mut c = hold(&self.clocked);
        c.activity = Instant::now();
        c.activity_wall = SystemTime::now();
    }

    pub fn settings(&self) -> Settings {
        hold(&self.settings).clone()
    }

    pub fn set_settings(&self, new: Settings) -> Ui<()> {
        new.check()?;
        let old = self.settings();
        if new.port != old.port && self.service.scope() != ExposureScope::Closed {
            return fail("settings", "请先关闭服务再改端口");
        }
        new.save(&self.dir)?;
        *hold(&self.settings) = new;
        Ok(())
    }

    /// 每秒调用一次：闲置、锁屏、休眠锁定，清剪贴板，发现新申请。AC-VLT-06
    pub fn tick(&self, screen_locked: bool) -> Tick {
        let idle_limit =
            Duration::from_secs(u64::from(hold(&self.settings).auto_lock_minutes) * 60);
        let (reason, sweep_inbox) = {
            let mut c = hold(&self.clocked);
            let now = SystemTime::now();
            // 系统时间回拨也按休眠处理，只会多锁一次
            let slept = now
                .duration_since(c.last_tick)
                .map_or(true, |d| d > SLEEP_GAP);
            let idle = c.activity.elapsed() >= idle_limit
                || now
                    .duration_since(c.activity_wall)
                    .is_ok_and(|d| d >= idle_limit);
            let newly_locked = screen_locked && !c.screen_locked;
            c.last_tick = now;
            c.screen_locked = screen_locked;
            let sweep = c
                .last_inbox_sweep
                .is_none_or(|since| since.elapsed() >= Duration::from_secs(60));
            if sweep {
                c.last_inbox_sweep = Some(Instant::now());
            }
            (slept || idle || newly_locked, sweep)
        };
        if hold(&self.copied).as_ref().is_some_and(Copied::due) {
            self.clear_clipboard();
        }
        let mut out = Tick::default();
        let Ok(shared) = self.shared() else {
            return out;
        };
        let mut e = hold(&shared);
        if sweep_inbox && e.vault().device_state() == DeviceState::Active {
            let _ = e.vault().expire_drafts();
        }
        let was_unlocked = e.vault().lock_state() == LockState::Unlocked;
        if reason && was_unlocked {
            e.lock_ui();
            out.locked = true;
        }
        let ids: HashSet<String> = e
            .pending()
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["state"] == "pending")
            .filter_map(|r| r["request_id"].as_str().map(str::to_owned))
            .collect();
        drop(e);
        if out.locked {
            self.drop_flow();
        }
        let mut c = hold(&self.clocked);
        out.new_request = ids.iter().any(|id| !c.seen.contains(id));
        c.seen = ids;
        out
    }

    fn drop_flow(&self) {
        *hold(&self.flow) = Flow::default();
    }

    /// 退出前：关闭服务、锁定、清掉自己写入的剪贴板内容。
    pub fn shutdown(&self) {
        self.service.close();
        self.lock();
        self.clear_clipboard();
    }

    // ---- 首次设置、解锁、恢复 ----

    fn require_empty(&self) -> Ui<()> {
        if hold(&self.core).is_some() || fs::symlink_metadata(self.path()).is_ok() {
            return fail("exists", "这台设备上已有密库");
        }
        Ok(())
    }

    pub fn setup_begin(&self, password: &SecretString) -> Ui<Value> {
        self.require_empty()?;
        let setup = Setup::begin(password)?;
        let out =
            json!({"recovery_key": setup.recovery_key().expose(), "challenge": setup.challenge()});
        hold(&self.flow).setup = Some(setup);
        Ok(out)
    }

    /// 核对通过才写盘。答错可重试。AC-VLT-01
    pub fn setup_confirm(&self, answers: &[Secret]) -> Ui<()> {
        self.require_empty()?;
        let answers = pair(answers)?;
        let mut flow = hold(&self.flow);
        let setup = flow
            .setup
            .take()
            .ok_or_else(|| UiError::new("no_flow", "请重新开始设置"))?;
        if let Err(e) = setup.check_answers(answers) {
            flow.setup = Some(setup);
            return Err(e.into());
        }
        let vault = setup.confirm(&self.path(), answers, self.clock.clone())?;
        let engine = Engine::attach(vault, self.clock.clone())?;
        *hold(&self.core) = Some(Arc::new(Mutex::new(engine)));
        self.touch();
        Ok(())
    }

    pub fn cancel_flow(&self) {
        self.drop_flow();
    }

    pub fn unlock(&self, password: &SecretString) -> Ui<()> {
        self.engine(|e| Ok(e.unlock(Auth::Password(password))?))?;
        self.drop_flow();
        self.touch();
        Ok(())
    }

    pub fn lock(&self) {
        let _ = self.engine(|e| {
            e.lock_ui();
            Ok(())
        });
        self.drop_flow();
    }

    fn keep_recovery(&self, p: PendingRecovery) -> Value {
        let out = json!({"recovery_key": p.recovery_key().expose(), "challenge": p.challenge()});
        hold(&self.flow).recovery = Some(p);
        out
    }

    pub fn recovery_begin(&self, key: &SecretString, new: &SecretString) -> Ui<Value> {
        let key = RecoveryKey::parse(key.expose())?;
        vault_core::check_master_password(new)?;
        let p = self.engine(|e| {
            let v = e.vault_mut();
            let ticket = v.unlock_with_recovery(&key)?;
            Ok(v.prepare_password_reset(&ticket, new)?)
        })?;
        Ok(self.keep_recovery(p))
    }

    pub fn recovery_reissue(&self, password: &SecretString) -> Ui<Value> {
        let p = self.unlocked(|e| Ok(e.vault_mut().prepare_recovery_reissue(password)?))?;
        Ok(self.keep_recovery(p))
    }

    pub fn recovery_confirm(&self, answers: &[Secret]) -> Ui<()> {
        let answers = pair(answers)?;
        let mut flow = hold(&self.flow);
        let p = flow
            .recovery
            .as_ref()
            .ok_or_else(|| UiError::new("no_flow", "请重新开始"))?;
        self.engine(|e| {
            e.vault_mut().commit_recovery(p, answers)?;
            Ok(e.finish_unlock()?)
        })?;
        flow.recovery = None;
        drop(flow);
        self.touch();
        Ok(())
    }

    pub fn change_password(&self, old: &SecretString, new: &SecretString) -> Ui<()> {
        self.unlocked(|e| Ok(e.vault_mut().change_password(old, new)?))
    }

    // ---- 条目 ----

    pub fn list(&self, trash: bool, query: &str) -> Ui<Value> {
        self.unlocked(|e| {
            let v = e.vault_mut();
            if !trash && !query.trim().is_empty() {
                return Ok(json!(
                    v.search(query, 200)?
                        .iter()
                        .map(|h| meta_json(&h.meta))
                        .collect::<Vec<_>>()
                ));
            }
            let filter = if trash {
                ListFilter::Trash
            } else {
                ListFilter::Active
            };
            Ok(json!(
                v.list(filter)?.iter().map(meta_json).collect::<Vec<_>>()
            ))
        })
    }

    /// 详情只含“有哪些内容”，不含内容本身。
    pub fn item(&self, id: &str) -> Ui<Value> {
        self.unlocked(|e| {
            let item = e.vault().get(item_id(id)?)?;
            let s = &item.secrets;
            let mut out = meta_json(&item.meta);
            out["has"] = json!({
                "username": s.username.is_some(),
                "password": s.password.is_some(),
                "note": s.note.is_some(),
                "totp": s.totp.is_some(),
                "body": s.body.is_some(),
                "urls": s.urls.len(),
                "custom": s.custom.len(),
            });
            Ok(out)
        })
    }

    fn secret(&self, id: &str, field: SecretField, index: usize) -> Ui<SecretString> {
        self.unlocked(|e| {
            let Item { secrets: s, .. } = e.vault().get(item_id(id)?)?;
            match field {
                SecretField::Username => s.username,
                SecretField::Password => s.password,
                SecretField::Note => s.note,
                SecretField::Totp => s.totp,
                SecretField::Body => s.body,
                SecretField::Url => s.urls.into_iter().nth(index),
                SecretField::CustomName => s.custom.into_iter().nth(index).map(|c| c.name),
                SecretField::CustomValue => s.custom.into_iter().nth(index).map(|c| c.value),
            }
            .ok_or_else(|| vault_core::Error::UnknownField.into())
        })
    }

    pub fn reveal(&self, id: &str, field: SecretField, index: usize) -> Ui<String> {
        Ok(self.secret(id, field, index)?.expose().to_owned())
    }

    /// 明文由 Rust 直接写剪贴板，不经过界面。
    pub fn copy_field(&self, id: &str, field: SecretField, index: usize) -> Ui<u32> {
        let s = self.secret(id, field, index)?;
        self.copy(&s)
    }

    pub fn copy(&self, text: &SecretString) -> Ui<u32> {
        let secs = hold(&self.settings).clipboard_seconds;
        let c = clipboard::copy(text, Duration::from_secs(secs.into()))?;
        *hold(&self.copied) = Some(c);
        Ok(secs)
    }

    fn clear_clipboard(&self) {
        if let Some(c) = hold(&self.copied).take() {
            c.clear();
        }
    }

    pub fn save_item(&self, id: Option<&str>, draft: DraftIn) -> Ui<String> {
        self.unlocked(|e| {
            let v = e.vault_mut();
            match id {
                None => Ok(v.add(&draft.into_draft(Secrets::default()))?.to_hex()),
                Some(id) => {
                    let key = item_id(id)?;
                    let old = v.get(key)?;
                    if old.meta.kind != draft.kind {
                        return fail("invalid_item", "条目类型不能修改");
                    }
                    v.update(key, &draft.into_draft(old.secrets))?;
                    Ok(id.to_owned())
                }
            }
        })
    }

    pub fn item_action(&self, id: &str, action: &str) -> Ui<()> {
        self.unlocked(|e| {
            let id = item_id(id)?;
            let v = e.vault_mut();
            match action {
                "trash" => v.trash(id)?,
                "restore" => v.restore(id)?,
                "purge" => v.purge(id)?,
                "hide_from_ai" => v.set_ai_hidden(id, true)?,
                "show_to_ai" => v.set_ai_hidden(id, false)?,
                _ => return Err(UiError::internal()),
            }
            Ok(())
        })
    }

    pub fn empty_trash(&self) -> Ui<usize> {
        self.unlocked(|e| Ok(e.vault_mut().empty_trash()?))
    }

    pub fn totp(&self, id: &str) -> Ui<Value> {
        self.unlocked(|e| {
            let c = e.vault().totp_code(item_id(id)?)?;
            Ok(json!({"code": c.code.expose(), "remaining": c.remaining_secs}))
        })
    }

    // ---- 服务、客户端、申请 ----

    /// 已开放时视为切换：先关闭，使所有申请、授权码失效，再按新范围打开。
    pub async fn open_service(&self, scope: OpenScope, minutes: u64, direct: bool) -> Ui<()> {
        if ![0, 15, 60, 480].contains(&minutes) {
            return fail("invalid_params", "自动关闭时间无效");
        }
        let shared = self.shared()?;
        if hold(&shared).vault().lock_state() != LockState::Unlocked {
            return Err(UiError::locked());
        }
        let port = self.settings().port;
        let ttl = (minutes != 0).then(|| Duration::from_secs(minutes * 60));
        let public = (scope == OpenScope::Public).then_some(Public { direct });
        self.service.close();
        self.service.open(shared, port, ttl, public).await?;
        Ok(())
    }

    // ---- 公网跳板与桥接配对 ----

    /// 登记或接管跳板。网络往返期间不持有密库锁。
    pub async fn relay_claim(
        &self,
        url: &str,
        ca: Option<&str>,
        code: &SecretString,
        password: &SecretString,
    ) -> Ui<()> {
        if self.service.scope() == ExposureScope::Public {
            return fail("settings", "请先关闭公网再配对跳板");
        }
        let claim = self
            .unlocked(|e| Ok(e.relay_begin(url, ca, code.expose(), Auth::Password(password))?))?;
        let claim = vault_service::claim_relay(claim).await?;
        self.engine(|e| Ok(e.relay_commit(claim)?)).map_err(|_| {
            UiError::new(
                "relay_save",
                "跳板已接受，但没有保存成功。请重新生成配对码再试一次",
            )
        })
    }

    pub fn relay_forget(&self) -> Ui<()> {
        if self.service.scope() == ExposureScope::Public {
            return fail("settings", "请先关闭公网");
        }
        self.unlocked(|e| Ok(e.relay_forget()?))
    }

    pub fn pairing_begin(
        &self,
        name: &str,
        tags: Vec<String>,
        password: &SecretString,
    ) -> Ui<String> {
        if self.service.scope() != ExposureScope::Public {
            return fail("settings", "请先开放公网，桥接要连到这台设备才能配对");
        }
        self.unlocked(|e| {
            let text = e.pairing_begin(name.trim(), tags, Auth::Password(password))?;
            Ok(text.expose().to_owned())
        })
    }

    pub fn pairing_accept(&self) -> Ui<()> {
        self.unlocked(|e| Ok(e.pairing_accept()?))
    }

    pub fn pairing_cancel(&self) -> Ui<()> {
        self.engine(|e| {
            e.pairing_cancel();
            Ok(())
        })
    }

    pub fn clients(&self) -> Ui<Value> {
        self.unlocked(|e| Ok(e.clients()))
    }

    /// `direct` 表示这枚令牌也可从公网直连 HTTPS 使用。
    pub fn add_client(
        &self,
        name: &str,
        tags: Vec<String>,
        direct: bool,
        password: &SecretString,
    ) -> Ui<String> {
        let access = if direct {
            Access::Direct
        } else {
            Access::Local
        };
        self.unlocked(|e| {
            e.verify_user(Auth::Password(password))?;
            let (_, token) = e.add_client_for(name.trim(), tags, access)?;
            Ok(token.expose().to_owned())
        })
    }

    pub fn mcp_config(&self, client: &str, transport: &str) -> Ui<Value> {
        let relay = self.unlocked(|e| Ok(e.relay_info()))?;
        crate::mcp_config::build(
            client,
            transport,
            self.settings().port,
            relay["url"].as_str(),
        )
    }

    pub fn rename_client(&self, id: &str, name: &str) -> Ui<()> {
        self.unlocked(|e| Ok(e.rename_client(client_id(id)?, name.trim())?))
    }

    pub fn revoke_client(&self, id: &str) -> Ui<()> {
        self.unlocked(|e| Ok(e.revoke_client(client_id(id)?)?))
    }

    pub fn resume_client(&self, id: &str, password: &SecretString) -> Ui<()> {
        self.unlocked(|e| Ok(e.resume_search(client_id(id)?, Auth::Password(password))?))
    }

    /// 界面锁定、服务运行时也能批准，但每次都要重新验证主密码。AC-GRT-04
    pub fn decide(
        &self,
        id: &str,
        fields: Vec<AiField>,
        action: Decision,
        password: &SecretString,
    ) -> Ui<Option<String>> {
        self.engine(|e| match action {
            Decision::Deny => Ok(e.deny(id).map(|()| None)?),
            Decision::Revoke => Ok(e.revoke(id).map(|()| None)?),
            Decision::View | Decision::Issue => {
                let for_ai = action == Decision::Issue;
                match e.approve(id, fields, Auth::Password(password), for_ai)? {
                    LocalApproval::Code(c) => Ok(Some(c.expose().to_owned())),
                    LocalApproval::View(v) => std::str::from_utf8(&v)
                        .map(|s| Some(s.to_owned()))
                        .map_err(|_| UiError::internal()),
                }
            }
        })
    }

    pub fn request_state(&self, id: &str) -> Ui<Value> {
        self.engine(|e| Ok(json!(e.state_of(id))))
    }

    pub fn audit(&self, query: &str) -> Ui<Value> {
        self.unlocked(|e| {
            let events = e.audit_rows(query)?;
            let v = e.vault();
            let mut titles = serde_json::Map::new();
            for m in v
                .list(ListFilter::Active)?
                .into_iter()
                .chain(v.list(ListFilter::Trash)?)
            {
                titles.insert(m.id.to_hex(), json!(m.title));
            }
            Ok(json!({"events": events, "titles": titles, "clients": e.clients()}))
        })
    }

    // ---- 导入、备份、迁移 ----

    pub fn import_csv(&self, path: &Path) -> Ui<Value> {
        let report = self.unlocked(|e| Ok(e.vault_mut().import_csv(path, None)?))?;
        let out = report_json(&report);
        hold(&self.flow).import = Some(report);
        Ok(out)
    }

    /// 删除刚导入的明文 CSV。核心会先核对内容没有变化。
    pub fn delete_csv(&self) -> Ui<()> {
        let mut flow = hold(&self.flow);
        let report = flow
            .import
            .as_ref()
            .ok_or_else(|| UiError::new("no_flow", "没有可删除的文件"))?;
        report.delete_source()?;
        flow.import = None;
        Ok(())
    }

    pub fn export_backup(&self, dest: &Path) -> Ui<()> {
        self.unlocked(|e| Ok(e.vault().export_backup(dest)?))
    }

    pub fn set_package(&self, path: PathBuf) -> String {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        hold(&self.flow).package = Some(path);
        name
    }

    fn package(&self) -> Ui<PathBuf> {
        hold(&self.flow)
            .package
            .clone()
            .ok_or_else(|| UiError::new("no_flow", "请先选择文件"))
    }

    /// 用主密码或恢复密钥打开备份、迁移包。
    fn with_auth<T>(
        kind: Credential,
        secret: &SecretString,
        f: impl FnOnce(RestoreAuth<'_>) -> vault_core::Result<T>,
    ) -> Ui<T> {
        Ok(match kind {
            Credential::Password => f(RestoreAuth::Password(secret))?,
            Credential::Recovery => {
                let key = RecoveryKey::parse(secret.expose())?;
                f(RestoreAuth::Recovery(&key))?
            }
        })
    }

    pub fn restore(&self, kind: Credential, secret: &SecretString) -> Ui<usize> {
        self.require_empty()?;
        let from = self.package()?;
        let dest = self.path();
        let r = Self::with_auth(kind, secret, |a| restore_backup(&from, &dest, a))?;
        self.drop_flow();
        self.open_existing();
        Ok(r.items)
    }

    pub fn migration_import(
        &self,
        code: &SecretString,
        kind: Credential,
        secret: &SecretString,
    ) -> Ui<Value> {
        self.require_empty()?;
        let from = self.package()?;
        let code = MigrationCode::parse(code.expose())?;
        let dest = self.path();
        let r = Self::with_auth(kind, secret, |a| {
            import_migration(&from, &code, a, &dest, self.clock.clone())
        })?;
        let out = json!({"items": r.items, "completion_code": r.completion_code.expose()});
        // 先放开文件独占，再由统一入口打开
        drop(r);
        self.drop_flow();
        self.open_existing();
        Ok(out)
    }

    /// 旧设备：先关闭服务并撤销全部申请。AC-MIG-02
    pub fn migration_begin(&self, password: &SecretString, package: &Path) -> Ui<String> {
        self.service.close();
        self.unlocked(|e| {
            Ok(e.vault_mut()
                .begin_migration(Auth::Password(password), package)?
                .expose()
                .to_owned())
        })
    }

    pub fn migration_cancel(&self) -> Ui<()> {
        self.unlocked(|e| Ok(e.vault_mut().cancel_migration()?))
    }

    pub fn migration_confirm(&self, completion: &SecretString) -> Ui<()> {
        self.unlocked(|e| {
            e.vault_mut().confirm_migration(completion.expose())?;
            e.lock_ui();
            Ok(())
        })?;
        self.drop_flow();
        Ok(())
    }

    /// 清除已停用的密库文件。AC-MIG-04
    pub fn wipe_retired(&self) -> Ui<()> {
        self.service.close();
        let mut core = hold(&self.core);
        let shared = core
            .take()
            .ok_or_else(|| UiError::new("no_vault", "没有密库"))?;
        if hold(&shared).vault().device_state() != DeviceState::Retired {
            *core = Some(shared);
            return fail("read_only", "只有已停用的密库可以清除");
        }
        match Arc::try_unwrap(shared) {
            Ok(m) => m
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .into_vault()
                .wipe_retired()?,
            Err(still_used) => {
                *core = Some(still_used);
                return Err(UiError::internal());
            }
        }
        Ok(())
    }

    /// 打不开的密库：改名保留，不删除，之后可从备份恢复。
    pub fn set_aside(&self) -> Ui<String> {
        if hold(&self.open_error).is_none() {
            return fail("exists", "密库可以正常打开，不需要移开");
        }
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let name = format!("vault-无法打开-{secs}.svault");
        let dest = self.dir.join(&name);
        if fs::symlink_metadata(&dest).is_ok() {
            return Err(vault_core::Error::AlreadyExists.into());
        }
        fs::rename(self.path(), &dest)
            .map_err(|_| UiError::new("io", "改名失败，请检查文件权限"))?;
        self.open_existing();
        Ok(name)
    }
}

pub(crate) fn item_id(s: &str) -> Ui<ItemId> {
    ItemId::parse(s).ok_or_else(|| vault_core::Error::UnknownItem.into())
}

pub(crate) fn client_id(s: &str) -> Ui<ClientId> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .map(ClientId)
        .ok_or_else(|| UiError::new("unauthorized", "这个客户端已不存在"))
}

fn meta_json(m: &ItemMeta) -> Value {
    json!({
        "id": m.id.to_hex(), "kind": m.kind, "title": m.title, "domains": m.domains,
        "tags": m.tags, "hint": m.hint, "masked_account": m.masked_account,
        "ai_hidden": m.ai_hidden, "created_ms": m.created_ms, "updated_ms": m.updated_ms,
        "deleted_ms": m.deleted_ms,
    })
}

fn report_json(r: &ImportReport) -> Value {
    let format = match r.format {
        CsvFormat::Chrome => "Chrome",
        CsvFormat::Bitwarden => "Bitwarden",
        CsvFormat::KeePass => "KeePass",
        CsvFormat::KeePassXc => "KeePassXC",
    };
    let adjusted: Vec<Value> = r
        .adjusted
        .iter()
        .map(|(n, a)| {
            json!([
                n,
                match a {
                    Adjustment::TitleGenerated => "标题为空，已用域名或序号代替",
                    Adjustment::TitleMoved => "标题含账号或密码，已挪到机密字段",
                    Adjustment::TitleShortened => "标题过长，完整内容已存为自定义字段",
                    Adjustment::DomainOmitted => "域名与账号重合，没有写入可搜索信息",
                    Adjustment::TagMoved => "标签含账号或密码，已挪到机密字段",
                    Adjustment::TotpMoved => "动态口令无法识别，原文已存为自定义字段",
                    Adjustment::ExtraKept => "多余的列已存为自定义字段",
                }
            ])
        })
        .collect();
    let rejected: Vec<Value> = r
        .rejected
        .iter()
        .map(|(n, e)| {
            json!([
                n,
                match e {
                    RejectReason::ColumnCount => "列数与表头不符",
                    RejectReason::TooLarge => "内容过大",
                    RejectReason::Invalid => "内容不符合要求",
                }
            ])
        })
        .collect();
    json!({
        "format": format, "imported": r.imported, "blank": r.blank,
        "adjusted": adjusted, "rejected": rejected, "prompt": r.delete_prompt(),
        "file": r.source().file_name().map(|n| n.to_string_lossy().into_owned()),
    })
}

#[cfg(test)]
impl AppState {
    /// 测试用：把最近一次操作时间和心跳往前拨。
    fn rewind_activity(&self, by: Duration) {
        let mut c = hold(&self.clocked);
        c.activity_wall -= by;
    }
    fn rewind_tick(&self, by: Duration) {
        hold(&self.clocked).last_tick -= by;
    }
}

#[cfg(test)]
mod tests;
