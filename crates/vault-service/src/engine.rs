use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;
use vault_core::{
    Auth, Clock, GrantEvent as Event, GrantState as State, Key, LockMode, LockState, SecretString,
    Vault,
    delivery::Envelope,
    model::{AiField, ItemId, RevealedValue},
    policy,
    search::{AiSearchError, ClientId},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct ServiceError(pub u16, pub &'static str);
pub(crate) type Result<T> = std::result::Result<T, ServiceError>;
pub(crate) const BAD: ServiceError = ServiceError(400, "invalid_params");
pub(crate) const OFF: ServiceError = ServiceError(503, "unavailable");
const UNKNOWN: ServiceError = ServiceError(404, "unknown_request");
const ITEM: ServiceError = ServiceError(404, "unknown_item");
const LIMIT: ServiceError = ServiceError(429, "rate_limited");
impl From<vault_core::Error> for ServiceError {
    fn from(_: vault_core::Error) -> Self {
        OFF
    }
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| OFF)?;
    Ok(b)
}
fn valid_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty()
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c as u32, 0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
        })
        && s.chars().count() <= max
}
#[derive(Clone, Deserialize, Serialize)]
struct Client {
    name: String,
    tags: Vec<String>,
    digest: [u8; 32],
    attempts: Vec<i64>,
    denied: HashMap<String, i64>,
    streak: u8,
    pause_until: i64,
}
struct Request {
    id: String,
    client: ClientId,
    item: ItemId,
    rev: u64,
    fields: Vec<AiField>,
    reason: String,
    state: State,
    wall: i64,
    mono: u64,
    failures: u32,
    envelope: Option<Envelope>,
}
impl Request {
    fn transition(&mut self, event: Event) -> Result<()> {
        self.state = self
            .state
            .apply(event)
            .ok_or(ServiceError(409, "not_ready"))?;
        if self.state.is_terminal() {
            self.envelope = None;
            self.reason.clear();
        }
        Ok(())
    }
    fn age(&self, wall: i64, mono: u64) -> u64 {
        if wall < self.wall {
            return u64::MAX;
        }
        mono.saturating_sub(self.mono)
            .max(wall.saturating_sub(self.wall) as u64)
    }
    fn aad(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&(
            "suishen-vault/delivery/v1",
            self.client.0,
            &self.id,
            self.item.to_hex(),
            self.rev,
            &self.fields,
            self.wall,
            self.mono,
            policy::AUTH_CODE_TTL.as_secs(),
        ))
        .map_err(|_| OFF)
    }
}
pub enum LocalApproval {
    Code(SecretString),
    View(Zeroizing<Vec<u8>>),
}
/// 密库与授权状态的唯一持有者。App 存续期间只有一个，服务开关与界面锁定互不影响。
pub struct Engine {
    vault: Vault,
    clock: Arc<dyn Clock>,
    key: Key,
    clients: HashMap<ClientId, Client>,
    requests: HashMap<String, Request>,
    redemptions: HashMap<ClientId, Vec<i64>>,
    serving: bool,
}
impl Engine {
    /// 接管刚打开的密库，可处于锁定状态。
    pub fn attach(vault: Vault, clock: Arc<dyn Clock>) -> Result<Self> {
        let mut engine = Self {
            vault,
            clock,
            key: Key::random()?,
            clients: HashMap::new(),
            requests: HashMap::new(),
            redemptions: HashMap::new(),
            serving: false,
        };
        if engine.vault.lock_state() != LockState::Locked {
            engine.load_clients()?;
        }
        Ok(engine)
    }
    /// 接管已解锁的密库并立即锁定界面，只留元数据密钥。
    pub fn new(vault: Vault, clock: Arc<dyn Clock>) -> Result<Self> {
        let mut engine = Self::attach(vault, clock)?;
        engine.vault.ai()?;
        engine.vault.lock(LockMode::KeepServing);
        Ok(engine)
    }
    fn load_clients(&mut self) -> Result<()> {
        let mut clients = HashMap::new();
        for (id, bytes) in self.vault.service_clients()? {
            clients.insert(
                ClientId(id),
                serde_json::from_slice(&bytes).map_err(|_| OFF)?,
            );
        }
        self.clients = clients;
        Ok(())
    }

    // ---- 只供主设备界面调用 ----

    pub fn vault(&self) -> &Vault {
        &self.vault
    }
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }
    pub fn into_vault(self) -> Vault {
        self.vault
    }
    pub fn unlock(&mut self, auth: Auth<'_>) -> vault_core::Result<()> {
        self.vault.unlock(auth)?;
        self.finish_unlock()
    }
    /// 经恢复密钥进入密库后，补上解锁后的准备。
    pub fn finish_unlock(&mut self) -> vault_core::Result<()> {
        self.load_clients().map_err(|_| {
            self.lock_ui();
            vault_core::Error::Tampered
        })
    }
    /// 锁定界面。服务在运行时保留元数据密钥，已签发的授权码不受影响。
    pub fn lock_ui(&mut self) {
        self.vault.lock(if self.serving {
            LockMode::KeepServing
        } else {
            LockMode::Full
        });
        if self.vault.lock_state() == LockState::Locked {
            self.clients.clear();
        }
    }
    pub(crate) fn begin_service(&mut self) -> Result<()> {
        self.vault.ai()?;
        self.serving = true;
        Ok(())
    }
    /// 使所有申请、授权码、不透明 ID 失效。界面已锁定时清除全部密钥。
    pub(crate) fn end_service(&mut self) {
        for r in self
            .requests
            .values_mut()
            .filter(|r| !r.state.is_terminal())
        {
            let _ = r.transition(Event::Revoke);
        }
        self.requests.clear();
        self.redemptions.clear();
        self.vault.revoke_item_refs();
        self.serving = false;
        if self.vault.lock_state() != LockState::Unlocked {
            self.lock_ui();
        }
    }
    /// 完成需要完全解锁的操作后，恢复到原来的锁定状态。
    fn with_unlocked<T>(
        &mut self,
        auth: Auth<'_>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        if self.vault.lock_state() == LockState::Unlocked {
            self.verify_user(auth)?;
            return f(self);
        }
        self.vault
            .unlock(auth)
            .map_err(|_| ServiceError(403, "unlock_failed"))?;
        let r = f(self);
        self.lock_ui();
        r
    }
    fn save(&self, id: ClientId, c: &Client) -> Result<()> {
        self.vault
            .store_client(id.0, &serde_json::to_vec(c).map_err(|_| OFF)?)?;
        Ok(())
    }
    pub fn add_client(
        &mut self,
        name: &str,
        tags: Vec<String>,
    ) -> Result<(ClientId, SecretString)> {
        if !valid_text(name, 80)
            || tags.len() > 32
            || tags.iter().any(|s| !valid_text(s, 64))
            || self.clients.len() >= 64
        {
            return Err(BAD);
        }
        let id = ClientId(random()?);
        let token = SecretString::new(hex::encode(*Zeroizing::new(random::<32>()?)));
        let digest = Sha256::digest(token.expose().as_bytes()).into();
        let c = Client {
            name: name.to_owned(),
            tags,
            digest,
            attempts: vec![],
            denied: HashMap::new(),
            streak: 0,
            pause_until: 0,
        };
        self.save(id, &c)?;
        self.clients.insert(id, c);
        Ok((id, token))
    }
    pub fn clients(&self) -> Value {
        json!(
            self.clients
                .iter()
                .map(
                    |(id, c)| json!({"id":hex::encode(id.0),"name":c.name,"tags":c.tags,
                    "search_paused":self.vault.ai_search_paused(*id).unwrap_or(false),
                    "request_paused":self.clock.wall_ms() < c.pause_until})
                )
                .collect::<Vec<_>>()
        )
    }
    pub fn rename_client(&mut self, id: ClientId, name: &str) -> Result<()> {
        if !valid_text(name, 80) {
            return Err(BAD);
        }
        let mut c = self.client(id)?.clone();
        c.name = name.to_owned();
        self.save(id, &c)?;
        self.clients.insert(id, c);
        Ok(())
    }
    pub fn revoke_client(&mut self, id: ClientId) -> Result<()> {
        self.vault.remove_client(id.0)?;
        self.clients.remove(&id);
        self.redemptions.remove(&id);
        for r in self
            .requests
            .values_mut()
            .filter(|r| r.client == id && !r.state.is_terminal())
        {
            r.transition(Event::Revoke)?;
        }
        Ok(())
    }
    pub(crate) fn authenticate(&self, token: &str) -> Result<ClientId> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.clients
            .iter()
            .find(|(_, c)| bool::from(digest.ct_eq(&c.digest)))
            .map(|(id, _)| *id)
            .ok_or(ServiceError(401, "unauthorized"))
    }
    fn client(&self, id: ClientId) -> Result<&Client> {
        self.clients
            .get(&id)
            .ok_or(ServiceError(401, "unauthorized"))
    }
    fn audit(&self, client: ClientId, action: &str, subject: Value, outcome: &str) -> Result<()> {
        self.vault.append_service_audit(&serde_json::to_vec(&json!({"time_ms":self.clock.wall_ms(),"client":hex::encode(client.0),"action":action,"subject":subject,"result":outcome})).map_err(|_|OFF)?)?;
        Ok(())
    }
    pub fn search(&mut self, client: ClientId, query: &str) -> Result<Value> {
        let tags = self.client(client)?.tags.clone();
        let result = self
            .vault
            .ai()?
            .search_with_tags(client, query, &tags)
            .map_err(|e| match e {
                AiSearchError::QueryTooShort => ServiceError(400, "query_too_short"),
                AiSearchError::QueryTooLong => BAD,
                AiSearchError::RateLimited { .. } => LIMIT,
                AiSearchError::Paused => ServiceError(429, "search_paused"),
                _ => OFF,
            });
        // 限频后的拒绝不再写入数据库，避免无界日志写入。
        if !matches!(result, Err(ServiceError(429, "rate_limited"))) {
            let mut matches = Vec::new();
            if let Ok(hits) = &result {
                let mut gateway = self.vault.ai()?;
                for hit in hits {
                    matches.push(gateway.resolve(client, hit.item_ref.as_str())?.to_hex());
                }
            }
            self.audit(
                client,
                "search",
                json!({"query_fingerprint":self.vault.query_fingerprint(query)?,"matches":matches}),
                result.as_ref().map_or_else(|e| e.1, |_| "ok"),
            )?;
        }
        Ok(json!({"results":result?}))
    }
    pub(crate) fn sweep(&mut self) {
        let wall = self.clock.wall_ms();
        let mono = self.clock.mono_ms();
        let mut changed = Vec::new();
        self.requests.retain(|_, r| {
            let age = r.age(wall, mono);
            if r.state.is_terminal() {
                return age < 3_600_000;
            }
            let event = if self
                .clients
                .get(&r.client)
                .and_then(|c| self.vault.ai_item(r.item, &c.tags).ok())
                .is_none_or(|(rev, _)| rev != r.rev)
            {
                Some(Event::Revoke)
            } else if r.state == State::Pending && age >= policy::REQUEST_TTL.as_millis() as u64 {
                Some(Event::RequestTimeout)
            } else if r.state == State::CodeIssued
                && age >= policy::AUTH_CODE_TTL.as_millis() as u64
            {
                Some(Event::CodeTimeout)
            } else {
                None
            };
            if let Some(e) = event {
                let _ = r.transition(e);
                changed.push((r.client, r.id.clone(), r.state));
            }
            true
        });
        for (c, id, state) in changed {
            let _ = self.audit(c, "state", json!({"request_id":id,"state":state}), "ok");
        }
    }
    pub fn request(
        &mut self,
        client: ClientId,
        item_ref: &str,
        fields: Vec<AiField>,
        reason: &str,
    ) -> Result<Value> {
        self.sweep();
        let now = self.clock.wall_ms();
        let mut c = self.client(client)?.clone();
        charge(&mut c.attempts, now, 3)?;
        self.save(client, &c)?;
        self.clients.insert(client, c.clone());
        let item = self
            .vault
            .ai()?
            .resolve(client, item_ref)
            .map_err(|_| ITEM)?;
        let result = (|| {
            if !valid_text(reason, 200) {
                return Err(ServiceError(400, "invalid_reason"));
            }
            let (rev, meta) = self.vault.ai_item(item, &c.tags).map_err(|_| ITEM)?;
            check_fields(&fields, AiField::requestable(meta.kind))?;
            if now < c.pause_until
                || c.denied
                    .get(&item.to_hex())
                    .is_some_and(|until| now < *until)
            {
                return Err(ServiceError(429, "cooldown"));
            }
            let pending = self.requests.values().filter(|r| r.state == State::Pending);
            if pending.clone().count() >= 10
                || pending.filter(|r| r.client == client).count() >= policy::MAX_PENDING_PER_CLIENT
            {
                return Err(ServiceError(429, "too_many_pending"));
            }
            let id = format!("req_{}", hex::encode(random::<16>()?));
            self.audit(
                client,
                "request",
                json!({"item":item.to_hex(),"fields":fields,"request_id":id}),
                "pending",
            )?;
            self.requests.insert(
                id.clone(),
                Request {
                    id: id.clone(),
                    client,
                    item,
                    rev,
                    fields,
                    reason: reason.into(),
                    state: State::Pending,
                    wall: now,
                    mono: self.clock.mono_ms(),
                    failures: 0,
                    envelope: None,
                },
            );
            Ok(
                json!({"request_id":id,"state":"pending","expires_in_seconds":600,"next_step":"请用户在 App 上核对并批准，等待用户提供授权码。"}),
            )
        })();
        if let Err(e) = result {
            self.audit(client, "request", json!({"item":item.to_hex()}), e.1)?;
        }
        result
    }
    fn owned(&self, client: ClientId, id: &str) -> Result<&Request> {
        self.client(client)?;
        self.requests
            .get(id)
            .filter(|r| r.client == client)
            .ok_or(UNKNOWN)
    }
    pub fn status(&mut self, client: ClientId, id: &str) -> Result<Value> {
        self.sweep();
        let r = self.owned(client, id)?;
        let mut out = json!({"request_id":id,"state":r.state});
        if !r.state.is_terminal() {
            let ttl: u64 = if r.state == State::CodeIssued {
                out["approved_fields"] = json!(r.fields);
                120000
            } else {
                600000
            };
            out["expires_in_seconds"] = json!(
                ttl.saturating_sub(r.age(self.clock.wall_ms(), self.clock.mono_ms()))
                    .div_ceil(1000)
            );
        }
        Ok(out)
    }
    pub fn pending(&mut self) -> Value {
        self.sweep();
        json!(self.requests.values().filter(|r| !r.state.is_terminal()).filter_map(|r|{
            let c=self.clients.get(&r.client)?;let (_,m)=self.vault.ai_item(r.item,&c.tags).ok()?;
            let ttl: u64 = if r.state == State::CodeIssued { 120_000 } else { 600_000 };
            let left = ttl.saturating_sub(r.age(self.clock.wall_ms(), self.clock.mono_ms())).div_ceil(1000);
            Some(json!({"request_id":r.id,"client":c.name,"reason":r.reason,"title":m.title,"type":m.kind,
                "domain":m.domains.first(),"masked_account":m.masked_account,
                "fields":r.fields,"state":r.state,"expires_in_seconds":left}))
        }).collect::<Vec<_>>())
    }
    /// 最近的申请结果，供界面说明授权码是否已被取用。终态保留一小时，不含明文与授权码。
    pub fn state_of(&self, id: &str) -> Option<State> {
        self.requests.get(id).map(|r| r.state)
    }
    pub fn deny(&mut self, id: &str) -> Result<()> {
        self.sweep();
        let r = self
            .requests
            .get(id)
            .filter(|r| r.state == State::Pending)
            .ok_or(UNKNOWN)?;
        let subject = json!({"request_id":id,"item":r.item.to_hex(),"fields":r.fields});
        let mut c = self.client(r.client)?.clone();
        let now = self.clock.wall_ms();
        c.denied.retain(|_, t| *t > now);
        c.denied.insert(r.item.to_hex(), now + 300000);
        c.streak += 1;
        if c.streak >= 3 {
            c.pause_until = now + 900000;
            c.streak = 0;
        }
        self.save(r.client, &c)?;
        self.clients.insert(r.client, c);
        self.audit(r.client, "decision", subject, "denied")?;
        self.requests
            .get_mut(id)
            .ok_or(UNKNOWN)?
            .transition(Event::Deny)
    }
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        let r = self.requests.get_mut(id).ok_or(UNKNOWN)?;
        r.transition(Event::Revoke)?;
        let c = r.client;
        let subject = json!({"request_id":id,"item":r.item.to_hex(),"fields":r.fields});
        self.audit(c, "decision", subject, "revoked")
    }
    pub fn approve(
        &mut self,
        id: &str,
        fields: Vec<AiField>,
        auth: Auth<'_>,
        for_ai: bool,
    ) -> Result<LocalApproval> {
        self.sweep();
        let r = self
            .requests
            .get(id)
            .filter(|r| r.state == State::Pending)
            .ok_or(UNKNOWN)?;
        check_fields(&fields, &r.fields)?;
        let mut client = self.client(r.client)?.clone();
        let (_, meta) = self.vault.ai_item(r.item, &client.tags)?;
        let values = self
            .vault
            .reveal_for_grant(r.item, &fields, auth)
            .map_err(|_| ServiceError(403, "unlock_failed"))?;
        // 直接借用 SecretString 写入可清零的缓冲区，不将机密复制进 JSON Value。
        let rows = values
            .iter()
            .map(|f| match &f.value {
                RevealedValue::Text(s) => Row {
                    name: f.name,
                    value: Field::Text(s.expose()),
                },
                RevealedValue::Pairs(p) => Row {
                    name: f.name,
                    value: Field::Pairs(
                        p.iter()
                            .map(|v| Pair {
                                name: v.name.expose(),
                                value: v.value.expose(),
                            })
                            .collect(),
                    ),
                },
            })
            .collect();
        let data = Zeroizing::new(
            serde_json::to_vec(&Delivery {
                request_id: id,
                item: json!({"title":meta.title,"type":meta.kind,"domain":meta.domains.first()}),
                fields: rows,
            })
            .map_err(|_| OFF)?,
        );
        client.streak = 0;
        self.save(r.client, &client)?;
        self.clients.insert(r.client, client);
        self.audit(
            r.client,
            "decision",
            json!({"request_id":id,"item":r.item.to_hex(),"fields":fields}),
            if for_ai { "code_issued" } else { "view_only" },
        )?;
        let r = self.requests.get_mut(id).ok_or(UNKNOWN)?;
        if r.age(self.clock.wall_ms(), self.clock.mono_ms()) >= 600000 {
            r.transition(Event::RequestTimeout)?;
            return Err(ServiceError(410, "gone"));
        }
        r.fields = fields;
        r.wall = self.clock.wall_ms();
        r.mono = self.clock.mono_ms();
        if for_ai {
            let (env, code) = Envelope::issue(&self.key, &r.aad()?, &data)?;
            r.envelope = Some(env);
            r.transition(Event::ApproveForAi)?;
            Ok(LocalApproval::Code(code))
        } else {
            r.transition(Event::ApproveViewOnly)?;
            Ok(LocalApproval::View(data))
        }
    }
    pub(crate) fn redeem(
        &mut self,
        client: ClientId,
        id: &str,
        code: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.sweep();
        self.client(client)?;
        charge(
            self.redemptions.entry(client).or_default(),
            self.clock.wall_ms(),
            10,
        )?;
        let result = (|| {
            self.owned(client, id)?;
            let r = self.requests.get_mut(id).ok_or(UNKNOWN)?;
            if r.state == State::Pending {
                return Err(ServiceError(409, "not_ready"));
            }
            if !r.state.may_redeem() {
                return Err(ServiceError(410, "gone"));
            }
            let code = code.ok_or(ServiceError(400, "missing_code"))?;
            let env = r.envelope.as_ref().ok_or(OFF)?;
            match env.open(&self.key, &r.aad()?, code) {
                Ok(data) => {
                    r.transition(Event::RedeemOk)?;
                    Ok(data)
                }
                Err(_) => {
                    r.failures += 1;
                    if r.failures >= policy::AUTH_CODE_MAX_FAILURES {
                        r.transition(Event::FailuresExhausted)?;
                    }
                    Err(ServiceError(403, "invalid_code"))
                }
            }
        })();
        // 未知句柄是客户端输入，不复制到审计。
        let subject = self
            .requests
            .get(id)
            .filter(|r| r.client == client)
            .map(|r| json!({"request_id":r.id,"item":r.item.to_hex(),"fields":r.fields}));
        self.audit(
            client,
            "redeem",
            json!(subject),
            result.as_ref().map_or_else(|e| e.1, |_| "redeemed"),
        )?;
        result
    }
    /// 只在主设备重新解锁后查看。输入候选搜索词即可用指纹核对。
    pub fn audit_history(&mut self, auth: Auth<'_>, query: &str) -> Result<Value> {
        self.with_unlocked(auth, |e| e.audit_rows(query))
    }
    /// 界面已解锁时的审计列表。
    pub fn audit_rows(&self, query: &str) -> Result<Value> {
        let filter = self.vault.query_fingerprint(query)?;
        let mut events = Vec::new();
        for row in self.vault.recent_service_audit()? {
            let event: Value = serde_json::from_slice(&row).map_err(|_| OFF)?;
            if query.is_empty() || event["subject"]["query_fingerprint"] == filter {
                events.push(event);
            }
        }
        Ok(json!(events))
    }
    pub fn verify_user(&mut self, auth: Auth<'_>) -> Result<()> {
        self.vault
            .reauthenticate(auth)
            .map_err(|_| ServiceError(403, "unlock_failed"))
    }
    pub fn resume_search(&mut self, id: ClientId, auth: Auth<'_>) -> Result<()> {
        self.with_unlocked(auth, |e| Ok(e.vault.resume_ai_search(id)?))
    }
}
fn check_fields(fields: &[AiField], allowed: &[AiField]) -> Result<()> {
    if fields.is_empty()
        || fields.len() > 4
        || fields
            .iter()
            .enumerate()
            .any(|(i, f)| !allowed.contains(f) || fields[..i].contains(f))
    {
        return Err(ServiceError(400, "invalid_fields"));
    }
    Ok(())
}
pub(crate) fn charge(times: &mut Vec<i64>, now: i64, limit: usize) -> Result<()> {
    times.retain(|t| now.saturating_sub(*t) < 60000);
    if times.len() >= limit {
        return Err(LIMIT);
    }
    times.push(now);
    Ok(())
}
#[derive(Serialize)]
struct Delivery<'a> {
    request_id: &'a str,
    item: Value,
    fields: Vec<Row<'a>>,
}
#[derive(Serialize)]
struct Row<'a> {
    name: AiField,
    value: Field<'a>,
}
#[derive(Serialize)]
struct Pair<'a> {
    name: &'a str,
    value: &'a str,
}
#[derive(Serialize)]
#[serde(untagged)]
enum Field<'a> {
    Text(&'a str),
    Pairs(Vec<Pair<'a>>),
}
