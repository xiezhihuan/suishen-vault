//! 跳板登记与桥接配对。配对须由用户在 App 上发起并确认。AC-MCP-07
use crate::{
    Access, Engine, ServiceError,
    engine::{BAD, OFF, Result, random, valid_text},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vault_core::{Auth, Clock, SecretString};
use vault_tunnel::{
    DEVICE_PATH, DEVICE_PROTOCOL, Endpoint, Identity, PairCode, PublicKey, dial, fingerprint,
    handshake::{self, Verdict},
    tls::parse_ca,
};
use zeroize::{Zeroize, Zeroizing};

const PAIR_TTL_MS: u64 = 600_000;
const PAIR_MAX_FAILURES: u8 = 5;
const GONE: ServiceError = ServiceError::new(410, "pairing_closed");

/// 加密存放在密库里，不进备份与迁移包。
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct Stored {
    url: String,
    ca: Option<String>,
    /// 向跳板证明身份的私钥，每次登记都换新。
    relay_key: String,
    /// 与桥接之间端到端 TLS 的私钥，换跳板不变。
    device_key: String,
    superseded: bool,
}

/// 打开公网所需的材料。
pub(crate) struct Remote {
    pub endpoint: Endpoint,
    pub ca: Option<String>,
    pub relay: Identity,
    pub device: Identity,
}

/// 尚未完成的跳板登记。
pub struct RelayClaim {
    remote: Remote,
    code: PairCode,
}

/// 连接跳板并用配对码登记。成功后还须 [`Engine::relay_commit`]。
pub async fn claim_relay(claim: RelayClaim) -> Result<RelayClaim> {
    let r = &claim.remote;
    let unreachable = ServiceError::new(503, "relay_unreachable");
    let mut io = dial::upgrade(&r.endpoint, r.ca.as_deref(), DEVICE_PATH, DEVICE_PROTOCOL)
        .await
        .map_err(|_| unreachable)?
        .ok_or(ServiceError::new(503, "relay_refused"))?;
    match handshake::prove(
        &mut io,
        &r.endpoint.authority(),
        &r.relay,
        Some(&claim.code),
        false,
    )
    .await
    {
        Ok(Verdict::Accepted) => Ok(claim),
        Ok(_) => Err(ServiceError::new(403, "relay_code")),
        Err(_) => Err(unreachable),
    }
}

/// 桥接配对。一次只有一个，服务关闭即取消。
pub(crate) struct Pairing {
    digest: [u8; 32],
    name: String,
    tags: Vec<String>,
    wall: i64,
    mono: u64,
    failures: u8,
    stage: Stage,
}

enum Stage {
    /// 等桥接连入。
    Open,
    /// 桥接出示了配对密钥，等用户核对指纹。
    Asked { key: PublicKey, label: String },
    /// 用户已确认，等桥接来取令牌。
    Ready { key: PublicKey, token: SecretString },
}

impl Pairing {
    /// 握手阶段就挡掉无关的公钥。
    pub fn admits(&self, key: &PublicKey) -> bool {
        match &self.stage {
            Stage::Open => true,
            Stage::Asked { key: k, .. } | Stage::Ready { key: k, .. } => k == key,
        }
    }
    fn live(&self, clock: &dyn Clock) -> bool {
        let wall = clock.wall_ms();
        let age = clock
            .mono_ms()
            .saturating_sub(self.mono)
            .max(wall.saturating_sub(self.wall).max(0) as u64);
        wall >= self.wall && age < PAIR_TTL_MS && self.failures < PAIR_MAX_FAILURES
    }
}

impl Engine {
    fn stored(&self) -> Result<Option<Stored>> {
        self.vault()
            .remote_config()?
            .map(|b| serde_json::from_slice(&b).map_err(|_| OFF))
            .transpose()
    }
    fn store(&mut self, s: &Stored) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(s).map_err(|_| OFF)?);
        self.vault_mut().store_remote_config(Some(&bytes))?;
        Ok(())
    }
    /// 供界面显示，不含密钥。锁定时为 `null`。
    pub fn relay_info(&self) -> Value {
        match self.stored() {
            Ok(Some(s)) => json!({"url": s.url, "custom_ca": s.ca.is_some(),
                "superseded": s.superseded}),
            _ => Value::Null,
        }
    }
    /// 准备登记：每次都生成新的跳板身份。
    pub fn relay_begin(
        &mut self,
        url: &str,
        ca: Option<&str>,
        code: &str,
        auth: Auth<'_>,
    ) -> Result<RelayClaim> {
        let endpoint = Endpoint::parse(url).map_err(|_| ServiceError::new(400, "relay_url"))?;
        let ca = ca.map(str::trim).filter(|s| !s.is_empty());
        if let Some(pem) = ca {
            parse_ca(pem).map_err(|_| ServiceError::new(400, "relay_ca"))?;
        }
        let code = PairCode::parse(code).map_err(|_| ServiceError::new(400, "relay_code"))?;
        self.verify_user(auth)?;
        let device = match self.stored()? {
            Some(s) => Identity::from_hex(&s.device_key),
            None => Identity::generate(),
        };
        Ok(RelayClaim {
            remote: Remote {
                endpoint,
                ca: ca.map(str::to_owned),
                relay: Identity::generate().map_err(|_| OFF)?,
                device: device.map_err(|_| OFF)?,
            },
            code,
        })
    }
    pub fn relay_commit(&mut self, claim: RelayClaim) -> Result<()> {
        let r = claim.remote;
        self.store(&Stored {
            url: r.endpoint.url(),
            ca: r.ca,
            relay_key: r.relay.to_hex().to_string(),
            device_key: r.device.to_hex().to_string(),
            superseded: false,
        })
    }
    /// 清除本机的跳板配置与设备身份。已配对的桥接须重新配对。
    pub fn relay_forget(&mut self) -> Result<()> {
        self.vault_mut().store_remote_config(None)?;
        Ok(())
    }
    pub(crate) fn relay_superseded(&mut self) -> Result<()> {
        if let Some(mut s) = self.stored()? {
            s.superseded = true;
            self.store(&s)?;
        }
        Ok(())
    }
    pub(crate) fn remote(&self) -> Result<Remote> {
        let s = self
            .stored()?
            .ok_or(ServiceError::new(409, "relay_not_set"))?;
        if s.superseded {
            return Err(ServiceError::new(409, "relay_superseded"));
        }
        Ok(Remote {
            endpoint: Endpoint::parse(&s.url).map_err(|_| OFF)?,
            ca: s.ca.clone(),
            relay: Identity::from_hex(&s.relay_key).map_err(|_| OFF)?,
            device: Identity::from_hex(&s.device_key).map_err(|_| OFF)?,
        })
    }

    // ---- 桥接配对 ----

    /// 生成配对串。只显示一次，10 分钟有效。
    pub fn pairing_begin(
        &mut self,
        name: &str,
        tags: Vec<String>,
        auth: Auth<'_>,
    ) -> Result<SecretString> {
        self.check_client(name, &tags)?;
        self.verify_user(auth)?;
        let remote = self.remote()?;
        let secret = Zeroizing::new(hex::encode(*Zeroizing::new(random::<16>()?)));
        let text = pair_string(&remote, &secret)?;
        self.pairing = Some(Pairing {
            digest: Sha256::digest(secret.as_bytes()).into(),
            name: name.to_owned(),
            tags,
            wall: self.clock().wall_ms(),
            mono: self.clock().mono_ms(),
            failures: 0,
            stage: Stage::Open,
        });
        Ok(text)
    }
    pub fn pairing_cancel(&mut self) {
        self.pairing = None;
    }
    pub(crate) fn pairing_sweep(&mut self) {
        let clock = self.clock();
        if self.pairing.as_ref().is_some_and(|p| !p.live(clock)) {
            self.pairing = None;
        }
    }
    /// 供界面显示。
    pub fn pairing_info(&mut self) -> Value {
        self.pairing_sweep();
        let Some(p) = &self.pairing else {
            return Value::Null;
        };
        let age = self.clock().wall_ms().saturating_sub(p.wall).max(0) as u64;
        let mut out = json!({"name": p.name, "state": "open",
            "expires_in_seconds": PAIR_TTL_MS.saturating_sub(age).div_ceil(1000)});
        match &p.stage {
            Stage::Open => {}
            Stage::Asked { key, label } => {
                let Ok(r) = self.remote() else {
                    return Value::Null;
                };
                out["state"] = json!("asked");
                out["label"] = json!(label);
                out["fingerprint"] = json!(fingerprint(&r.device.public(), key));
            }
            Stage::Ready { .. } => out["state"] = json!("ready"),
        }
        out
    }
    /// 用户核对指纹后确认。令牌由桥接在同一条加密连接上取走，不经过界面。
    pub fn pairing_accept(&mut self) -> Result<()> {
        self.pairing_sweep();
        let Some(Pairing {
            stage: Stage::Asked { key, .. },
            name,
            tags,
            ..
        }) = &self.pairing
        else {
            return Err(GONE);
        };
        let (key, name, tags) = (*key, name.clone(), tags.clone());
        let (_, token) = self.add_client_for(&name, tags, Access::Bridge(key))?;
        if let Some(p) = &mut self.pairing {
            p.stage = Stage::Ready { key, token };
        }
        Ok(())
    }
    /// 桥接经端到端连接提交配对密钥。`peer` 已由 TLS 证明持有私钥。
    pub(crate) fn pair(&mut self, peer: PublicKey, secret: &str, label: &str) -> Result<Value> {
        self.pairing_sweep();
        let p = self.pairing.as_mut().ok_or(GONE)?;
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        if !bool::from(digest.ct_eq(&p.digest)) {
            p.failures += 1;
            self.pairing_sweep();
            return Err(ServiceError::new(403, "invalid_pairing"));
        }
        if !valid_text(label, 64) {
            return Err(BAD);
        }
        if !p.admits(&peer) {
            return Err(GONE);
        }
        match &p.stage {
            Stage::Open => {
                p.stage = Stage::Asked {
                    key: peer,
                    label: label.to_owned(),
                };
                Ok(json!({"state":"waiting"}))
            }
            Stage::Asked { .. } => Ok(json!({"state":"waiting"})),
            Stage::Ready { token, .. } => {
                let out = json!({"state":"paired","token":token.expose()});
                self.pairing = None;
                Ok(out)
            }
        }
    }
}

/// `svp1:` 加十六进制 JSON。含配对密钥，不含令牌。
fn pair_string(r: &Remote, secret: &str) -> Result<SecretString> {
    let body = Zeroizing::new(
        json!({"url": r.endpoint.url(), "ca": r.ca, "device": hex::encode(r.device.public()),
            "secret": secret})
        .to_string(),
    );
    Ok(SecretString::new(format!(
        "svp1:{}",
        hex::encode(body.as_bytes())
    )))
}
