//! 公网模式：经跳板与主设备建立端到端 TLS。跳板与反向代理只看到密文。
use crate::OFF;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes, header};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use vault_core::SecretString;
use vault_service::ServiceError;
use vault_tunnel::{
    BRIDGE_PATH, BRIDGE_PROTOCOL, Endpoint, Identity, PublicKey, dial, tls,
    tls::{DEVICE_HOST, parse_ca},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_REPLY: usize = 32 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

/// App 显示的配对串内容。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairText {
    url: String,
    ca: Option<String>,
    device: String,
    secret: String,
}

/// 存在系统凭据里的一份连接资料。
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct Profile {
    url: String,
    ca: Option<String>,
    device: String,
    key: String,
    pub token: String,
}

pub struct Remote {
    endpoint: Endpoint,
    ca: Option<String>,
    device: PublicKey,
    me: Identity,
}

pub struct Reply {
    pub status: u16,
    pub body: String,
}

fn public_key(text: &str) -> Result<PublicKey, ()> {
    hex::decode(text)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(())
}

impl Remote {
    fn new(url: &str, ca: Option<&String>, device: &str, me: Identity) -> Result<Self, ()> {
        if let Some(pem) = ca {
            parse_ca(pem).map_err(|_| ())?;
        }
        Ok(Self {
            endpoint: Endpoint::parse(url).map_err(|_| ())?,
            ca: ca.cloned(),
            device: public_key(device)?,
            me,
        })
    }

    pub fn open(p: &Profile) -> Result<Self, ()> {
        let me = Identity::from_hex(&p.key).map_err(|_| ())?;
        Self::new(&p.url, p.ca.as_ref(), &p.device, me)
    }

    /// 每次请求一条新的端到端连接。设备身份在内层握手里核对，对不上就不会发出任何内容。
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&SecretString>,
        code: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Reply, ServiceError> {
        let work = async {
            let outer = dial::upgrade(
                &self.endpoint,
                self.ca.as_deref(),
                BRIDGE_PATH,
                BRIDGE_PROTOCOL,
            )
            .await
            .map_err(|_| OFF)?
            .ok_or(OFF)?;
            let inner = tls::bridge_connect(outer, &self.me, self.device)
                .await
                .map_err(|_| OFF)?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(inner))
                .await
                .map_err(|_| OFF)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, DEVICE_HOST)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(t) = token {
                let value = Zeroizing::new(format!("Bearer {}", t.expose()));
                req = req.header(header::AUTHORIZATION, value.as_str());
            }
            if let Some(c) = code {
                req = req.header("x-auth-code", crate::code_header(c));
            }
            let req = req.body(Full::new(Bytes::from(body))).map_err(|_| OFF)?;
            let reply = send.send_request(req).await.map_err(|_| OFF)?;
            let status = reply.status().as_u16();
            let data = Limited::new(reply.into_body(), MAX_REPLY)
                .collect()
                .await
                .map_err(|_| OFF)?
                .to_bytes();
            Ok(Reply {
                status,
                body: String::from_utf8(data.to_vec()).map_err(|_| OFF)?,
            })
        };
        tokio::time::timeout(TIMEOUT, work).await.map_err(|_| OFF)?
    }
}

/// 用 App 的配对串完成配对。`show` 用来显示供用户比对的指纹。
pub async fn pair(text: &str, show: impl FnOnce(&str)) -> Result<Profile, ()> {
    let hex = text.trim().strip_prefix("svp1:").ok_or(())?;
    let bytes = Zeroizing::new(hex::decode(hex).map_err(|_| ())?);
    let p: PairText = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let secret = Zeroizing::new(p.secret);
    let me = Identity::generate().map_err(|_| ())?;
    let key = me.to_hex();
    let fingerprint = vault_tunnel::fingerprint(&public_key(&p.device)?, &me.public());
    let remote = Remote::new(&p.url, p.ca.as_ref(), &p.device, me)?;
    let body = serde_json::to_vec(&serde_json::json!({"secret": &*secret, "label": label()}))
        .map_err(|_| ())?;
    let mut show = Some(show);
    // 配对串 10 分钟有效
    for _ in 0..300 {
        let r = remote
            .call("POST", "/v1/pair", None, None, body.clone())
            .await;
        match r {
            Ok(r) if r.status == 200 => {
                let v: serde_json::Value = serde_json::from_str(&r.body).map_err(|_| ())?;
                if let Some(show) = show.take() {
                    show(&fingerprint);
                }
                if let Some(token) = v["token"].as_str() {
                    return Ok(Profile {
                        url: p.url,
                        ca: p.ca,
                        device: p.device,
                        key: key.to_string(),
                        token: token.to_owned(),
                    });
                }
            }
            // 已经开始等待后，一次网络波动或限流不算失败
            Ok(r) if r.status == 429 && show.is_none() => {}
            Err(_) if show.is_none() => {}
            _ => return Err(()),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(())
}

/// 显示在 App 上帮助辨认，不作为身份依据。
fn label() -> String {
    ["HOSTNAME", "COMPUTERNAME", "USER", "USERNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
                .take(40)
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "vault-bridge".into())
}
