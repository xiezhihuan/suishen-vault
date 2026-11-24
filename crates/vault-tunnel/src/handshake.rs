//! 设备向跳板证明身份。在升级后的连接上、多路复用开始之前进行。
//!
//! 跳板先发随机挑战，设备对“跳板主机名 + 挑战 + 公钥 + 选项”签名。
//! 绑定主机名，是为了不让别的跳板把挑战转手骗签。
use crate::{
    HANDSHAKE_TIMEOUT, Identity, PairCode, PublicKey, Result, TunnelError, frame, identity,
    paircode, random,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

const DOMAIN: &[u8] = b"suishen-vault/relay-auth/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    key: String,
    sig: String,
    /// 用配对码接管时附带。
    claim: Option<String>,
    /// 是否允许跳板转发直连 HTTPS 请求。
    direct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accepted,
    /// 没有登记、签名不符、配对码错误或过期，不加区分。
    Rejected,
    /// 曾是当前设备，已被新设备取代。只有证明了私钥才会得到这个答复。
    Superseded,
}

fn transcript(
    host: &str,
    challenge: &[u8; 32],
    key: &PublicKey,
    claim: bool,
    direct: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for part in [
        DOMAIN,
        host.as_bytes(),
        challenge,
        key,
        &[u8::from(claim)],
        &[u8::from(direct)],
    ] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn array<const N: usize>(text: &str) -> Result<[u8; N]> {
    hex::decode(text)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(TunnelError)
}

/// 设备侧。
pub async fn prove<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    me: &Identity,
    code: Option<&PairCode>,
    direct: bool,
) -> Result<Verdict> {
    let work = async {
        let c: Challenge = frame::recv(io).await?;
        let key = me.public();
        let t = transcript(host, &array(&c.challenge)?, &key, code.is_some(), direct);
        let hello = Hello {
            key: hex::encode(key),
            sig: hex::encode(me.sign(&t)),
            claim: code.map(|c| hex::encode(c.prove(&t))),
            direct,
        };
        frame::send(io, &hello).await?;
        frame::recv(io).await
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| TunnelError)?
}

/// 已证明持有私钥的设备。
pub struct Proven {
    pub key: PublicKey,
    pub direct: bool,
    transcript: Vec<u8>,
    claim: Option<Vec<u8>>,
}

impl Proven {
    pub fn claims(&self) -> bool {
        self.claim.is_some()
    }

    /// 配对码证明与本次握手绑定，截获后不能换到别的设备上用。
    pub fn knows_code(&self, key: &[u8; 32]) -> bool {
        self.claim
            .as_ref()
            .is_some_and(|p| paircode::verify(key, &self.transcript, p))
    }
}

/// 跳板侧：发挑战并核对签名。`None` 表示签名不符。
pub async fn challenge<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
) -> Result<Option<Proven>> {
    let work = async {
        let challenge = random::<32>()?;
        let first = Challenge {
            challenge: hex::encode(challenge),
        };
        frame::send(io, &first).await?;
        let hello: Hello = frame::recv(io).await?;
        let key = array(&hello.key)?;
        let t = transcript(host, &challenge, &key, hello.claim.is_some(), hello.direct);
        if !identity::verify(&key, &t, &array::<64>(&hello.sig)?) {
            return Ok(None);
        }
        Ok(Some(Proven {
            key,
            direct: hello.direct,
            transcript: t,
            claim: hello
                .claim
                .map(|c| array::<32>(&c))
                .transpose()?
                .map(Into::into),
        }))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| TunnelError)?
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(device_host: &str, me: &Identity, code: Option<&PairCode>) -> Option<Proven> {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let device = async {
            let _ = prove(&mut a, device_host, me, code, true).await;
        };
        let relay = async {
            let r = challenge(&mut b, "relay.example.com").await.unwrap();
            drop(b);
            r
        };
        tokio::join!(device, relay).1
    }

    #[tokio::test]
    async fn signature_is_bound_to_host_challenge_and_code() {
        let me = Identity::generate().unwrap();
        let p = run("relay.example.com", &me, None).await.unwrap();
        assert_eq!(p.key, me.public());
        assert!(!p.claims() && p.direct);
        assert!(run("evil.example.com", &me, None).await.is_none());

        let code = PairCode::generate().unwrap();
        let p = run("relay.example.com", &me, Some(&code)).await.unwrap();
        assert!(p.knows_code(&code.key()));
        assert!(!p.knows_code(&PairCode::generate().unwrap().key()));
    }

    // AC-REL-04：录下的握手换一次挑战就失效
    #[tokio::test]
    async fn replayed_hello_is_refused() {
        let me = Identity::generate().unwrap();
        let hello = |c: [u8; 32]| {
            let t = transcript("h", &c, &me.public(), false, false);
            Hello {
                key: hex::encode(me.public()),
                sig: hex::encode(me.sign(&t)),
                claim: None,
                direct: false,
            }
        };
        let (mut a, mut b) = tokio::io::duplex(8192);
        let replay = async {
            let _: Challenge = frame::recv(&mut a).await.unwrap();
            frame::send(&mut a, &hello([7; 32])).await.unwrap();
        };
        let (_, r) = tokio::join!(replay, challenge(&mut b, "h"));
        assert!(r.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_frame_is_refused() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(8192);
        a.write_u32(1 << 20).await.unwrap();
        assert!(frame::recv::<Hello>(&mut b).await.is_err());
    }
}
