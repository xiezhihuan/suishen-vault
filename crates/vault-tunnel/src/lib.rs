//! 跳板、主设备、桥接三方共用的协议：身份握手、多路复用、端到端 TLS。
//!
//! 密码学全部来自 ring 与 rustls。跳板不启用 `tls` 功能，它看不懂也不需要看懂桥接流量。
#[cfg(feature = "tls")]
pub mod dial;
mod endpoint;
pub mod frame;
pub mod handshake;
mod identity;
pub mod mux;
mod paircode;
#[cfg(feature = "tls")]
pub mod tls;

pub use endpoint::Endpoint;
pub use identity::Identity;
pub use paircode::{PAIR_CODE_LEN, PairCode};

/// Ed25519 公钥。
pub type PublicKey = [u8; 32];

/// 设备建立隧道的路径与协议名。
pub const DEVICE_PATH: &str = "/_relay/device";
pub const DEVICE_PROTOCOL: &str = "suishen-device";
/// 桥接接入的路径与协议名。
pub const BRIDGE_PATH: &str = "/_relay/bridge";
pub const BRIDGE_PROTOCOL: &str = "suishen-bridge";

/// 隧道内每条流的第一个字节。
pub const STREAM_CONTROL: u8 = 0;
pub const STREAM_DIRECT: u8 = 1;
pub const STREAM_BRIDGE: u8 = 2;

/// 控制流上的字节：跳板发心跳，设备原样回送。
pub const PING: u8 = 1;
/// 控制流上的字节：本设备已被新设备取代。
pub const SUPERSEDED: u8 = 2;

pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// 心跳须短于反向代理常见的 60 秒空闲超时。
pub const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// 超过这么久没有收到对方的心跳即视为断线。
pub const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 不携带任何底层错误文本，避免把内容带进日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelError;

pub type Result<T> = std::result::Result<T, TunnelError>;

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("隧道错误")
    }
}

impl std::error::Error for TunnelError {}

impl From<std::io::Error> for TunnelError {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}

/// 系统随机数。
pub fn random<const N: usize>() -> Result<[u8; N]> {
    use ring::rand::SecureRandom;
    let mut b = [0; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| TunnelError)?;
    Ok(b)
}

/// 配对时两端各自显示、由用户比对的短指纹，60 位。
pub fn fingerprint(device: &PublicKey, bridge: &PublicKey) -> String {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"suishen-vault/pair-fingerprint/v1\0");
    h.update(device);
    h.update(bridge);
    let d = h.finish();
    let text = paircode::encode(&d.as_ref()[..12]);
    format!("{}-{}-{}", &text[..4], &text[4..8], &text[8..])
}
