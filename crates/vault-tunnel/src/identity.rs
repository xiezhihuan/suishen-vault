use crate::{PublicKey, Result, TunnelError};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use zeroize::Zeroizing;

/// Ed25519 密钥对。不实现 `Debug`、`Serialize`。
pub struct Identity {
    pkcs8: Zeroizing<Vec<u8>>,
    pair: Ed25519KeyPair,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| TunnelError)?;
        Self::from_pkcs8(doc.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        Ok(Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| TunnelError)?,
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
        })
    }

    pub fn from_hex(text: &str) -> Result<Self> {
        Self::from_pkcs8(&Zeroizing::new(hex::decode(text).map_err(|_| TunnelError)?))
    }

    /// 私钥的十六进制，只用于写入加密存储。
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(&*self.pkcs8))
    }

    #[cfg(feature = "tls")]
    pub(crate) fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn public(&self) -> PublicKey {
        let mut out = [0; 32];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut out = [0; 64];
        out.copy_from_slice(self.pair.sign(message).as_ref());
        out
    }
}

pub(crate) fn verify(key: &PublicKey, message: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, sig)
        .is_ok()
}
