//! 一次性授权包。调用方提供包含客户端、申请、条目、获批字段和有效期的 AAD。
use crate::{
    Error, Key, Result, SecretString,
    crypto::{aead, code, hkdf_sha256},
    secret::random_array,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(ZeroizeOnDrop)]
pub struct Envelope {
    salt: [u8; 32],
    verifier: [u8; 32],
    ciphertext: Vec<u8>,
}

fn verifier(key: &Key, code: &SecretString) -> Result<[u8; 32]> {
    let mut h = Hmac::<Sha256>::new_from_slice(key.expose()).map_err(|_| Error::Storage)?;
    h.update(code.expose().as_bytes());
    Ok(h.finalize().into_bytes().into())
}
impl Envelope {
    pub fn issue(process: &Key, aad: &[u8], data: &[u8]) -> Result<(Self, SecretString)> {
        let random = Zeroizing::new(random_array()?);
        let code = code::short_code(&random);
        let salt = random_array()?;
        let key = hkdf_sha256(code.expose().as_bytes(), &salt, b"suishen-vault/grant/v1")?;
        let envelope = Self {
            salt,
            verifier: verifier(process, &code)?,
            ciphertext: aead::seal_raw(&key, aad, data)?,
        };
        Ok((envelope, code))
    }
    pub fn open(&self, process: &Key, aad: &[u8], input: &str) -> Result<Zeroizing<Vec<u8>>> {
        let code = code::parse_short_code(input)?;
        if !bool::from(self.verifier.ct_eq(&verifier(process, &code)?)) {
            return Err(Error::UnlockFailed);
        }
        let key = hkdf_sha256(
            code.expose().as_bytes(),
            &self.salt,
            b"suishen-vault/grant/v1",
        )?;
        aead::open_raw(&key, aad, &self.ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changing_any_grant_binding_fails_with_the_correct_code() {
        let key = Key::random().unwrap();
        let binding = [
            "client", "request", "item", "revision", "password", "expiry",
        ];
        let aad = serde_json::to_vec(&binding).unwrap();
        let (envelope, code) = Envelope::issue(&key, &aad, b"fake-field").unwrap();
        assert_eq!(
            &**envelope.open(&key, &aad, code.expose()).unwrap(),
            b"fake-field"
        );
        for index in 0..binding.len() {
            let mut changed = binding;
            changed[index] = "other";
            assert!(
                envelope
                    .open(&key, &serde_json::to_vec(&changed).unwrap(), code.expose())
                    .is_err()
            );
        }
    }
}
