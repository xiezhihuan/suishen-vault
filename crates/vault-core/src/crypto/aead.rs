//! XChaCha20-Poly1305 与 AAD 编码。
//!
//! 密文布局：`nonce(24) || ciphertext || tag(16)`。明文先补齐到 64 字节的整数倍，
//! 避免从密文长度看出密码长度。

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::{Key, random_array};

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;
const PAD_BLOCK: usize = 64;
const DOMAIN: &[u8] = b"suishen-vault/v1";

/// 用途标识，写进 AAD，防止不同用途的密文互换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Purpose {
    WrapMetaKey = 1,
    WrapSecretKey = 2,
    ItemMeta = 3,
    ItemField = 4,
    Manifest = 5,
    Migration = 6,
    Backup = 7,
    MigrationPackage = 8,
    SearchQuota = 9,
}

/// 带长度前缀的 AAD：每一段都是 `u32 长度 || 内容`，不同分段不会拼出相同字节。
pub(crate) struct Aad(Vec<u8>);

impl Aad {
    pub(crate) fn new(purpose: Purpose, vault_id: &[u8; 16]) -> Self {
        Self(Vec::with_capacity(160))
            .part(DOMAIN)
            .part(&[purpose as u8])
            .part(vault_id)
    }

    pub(crate) fn part(mut self, bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn int(self, v: u64) -> Self {
        self.part(&v.to_be_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 不补齐的加密，给定长密钥包裹使用。
pub(crate) fn seal_raw(key: &Key, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = random_array()?;
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::TooLarge)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn open_raw(key: &Key, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (nonce, ct) = blob
        .split_first_chunk::<NONCE_LEN>()
        .filter(|(_, ct)| ct.len() >= TAG_LEN)
        .ok_or(Error::Tampered)?;
    XChaCha20Poly1305::new(key.bytes().into())
        .decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Tampered)
}

pub(crate) fn seal(key: &Key, aad: &Aad, plain: &[u8]) -> Result<Vec<u8>> {
    seal_raw(key, aad.as_bytes(), &pad(plain, PAD_BLOCK)?)
}

pub(crate) fn open(key: &Key, aad: &Aad, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    unpad(&open_raw(key, aad.as_bytes(), blob)?)
}

pub(crate) fn pad(plain: &[u8], block: usize) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(plain.len()).map_err(|_| Error::TooLarge)?;
    let total = (4 + plain.len()).next_multiple_of(block);
    let mut buf = Zeroizing::new(Vec::with_capacity(total));
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(plain);
    buf.resize(total, 0);
    Ok(buf)
}

pub(crate) fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (len, rest) = padded.split_first_chunk::<4>().ok_or(Error::Tampered)?;
    let len = u32::from_be_bytes(*len) as usize;
    let body = rest.get(..len).ok_or(Error::Tampered)?;
    if rest[len..].iter().any(|b| *b != 0) {
        return Err(Error::Tampered);
    }
    Ok(Zeroizing::new(body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::unhex;
    use proptest::prelude::*;

    /// draft-irtf-cfrg-xchacha-03 附录 A.3.1。
    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key = Key::from_slice(&unhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ))
        .unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e",
        );
        let tag = unhex("c0875924c1c7987947deafd8780acf49");
        let blob = [nonce, ct, tag].concat();
        assert_eq!(open_raw(&key, &aad, &blob).unwrap()[..], plain[..]);
        // 反向：用同一 nonce 加密应得到同样的字节
        let n: [u8; 24] = blob[..24].try_into().unwrap();
        let out = XChaCha20Poly1305::new(key.bytes().into())
            .encrypt(
                &XNonce::from(n),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(out, blob[24..]);
    }

    #[test]
    fn length_is_hidden_within_a_block() {
        let key = Key::random().unwrap();
        let aad = Aad::new(Purpose::ItemField, &[1; 16]);
        let a = seal(&key, &aad, &[b'x'; 8]).unwrap().len();
        let b = seal(&key, &aad, &[b'x'; 40]).unwrap().len();
        assert_eq!(a, b);
    }

    proptest! {
        #[test]
        fn round_trip(plain in prop::collection::vec(any::<u8>(), 0..500)) {
            let key = Key::random().unwrap();
            let aad = Aad::new(Purpose::ItemMeta, &[7; 16]).int(3);
            let blob = seal(&key, &aad, &plain).unwrap();
            prop_assert_eq!(&open(&key, &aad, &blob).unwrap()[..], &plain[..]);
        }

        #[test]
        fn any_bit_flip_or_truncation_fails(
            plain in prop::collection::vec(any::<u8>(), 0..200),
            pos in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            let key = Key::random().unwrap();
            let aad = Aad::new(Purpose::ItemMeta, &[7; 16]);
            let blob = seal(&key, &aad, &plain).unwrap();
            let i = pos.index(blob.len());
            let mut bad = blob.clone();
            bad[i] ^= 1 << bit;
            prop_assert_eq!(open(&key, &aad, &bad).err(), Some(Error::Tampered));
            prop_assert_eq!(open(&key, &aad, &blob[..i]).err(), Some(Error::Tampered));
        }

        #[test]
        fn aad_parts_are_injective(
            a in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..6), 0..5),
            b in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..6), 0..5),
        ) {
            let enc = |parts: &Vec<Vec<u8>>| parts.iter()
                .fold(Aad::new(Purpose::ItemField, &[0; 16]), |x, p| x.part(p)).0;
            prop_assert_eq!(a == b, enc(&a) == enc(&b));
        }

        #[test]
        fn unpad_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
            let _ = unpad(&bytes);
        }
    }
}
