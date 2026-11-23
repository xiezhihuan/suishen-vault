//! 密码学封装。只组合成熟库，不自造算法。

pub(crate) mod aead;
pub mod code;
pub(crate) mod kdf;
pub(crate) mod wrap;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::secret::Key;

/// HKDF-SHA256，输出 256 位。`info` 用于区分用途。
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Key> {
    let mut out = Key::zeroed();
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.bytes_mut())
        .map_err(|_| Error::Tampered)?;
    Ok(out)
}

#[cfg(test)]
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 附录 A.1。
    #[test]
    fn hkdf_rfc5869_case_1() {
        let okm = hkdf_sha256(
            &[0x0b; 22],
            &unhex("000102030405060708090a0b0c"),
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
        )
        .unwrap();
        assert_eq!(
            okm.bytes()[..],
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
        );
    }
}
