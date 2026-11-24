use crate::{Result, TunnelError, random};
use ring::hmac;
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 20 个 Crockford 字符，100 位。
pub const PAIR_CODE_LEN: usize = 20;

pub(crate) fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| ALPHABET[usize::from(b & 31)] as char)
        .collect()
}

/// 跳板管理员配对码。线上只传由它算出的 HMAC，跳板磁盘上只存派生密钥。
pub struct PairCode(Zeroizing<String>);

impl PairCode {
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(encode(&random::<PAIR_CODE_LEN>()?))))
    }

    /// 去掉空格与连字符、转大写、纠正易混字符。
    pub fn parse(text: &str) -> Result<Self> {
        let s: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| match c.to_ascii_uppercase() {
                    'O' => '0',
                    'I' | 'L' => '1',
                    c => c,
                })
                .collect(),
        );
        if s.len() != PAIR_CODE_LEN || !s.bytes().all(|b| ALPHABET.contains(&b)) {
            return Err(TunnelError);
        }
        Ok(Self(s))
    }

    /// 五个一组，便于抄写。
    pub fn display(&self) -> Zeroizing<String> {
        let groups: Vec<_> = (0..4).map(|i| &self.0[i * 5..i * 5 + 5]).collect();
        Zeroizing::new(groups.join("-"))
    }

    pub fn key(&self) -> [u8; 32] {
        let mut h = ring::digest::Context::new(&ring::digest::SHA256);
        h.update(b"suishen-vault/relay-pairing/v1\0");
        h.update(self.0.as_bytes());
        let mut out = [0; 32];
        out.copy_from_slice(h.finish().as_ref());
        out
    }

    pub(crate) fn prove(&self, transcript: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key());
        hmac::sign(&key, transcript).as_ref().to_vec()
    }
}

/// 常量时间比较。
pub(crate) fn verify(key: &[u8; 32], transcript: &[u8], proof: &[u8]) -> bool {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), transcript, proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_survives_copying_by_hand() {
        let c = PairCode::generate().unwrap();
        let shown = c.display();
        assert_eq!(shown.len(), 23);
        let sloppy = shown.to_lowercase().replace('-', " ");
        assert_eq!(PairCode::parse(&sloppy).unwrap().key(), c.key());
        assert!(PairCode::parse(&shown[1..]).is_err());
        assert!(PairCode::parse("UUUUU-UUUUU-UUUUU-UUUUU").is_err());
        let proof = c.prove(b"a");
        assert!(verify(&c.key(), b"a", &proof));
        assert!(!verify(&c.key(), b"b", &proof));
    }
}
