//! 人工抄写的码：恢复密钥、迁移码、完成码。都用 Crockford Base32，带校验字符。

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::policy::CROCKFORD_ALPHABET;
use crate::secret::{SecretString, fill_random};

/// 归一化并解码为 5 位符号：去连字符与空格、忽略大小写、`O→0`、`I/L→1`。
fn parse_symbols(input: &str, expected: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(expected));
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' | '\r' | '\n' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = CROCKFORD_ALPHABET
            .iter()
            .position(|a| *a as char == c)
            .ok_or(Error::CodeFormat)?;
        if out.len() == expected {
            return Err(Error::CodeFormat);
        }
        out.push(v as u8);
    }
    if out.len() == expected {
        Ok(out)
    } else {
        Err(Error::CodeFormat)
    }
}

fn checksum(label: &[u8], symbols: &[u8], n: usize) -> Zeroizing<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(b"suishen-vault/v1 checksum ");
    h.update(label);
    h.update(symbols);
    let mut d = h.finalize();
    let out = Zeroizing::new(d.iter().take(n).map(|b| b & 31).collect());
    d.as_mut_slice().zeroize();
    out
}

fn format_groups(symbols: &[u8]) -> SecretString {
    let mut s = String::with_capacity(symbols.len() * 5 / 4 + 1);
    for (i, v) in symbols.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(CROCKFORD_ALPHABET[usize::from(*v & 31)] as char);
    }
    SecretString::new(s)
}

/// 数据符号 + 校验符号，均为 0..32。
#[derive(Zeroize, ZeroizeOnDrop)]
struct CheckedCode<const DATA: usize, const CHECK: usize>(Vec<u8>);

impl<const DATA: usize, const CHECK: usize> CheckedCode<DATA, CHECK> {
    fn generate(label: &[u8]) -> Result<Self> {
        let mut v = Vec::with_capacity(DATA + CHECK);
        v.resize(DATA, 0);
        fill_random(&mut v)?;
        v.iter_mut().for_each(|b| *b &= 31);
        let c = checksum(label, &v, CHECK);
        v.extend_from_slice(&c);
        Ok(Self(v))
    }

    fn parse(label: &[u8], input: &str) -> Result<Self> {
        let v = parse_symbols(input, DATA + CHECK)?;
        if checksum(label, &v[..DATA], CHECK)[..] != v[DATA..] {
            return Err(Error::CodeFormat);
        }
        let mut own = Vec::with_capacity(v.len());
        own.extend_from_slice(&v);
        Ok(Self(own))
    }

    /// 作为 HKDF 的输入密钥材料。每个字节携带 5 位熵。
    fn ikm(&self) -> &[u8] {
        &self.0[..DATA]
    }
}

const RECOVERY_LABEL: &[u8] = b"recovery";
const MIGRATION_LABEL: &[u8] = b"migration";
pub(crate) const RECOVERY_GROUPS: u32 = 9;

/// 恢复密钥：160 位随机（32 字符）+ 4 个校验字符，共 9 组。
#[derive(ZeroizeOnDrop)]
pub struct RecoveryKey(CheckedCode<32, 4>);

impl RecoveryKey {
    pub(crate) fn generate() -> Result<Self> {
        CheckedCode::generate(RECOVERY_LABEL).map(Self)
    }

    pub fn parse(input: &str) -> Result<Self> {
        CheckedCode::parse(RECOVERY_LABEL, input).map(Self)
    }

    /// 给用户抄写的形式。
    pub fn display(&self) -> SecretString {
        format_groups(&self.0.0)
    }

    pub(crate) fn ikm(&self) -> &[u8] {
        self.0.ikm()
    }

    /// 核对第 `index` 组（0 起）。
    pub(crate) fn group_matches(&self, index: u32, answer: &str) -> bool {
        let i = index as usize * 4;
        match parse_symbols(answer, 4) {
            Ok(a) => self.0.0.get(i..i + 4) == Some(&a[..]),
            Err(_) => false,
        }
    }
}

/// 迁移码：130 位随机（26 字符）+ 2 个校验字符，共 7 组。
#[derive(ZeroizeOnDrop)]
pub struct MigrationCode(CheckedCode<26, 2>);

impl MigrationCode {
    pub(crate) fn generate() -> Result<Self> {
        CheckedCode::generate(MIGRATION_LABEL).map(Self)
    }

    pub fn parse(input: &str) -> Result<Self> {
        CheckedCode::parse(MIGRATION_LABEL, input).map(Self)
    }

    pub fn display(&self) -> SecretString {
        format_groups(&self.0.0)
    }

    pub(crate) fn ikm(&self) -> &[u8] {
        self.0.ikm()
    }
}

/// 8 位完成码（40 位），由摘要截断而来。
pub(crate) fn short_code(digest: &[u8; 32]) -> SecretString {
    let symbols: Zeroizing<Vec<u8>> = Zeroizing::new(digest[..8].iter().map(|b| b & 31).collect());
    format_groups(&symbols)
}

pub(crate) fn parse_short_code(input: &str) -> Result<SecretString> {
    Ok(format_groups(&parse_symbols(input, 8)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn shapes_match_the_design() {
        let r = RecoveryKey::generate().unwrap().display();
        assert_eq!(r.expose().split('-').count(), RECOVERY_GROUPS as usize);
        assert_eq!(r.expose().replace('-', "").len(), 36);
        let m = MigrationCode::generate().unwrap().display();
        assert_eq!(m.expose().split('-').count(), 7);
        assert_eq!(m.expose().replace('-', "").len(), 28);
    }

    #[test]
    fn human_input_is_normalized() {
        let k = RecoveryKey::generate().unwrap();
        let shown = k.display();
        let messy = shown
            .expose()
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        assert_eq!(RecoveryKey::parse(&messy).unwrap().ikm(), k.ikm());
        for (i, g) in shown.expose().split('-').enumerate() {
            assert!(k.group_matches(i as u32, g));
        }
        assert!(!k.group_matches(0, "ZZZZZ"));
        assert!(!k.group_matches(9, "0000"));
        assert!(!k.group_matches(u32::MAX / 8, "0000"));
    }

    proptest! {
        #[test]
        fn typo_is_detected(pos in 0usize..36, delta in 1u8..32) {
            let k = RecoveryKey::generate().unwrap();
            let mut v = k.0.0.clone();
            v[pos] = (v[pos] + delta) % 32;
            prop_assert!(RecoveryKey::parse(format_groups(&v).expose()).is_err());
        }

        #[test]
        fn parsing_never_panics(s in "\\PC{0,60}") {
            let _ = RecoveryKey::parse(&s);
            let _ = MigrationCode::parse(&s);
            let _ = parse_short_code(&s);
        }
    }
}
