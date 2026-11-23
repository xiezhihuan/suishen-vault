//! 机密数据的容器：不实现 `Debug`、`Display`、`Serialize`、`Clone`，离开作用域清零。

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// 机密字符串。内部容量可能随来源而变，所以构造后不再修改，避免重新分配留下残片。
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// 取出明文。调用方负责不打印、不写日志。
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 显式复制，代码审查时容易看见。
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn ct_eq(&self, other: &str) -> bool {
        self.0.as_bytes().ct_eq(other.as_bytes()).into()
    }

    pub(crate) fn from_utf8(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        // 先校验再复制，失败时不会把明文放进错误值里
        std::str::from_utf8(&bytes)
            .map(|s| Self(s.to_owned()))
            .map_err(|_| Error::Tampered)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// 256 位密钥。放在堆上，移动时不会在栈上留下副本。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key(Box<[u8; 32]>);

impl Key {
    pub fn random() -> Result<Self> {
        let mut k = Self::zeroed();
        fill_random(k.bytes_mut())?;
        Ok(k)
    }

    /// 由平台钥匙库取回的设备密钥构造；传入的切片由调用方清零。
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut k = Self::zeroed();
        if bytes.len() != 32 {
            return Err(Error::CodeFormat);
        }
        k.0.copy_from_slice(bytes);
        Ok(k)
    }

    pub(crate) fn zeroed() -> Self {
        Self(Box::new([0; 32]))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// 交给平台钥匙库保存时使用。
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0; N];
    fill_random(&mut a)?;
    Ok(a)
}

/// `0..n` 的均匀随机数（拒绝采样）。
pub(crate) fn random_below(n: u32) -> Result<u32> {
    debug_assert!(n > 0);
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let v = u32::from_le_bytes(random_array()?);
        if v < zone {
            return Ok(v % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 编译期断言类型没有实现某个 trait：若实现了，`some_item` 的推断会有歧义而编译失败。
    macro_rules! assert_not_impl {
        ($t:ty: $($tr:path),+) => {$(
            const _: fn() = || {
                trait Ambiguous<A> { fn some_item() {} }
                impl<T: ?Sized> Ambiguous<()> for T {}
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $tr> Ambiguous<Invalid> for T {}
                let _ = <$t as Ambiguous<_>>::some_item;
            };
        )+};
    }

    // AC-KEY-09
    macro_rules! assert_opaque {
        ($($t:ty),+ $(,)?) => {$(
            assert_not_impl!($t: std::fmt::Debug, std::fmt::Display, serde::Serialize, Clone);
        )+};
    }
    assert_opaque!(
        SecretString,
        Key,
        crate::model::Secrets,
        crate::model::CustomField,
        crate::model::ItemDraft,
        crate::model::Item,
        crate::model::RevealedField,
        crate::crypto::code::RecoveryKey,
        crate::crypto::code::MigrationCode,
    );

    #[test]
    fn zeroize_clears_key_and_string() {
        let mut k = Key::random().unwrap();
        assert_ne!(k.bytes(), &[0; 32]);
        k.zeroize();
        assert_eq!(k.bytes(), &[0; 32]);
        let mut s = SecretString::from("假密码-FAKE");
        s.zeroize();
        assert!(s.is_empty());
    }

    #[test]
    fn random_below_stays_in_range_and_covers() {
        let mut seen = [false; 7];
        for _ in 0..500 {
            seen[random_below(7).unwrap() as usize] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }
}
