//! 动态口令（RFC 6238）。只在本机完全解锁时使用，不向 AI 提供。

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SecretString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

pub(crate) struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algo: Algo,
    digits: u32,
    period: u64,
}

/// 一次动态口令。
pub struct TotpCode {
    pub code: SecretString,
    /// 还有多少秒失效。
    pub remaining_secs: u64,
}

impl Totp {
    /// 接受 Base32 种子（允许空格、连字符、小写）或 `otpauth://totp/...` 链接。
    pub(crate) fn parse(input: &SecretString) -> Result<Self> {
        let s = input.expose().trim();
        if !s
            .get(..10)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
        {
            return Self::build(base32(s)?, Algo::Sha1, 6, 30);
        }
        let rest = &s[10..];
        let (authority, path) = rest.split_once('/').ok_or(Error::InvalidTotp)?;
        if !authority.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidTotp);
        }
        let (mut secret, mut algo, mut digits, mut period) = (None, Algo::Sha1, 6, 30);
        let (_, query) = path
            .split('#')
            .next()
            .and_then(|p| p.split_once('?'))
            .ok_or(Error::InvalidTotp)?;
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let v = Zeroizing::new(v.into_owned());
            match &*k {
                "secret" => secret = Some(base32(&v)?),
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algo::Sha1,
                        "SHA256" => Algo::Sha256,
                        "SHA512" => Algo::Sha512,
                        _ => return Err(Error::InvalidTotp),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| Error::InvalidTotp)?,
                "period" => period = v.parse().map_err(|_| Error::InvalidTotp)?,
                _ => {}
            }
        }
        Self::build(secret.ok_or(Error::InvalidTotp)?, algo, digits, period)
    }

    fn build(secret: Zeroizing<Vec<u8>>, algo: Algo, digits: u32, period: u64) -> Result<Self> {
        if secret.is_empty() || !(6..=8).contains(&digits) || !(1..=300).contains(&period) {
            return Err(Error::InvalidTotp);
        }
        Ok(Self {
            secret,
            algo,
            digits,
            period,
        })
    }

    pub(crate) fn at(&self, unix_secs: u64) -> Result<TotpCode> {
        let counter = (unix_secs / self.period).to_be_bytes();
        let mac = match self.algo {
            Algo::Sha1 => mac::<Hmac<Sha1>>(&self.secret, &counter)?,
            Algo::Sha256 => mac::<Hmac<Sha256>>(&self.secret, &counter)?,
            Algo::Sha512 => mac::<Hmac<Sha512>>(&self.secret, &counter)?,
        };
        let off = usize::from(mac[mac.len() - 1] & 15);
        let four: [u8; 4] = mac
            .get(off..off + 4)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::InvalidTotp)?;
        let n = (u32::from_be_bytes(four) & 0x7fff_ffff) % 10u32.pow(self.digits);
        Ok(TotpCode {
            code: SecretString::new(format!("{n:0w$}", w = self.digits as usize)),
            remaining_secs: self.period - unix_secs % self.period,
        })
    }
}

fn mac<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidTotp)?;
    m.update(msg);
    Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
}

/// RFC 4648 Base32，忽略空格、连字符与填充。
fn base32(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8 + 1));
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').chars() {
        let v = match c.to_ascii_uppercase() {
            ' ' | '-' => continue,
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(Error::InvalidTotp),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B。
    #[test]
    fn rfc6238_vectors() {
        let make = |secret: &[u8], algo| {
            Totp::build(Zeroizing::new(secret.to_vec()), algo, 8, 30).unwrap()
        };
        let s = b"1234567890".repeat(7);
        let (a, b, c) = (
            make(&s[..20], Algo::Sha1),
            make(&s[..32], Algo::Sha256),
            make(&s[..64], Algo::Sha512),
        );
        for (t, x, y, z) in [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(a.at(t).unwrap().code.expose(), x);
            assert_eq!(b.at(t).unwrap().code.expose(), y);
            assert_eq!(c.at(t).unwrap().code.expose(), z);
        }
    }

    #[test]
    fn parses_seed_and_uri() {
        // RFC 6238 的 SHA1 种子，Base32 形式
        let seed = "gezd gnbv gy3t qojq-GEZDGNBVGY3TQOJQ";
        let t = Totp::parse(&seed.into()).unwrap();
        assert_eq!(t.at(59).unwrap().code.expose(), "287082");
        assert_eq!(t.at(59).unwrap().remaining_secs, 1);
        let uri = "otpauth://totp/Fake:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        let t = Totp::parse(&uri.into()).unwrap();
        assert_eq!(t.at(59).unwrap().code.expose(), "94287082");
        for bad in [
            "",
            "0189!",
            "otpauth://hotp/x?secret=GEZDGNBV",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=GEZDGNBV&digits=20",
            "otpauth://totp/x?secret=GEZDGNBV&period=0",
        ] {
            assert!(Totp::parse(&bad.into()).is_err(), "{bad}");
        }
    }
}
