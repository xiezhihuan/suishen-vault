//! Argon2id。参数随密库保存，但读取时有硬性上下限，防止被改成弱参数或耗尽内存。

use argon2::{Algorithm, Argon2, Block, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::policy;
use crate::secret::{Key, SecretString};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub(crate) const DEFAULT: Self = Self {
        m_kib: policy::KDF_MIN_M_KIB,
        t: policy::KDF_MIN_T,
        p: policy::KDF_MIN_P,
    };

    pub(crate) fn check(self) -> Result<()> {
        let ok = (policy::KDF_MIN_M_KIB..=policy::KDF_MAX_M_KIB).contains(&self.m_kib)
            && (policy::KDF_MIN_T..=policy::KDF_MAX_T).contains(&self.t)
            && (policy::KDF_MIN_P..=policy::KDF_MAX_P).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParamsRejected)
        }
    }
}

/// 主密码先做 NFC，保证不同系统输入法产生的同一文字得到同一密钥。
pub(crate) fn derive_password_kek(
    password: &SecretString,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<Key> {
    params.check()?;
    let len = password.expose().nfc().map(char::len_utf8).sum();
    let mut pw = Zeroizing::new(String::with_capacity(len));
    pw.extend(password.expose().nfc());
    argon2id(pw.as_bytes(), salt, params)
}

fn argon2id(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::KdfParamsRejected)?;
    let blocks = p.block_count();
    let mut memory: Vec<Block> = Vec::new();
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| Error::OutOfMemory)?;
    memory.resize(blocks, Block::new());
    let mut out = Key::zeroed();
    let r = Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into_with_memory(
        password,
        salt,
        out.bytes_mut(),
        &mut memory,
    );
    memory.iter_mut().for_each(Zeroize::zeroize);
    r.map_err(|_| Error::KdfParamsRejected)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::unhex;

    /// RFC 9106 第 5.3 节（含 secret 与 associated data）。
    #[test]
    fn argon2id_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let mut out = [0; 32];
        Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap()
            .hash_password_into(&[1; 32], &[2; 16], &mut out)
            .unwrap();
        assert_eq!(
            out[..],
            unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")[..]
        );
    }

    /// 参考实现 phc-winner-argon2 的 test.c（v=19, t=2, m=2^16, p=1）。
    #[test]
    fn argon2id_reference_vector_through_our_path() {
        let params = KdfParams {
            m_kib: 65536,
            t: 2,
            p: 1,
        };
        let out = argon2id(b"password", b"somesalt", params).unwrap();
        assert_eq!(
            out.bytes()[..],
            unhex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")[..]
        );
    }

    // AC-KEY-01
    #[test]
    fn params_outside_limits_are_rejected() {
        let d = KdfParams::DEFAULT;
        assert!(d.check().is_ok());
        let max = KdfParams {
            m_kib: 1 << 20,
            t: 20,
            p: 8,
        };
        assert!(max.check().is_ok());
        for bad in [
            KdfParams {
                m_kib: d.m_kib - 1,
                ..d
            },
            KdfParams { t: 2, ..d },
            KdfParams { p: 3, ..d },
            KdfParams {
                m_kib: max.m_kib + 1,
                ..d
            },
            KdfParams { t: 21, ..d },
            KdfParams { p: 9, ..d },
            KdfParams {
                m_kib: 0,
                t: 0,
                p: 0,
            },
            KdfParams {
                m_kib: u32::MAX,
                t: u32::MAX,
                p: u32::MAX,
            },
        ] {
            let r = derive_password_kek(&"假主密码".into(), &[0; 16], bad);
            assert_eq!(r.err(), Some(Error::KdfParamsRejected));
        }
    }

    #[test]
    fn password_is_nfc_normalized() {
        // “é”的两种写法
        let a = derive_password_kek(&"caf\u{e9}-fake-pw".into(), &[0; 16], KdfParams::DEFAULT);
        let b = derive_password_kek(&"cafe\u{301}-fake-pw".into(), &[0; 16], KdfParams::DEFAULT);
        assert_eq!(a.unwrap().bytes(), b.unwrap().bytes());
    }
}
