//! 密钥槽：每种解锁方式各自包裹 MDK 与 SDK，两份密文相互独立。

use crate::crypto::aead::{self, Aad, NONCE_LEN, Purpose, TAG_LEN};
use crate::crypto::code::RecoveryKey;
use crate::crypto::hkdf_sha256;
use crate::crypto::kdf::{KdfParams, derive_password_kek};
use crate::error::{Error, Result};
use crate::policy::FORMAT_VERSION;
use crate::secret::{Key, SecretString, random_array};

pub(crate) const WRAPPED_LEN: usize = NONCE_LEN + 32 + TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum SlotKind {
    Password = 1,
    Recovery = 2,
    /// 系统钥匙库中、由生物识别保护的密钥。不进入备份与迁移包。
    Device = 3,
}

impl SlotKind {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        [Self::Password, Self::Recovery, Self::Device]
            .into_iter()
            .find(|k| *k as u8 == v)
    }
}

/// 派生方式：主密码用 Argon2id，另两种的输入已是高熵随机值，用 HKDF-SHA256。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfSpec {
    Argon2id(KdfParams),
    HkdfSha256,
}

impl KdfSpec {
    pub(crate) fn to_ints(self) -> [u32; 4] {
        match self {
            Self::Argon2id(p) => [1, p.m_kib, p.t, p.p],
            Self::HkdfSha256 => [2, 0, 0, 0],
        }
    }

    pub(crate) fn from_ints(v: [u32; 4]) -> Result<Self> {
        match v {
            [1, m_kib, t, p] => Ok(Self::Argon2id(KdfParams { m_kib, t, p })),
            [2, 0, 0, 0] => Ok(Self::HkdfSha256),
            _ => Err(Error::KdfParamsRejected),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeySlot {
    pub kind: SlotKind,
    pub kdf: KdfSpec,
    pub salt: [u8; 16],
    pub wrapped_mdk: Vec<u8>,
    pub wrapped_sdk: Vec<u8>,
}

/// 密库的两把数据密钥。
pub(crate) struct DataKeys {
    pub mdk: Key,
    pub sdk: Key,
}

impl DataKeys {
    pub(crate) fn random() -> Result<Self> {
        Ok(Self {
            mdk: Key::random()?,
            sdk: Key::random()?,
        })
    }
}

/// 解锁用的输入。
pub(crate) enum Input<'a> {
    Password(&'a SecretString),
    Recovery(&'a RecoveryKey),
    Device(&'a Key),
}

impl Input<'_> {
    pub(crate) fn kind(&self) -> SlotKind {
        match self {
            Self::Password(_) => SlotKind::Password,
            Self::Recovery(_) => SlotKind::Recovery,
            Self::Device(_) => SlotKind::Device,
        }
    }

    fn default_kdf(&self) -> KdfSpec {
        match self {
            Self::Password(_) => KdfSpec::Argon2id(KdfParams::DEFAULT),
            _ => KdfSpec::HkdfSha256,
        }
    }

    fn kek(&self, kdf: KdfSpec, salt: &[u8; 16]) -> Result<Key> {
        match (self, kdf) {
            (Self::Password(p), KdfSpec::Argon2id(params)) => derive_password_kek(p, salt, params),
            (Self::Recovery(r), KdfSpec::HkdfSha256) => {
                hkdf_sha256(r.ikm(), salt, b"suishen-vault/v1 kek recovery")
            }
            (Self::Device(k), KdfSpec::HkdfSha256) => {
                hkdf_sha256(k.bytes(), salt, b"suishen-vault/v1 kek device")
            }
            // 主密码槽被改成 HKDF 属于降级
            _ => Err(Error::KdfParamsRejected),
        }
    }
}

fn wrap_aad(purpose: Purpose, vault_id: &[u8; 16], slot: &KeySlotHead<'_>) -> Aad {
    let mut aad = Aad::new(purpose, vault_id)
        .int(u64::from(FORMAT_VERSION))
        .part(&[slot.kind as u8])
        .part(slot.salt);
    for v in slot.kdf.to_ints() {
        aad = aad.int(u64::from(v));
    }
    aad
}

struct KeySlotHead<'a> {
    kind: SlotKind,
    kdf: KdfSpec,
    salt: &'a [u8; 16],
}

impl KeySlot {
    pub(crate) fn create(vault_id: &[u8; 16], input: &Input<'_>, keys: &DataKeys) -> Result<Self> {
        let salt: [u8; 16] = random_array()?;
        let head = KeySlotHead {
            kind: input.kind(),
            kdf: input.default_kdf(),
            salt: &salt,
        };
        let kek = input.kek(head.kdf, &salt)?;
        let wrap = |purpose, key: &Key| {
            aead::seal_raw(
                &kek,
                wrap_aad(purpose, vault_id, &head).as_bytes(),
                key.bytes(),
            )
        };
        Ok(Self {
            kind: head.kind,
            kdf: head.kdf,
            wrapped_mdk: wrap(Purpose::WrapMetaKey, &keys.mdk)?,
            wrapped_sdk: wrap(Purpose::WrapSecretKey, &keys.sdk)?,
            salt,
        })
    }

    /// 派生 KEK。参数不合格时在运行 KDF 之前返回错误。
    pub(crate) fn kek(&self, input: &Input<'_>) -> Result<Key> {
        if input.kind() != self.kind {
            return Err(Error::UnlockFailed);
        }
        input.kek(self.kdf, &self.salt)
    }

    pub(crate) fn check_params(&self) -> Result<()> {
        match (self.kind, self.kdf) {
            (SlotKind::Password, KdfSpec::Argon2id(p)) => p.check(),
            (SlotKind::Recovery | SlotKind::Device, KdfSpec::HkdfSha256) => Ok(()),
            _ => Err(Error::KdfParamsRejected),
        }
    }

    fn unwrap(&self, vault_id: &[u8; 16], kek: &Key, purpose: Purpose) -> Result<Key> {
        let blob = match purpose {
            Purpose::WrapMetaKey => &self.wrapped_mdk,
            _ => &self.wrapped_sdk,
        };
        let head = KeySlotHead {
            kind: self.kind,
            kdf: self.kdf,
            salt: &self.salt,
        };
        let plain = aead::open_raw(kek, wrap_aad(purpose, vault_id, &head).as_bytes(), blob)
            .map_err(|_| Error::UnlockFailed)?;
        Key::from_slice(&plain).map_err(|_| Error::UnlockFailed)
    }

    pub(crate) fn unwrap_keys(&self, vault_id: &[u8; 16], kek: &Key) -> Result<DataKeys> {
        Ok(DataKeys {
            mdk: self.unwrap(vault_id, kek, Purpose::WrapMetaKey)?,
            sdk: self.unwrap(vault_id, kek, Purpose::WrapSecretKey)?,
        })
    }

    /// 只取机密密钥，用于批准授权。
    pub(crate) fn unwrap_secret_key(&self, vault_id: &[u8; 16], kek: &Key) -> Result<Key> {
        self.unwrap(vault_id, kek, Purpose::WrapSecretKey)
    }
}
