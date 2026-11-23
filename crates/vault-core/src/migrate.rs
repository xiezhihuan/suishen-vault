//! 设备迁移。见 `docs/设计.md` 第 8 节。
//!
//! 迁移包 = 备份格式再用一次性迁移码整体加密一层。没有迁移码解不开，
//! 有迁移码但没有主密码（或恢复密钥）也打不开。

use std::path::Path;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::backup::{self, RestoreAuth};
use crate::clock::Clock;
use crate::crypto::aead::{self, Aad, Purpose};
use crate::crypto::code::{MigrationCode, parse_short_code, short_code};
use crate::crypto::hkdf_sha256;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::policy::MAX_PACKAGE_BYTES;
use crate::sealed::{sha256, verify_snapshot};
use crate::secret::{SecretString, random_array};
use crate::store::DeviceState;
use crate::vault::{Auth, Vault};

const MAGIC: &[u8; 8] = b"SVMIGv1\n";
const SALT_LEN: usize = 32;
/// 包在验证前不知道属于哪个密库，外层 AAD 用全零。
const NO_VAULT: [u8; 16] = [0; 16];

fn package_aad(head: &[u8]) -> Aad {
    Aad::new(Purpose::MigrationPackage, &NO_VAULT).part(head)
}

fn wrap_package(code: &MigrationCode, inner: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = random_array()?;
    let head = [&MAGIC[..], &salt].concat();
    let key = hkdf_sha256(code.ikm(), &salt, b"suishen-vault/v1 migration package")?;
    let sealed = aead::seal_raw(&key, package_aad(&head).as_bytes(), inner)?;
    if (head.len() + sealed.len()) as u64 > MAX_PACKAGE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok([head, sealed].concat())
}

/// 完成码：由迁移码派生，并绑定密库与这份迁移包，说明新设备确实拿到并解开了它。
fn completion_code(
    code: &MigrationCode,
    vault_id: &[u8; 16],
    package: &[u8],
) -> Result<SecretString> {
    let key = hkdf_sha256(
        code.ikm(),
        vault_id,
        b"suishen-vault/v1 migration completion",
    )?;
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key.bytes()).map_err(|_| Error::Storage)?;
    mac.update(&sha256(package));
    let d: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(short_code(&d))
}

impl Vault {
    /// 旧设备：重新验证后进入“迁移中”（只读），写出迁移包，返回只显示一次的迁移码。
    ///
    /// 调用方须先关闭服务并撤销全部申请。
    pub fn begin_migration(&mut self, auth: Auth<'_>, package: &Path) -> Result<SecretString> {
        if self.device_state() != DeviceState::Active {
            return Err(Error::ReadOnly);
        }
        self.reauthenticate(auth)?;
        let code = MigrationCode::generate()?;
        let vault_id = self.header().vault_id;
        let bytes = {
            let (snap, keys) = self.snapshot()?;
            verify_snapshot(&snap, keys)?;
            wrap_package(&code, &backup::encode(&snap, &keys.mdk)?)?
        };
        let expected = completion_code(&code, &vault_id, &bytes)?;
        let sealed = aead::seal(
            self.mdk_for_migration()?,
            &Aad::new(Purpose::Migration, &vault_id),
            expected.expose().as_bytes(),
        )?;
        self.set_device_state(DeviceState::Migrating, Some(sealed))?;
        if let Err(e) = fsutil::write_new_atomic(package, &bytes) {
            self.set_device_state(DeviceState::Active, None)?;
            return Err(e);
        }
        Ok(code.display())
    }

    /// 旧设备：取消迁移。若新设备其实已导入成功，会出现两份密库，界面须提示。
    pub fn cancel_migration(&mut self) -> Result<()> {
        if self.device_state() != DeviceState::Migrating {
            return Err(Error::NotMigrating);
        }
        // 需完全解锁
        self.snapshot()?;
        self.set_device_state(DeviceState::Active, None)
    }

    /// 旧设备：输入新设备显示的完成码。正确则停用并清除内存密钥，之后只能清除。
    pub fn confirm_migration(&mut self, completion: &str) -> Result<()> {
        if self.device_state() != DeviceState::Migrating {
            return Err(Error::NotMigrating);
        }
        let sealed = self.header().migration.as_ref().ok_or(Error::Tampered)?;
        let expected = aead::open(
            self.mdk_for_migration()?,
            &Aad::new(Purpose::Migration, &self.header().vault_id),
            sealed,
        )?;
        let expected = SecretString::from_utf8(expected)?;
        let given = parse_short_code(completion).map_err(|_| Error::CompletionMismatch)?;
        if !expected.ct_eq(given.expose()) {
            return Err(Error::CompletionMismatch);
        }
        self.set_device_state(DeviceState::Retired, None)?;
        self.lock(crate::vault::LockMode::Full);
        Ok(())
    }
}

/// 新设备上的导入结果。
pub struct Imported {
    /// 已打开、处于锁定状态的新密库。
    pub vault: Vault,
    pub items: usize,
    /// 让用户在旧设备上输入的完成码。
    pub completion_code: SecretString,
}

/// 新设备：导入迁移包。逐条校验并写入成功后才给出完成码。AC-MIG-03
pub fn import_migration(
    package: &Path,
    code: &MigrationCode,
    auth: RestoreAuth<'_>,
    dest: &Path,
    clock: Arc<dyn Clock>,
) -> Result<Imported> {
    let bytes = fsutil::read_limited(package, MAX_PACKAGE_BYTES)?;
    let inner = {
        let head_len = MAGIC.len() + SALT_LEN;
        if bytes.len() < head_len || &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::Tampered);
        }
        let (head, sealed) = bytes.split_at(head_len);
        let key = hkdf_sha256(
            code.ikm(),
            &head[MAGIC.len()..],
            b"suishen-vault/v1 migration package",
        )?;
        aead::open_raw(&key, package_aad(head).as_bytes(), sealed)
            .map_err(|_| Error::UnlockFailed)?
    };
    let (snap, keys) = backup::decode(&inner, auth)?;
    let completion_code = completion_code(code, &snap.vault_id, &bytes)?;
    backup::install(&snap, &keys, dest)?;
    Ok(Imported {
        vault: Vault::open_with_clock(dest, clock)?,
        items: snap.items.len(),
        completion_code,
    })
}
