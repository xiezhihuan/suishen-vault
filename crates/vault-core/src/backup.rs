//! 加密备份 `.svbak`。
//!
//! 头部明文只有：格式、vault_id、纪元、主密码槽与恢复槽（都是包裹密文）。
//! 条目部分用由 MDK 派生的密钥整体再加密一次，连条目数量都看不出来，
//! AAD 为整个头部，任何一个字节被改动都会拒绝恢复。

use std::path::Path;

use crate::codec::{Reader, Writer};
use crate::crypto::aead::{self, Aad, Purpose};
use crate::crypto::code::RecoveryKey;
use crate::crypto::hkdf_sha256;
use crate::crypto::wrap::{DataKeys, Input, KdfSpec, KeySlot, SlotKind, WRAPPED_LEN};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::model::ItemId;
use crate::policy::{FORMAT_VERSION, MAX_PACKAGE_BYTES};
use crate::sealed::{ManifestBody, open_entries, verify_snapshot};
use crate::secret::{Key, SecretString, random_array};
use crate::store::{DeviceState, Manifest, RawField, RawItem, Snapshot, Store};
use crate::vault::Vault;

const MAGIC: &[u8; 8] = b"SVBAKv1\n";
/// 条目部分补齐到此大小，隐藏精确长度。
const BODY_PAD: usize = 16 * 1024;

/// 打开备份或迁移包时的凭据。
#[derive(Clone, Copy)]
pub enum RestoreAuth<'a> {
    Password(&'a SecretString),
    /// 用恢复密钥恢复后，仍须走“恢复密钥重设主密码”流程才能进入密库。
    Recovery(&'a RecoveryKey),
}

impl<'a> RestoreAuth<'a> {
    fn input(self) -> Input<'a> {
        match self {
            Self::Password(p) => Input::Password(p),
            Self::Recovery(r) => Input::Recovery(r),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreReport {
    pub items: usize,
}

impl Vault {
    /// 写出备份。需完全解锁；目标已存在时拒绝。
    pub fn export_backup(&self, dest: &Path) -> Result<()> {
        let (snap, keys) = self.snapshot()?;
        // 写之前先确认快照完好，避免把坏数据当备份
        verify_snapshot(&snap, keys)?;
        fsutil::write_new_atomic(dest, &encode(&snap, &keys.mdk)?)
    }
}

/// 把备份恢复成新的密库文件。目标已存在时拒绝，因此失败不会影响现有数据。AC-BAK-02
///
/// 恢复后原设备上的密库可能仍可使用，界面须提示（AC-BAK-03）。
pub fn restore_backup(backup: &Path, dest: &Path, auth: RestoreAuth<'_>) -> Result<RestoreReport> {
    let bytes = fsutil::read_limited(backup, MAX_PACKAGE_BYTES)?;
    let (snap, keys) = decode(&bytes, auth)?;
    let items = snap.items.len();
    install(&snap, &keys, dest)?;
    Ok(RestoreReport { items })
}

/// 以“活跃、纪元加一”的身份写成新库。
pub(crate) fn install(snap: &Snapshot, keys: &DataKeys, dest: &Path) -> Result<()> {
    let epoch = snap.epoch.checked_add(1).ok_or(Error::Tampered)?;
    let generation = snap
        .manifest
        .generation
        .checked_add(1)
        .ok_or(Error::Tampered)?;
    let entries = open_entries(
        &snap.vault_id,
        &keys.mdk,
        snap.items.iter().map(|i| (i.id, i.rev, &i.blob[..])),
    )?;
    let manifest = ManifestBody::compute(
        epoch,
        DeviceState::Active,
        &snap.slots,
        entries.iter().map(|(id, e)| (*id, e.rev, e.digest)),
    )
    .seal(&snap.vault_id, &keys.mdk, generation)?;
    let fresh = Snapshot {
        epoch,
        manifest,
        ..snap.clone()
    };
    let store = Store::create(dest, &fresh)?;
    // 回读核对：写到磁盘上的必须与校验过的一致
    let r = store
        .snapshot()
        .and_then(|back| verify_snapshot(&back, keys));
    if let Err(e) = r {
        let path = store.close()?;
        fsutil::overwrite_and_remove(&path)?;
        return Err(e);
    }
    Ok(())
}

fn body_key(mdk: &Key, salt: &[u8; 32]) -> Result<Key> {
    hkdf_sha256(mdk.bytes(), salt, b"suishen-vault/v1 backup body")
}

pub(crate) fn encode(snap: &Snapshot, mdk: &Key) -> Result<Vec<u8>> {
    let mut head = Writer::with_capacity(512);
    head.raw(MAGIC);
    head.u32(FORMAT_VERSION);
    head.raw(&snap.vault_id);
    head.u64(snap.epoch);
    head.len(snap.slots.len())?;
    for s in &snap.slots {
        head.u8(s.kind as u8);
        s.kdf.to_ints().iter().for_each(|v| head.u32(*v));
        head.raw(&s.salt);
        head.raw(&s.wrapped_mdk);
        head.raw(&s.wrapped_sdk);
    }
    let salt: [u8; 32] = random_array()?;
    head.raw(&salt);
    let head = head.finish();

    let mut body = Writer::with_capacity(1024);
    body.u64(snap.manifest.generation);
    body.bytes(&snap.manifest.blob)?;
    body.len(snap.items.len())?;
    for i in &snap.items {
        body.raw(&i.id.0);
        body.u64(i.rev);
        body.bytes(&i.blob)?;
        body.len(i.fields.len())?;
        for f in &i.fields {
            body.raw(&f.id);
            body.u64(f.rev);
            body.bytes(&f.blob)?;
        }
    }
    let padded = aead::pad(&body.finish(), BODY_PAD)?;
    let sealed = aead::seal_raw(
        &body_key(mdk, &salt)?,
        body_aad(snap, &head).as_bytes(),
        &padded,
    )?;
    if (head.len() + sealed.len()) as u64 > MAX_PACKAGE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok([&head[..], &sealed].concat())
}

fn body_aad(snap: &Snapshot, head: &[u8]) -> Aad {
    Aad::new(Purpose::Backup, &snap.vault_id).part(head)
}

/// 解析、解锁并逐条校验。
pub(crate) fn decode(bytes: &[u8], auth: RestoreAuth<'_>) -> Result<(Snapshot, DataKeys)> {
    let mut r = Reader::new(bytes);
    if &r.array::<8>()? != MAGIC {
        return Err(Error::Tampered);
    }
    if r.u32()? != FORMAT_VERSION {
        return Err(Error::UnsupportedFormat);
    }
    let vault_id = r.array()?;
    let epoch = r.u64()?;
    let n = r.count(1 + 16 + 16 + 2 * WRAPPED_LEN)?;
    if n != 2 {
        return Err(Error::Tampered);
    }
    let mut slots: Vec<KeySlot> = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = SlotKind::from_u8(r.u8()?)
            .filter(|k| *k != SlotKind::Device)
            .ok_or(Error::Tampered)?;
        let slot = KeySlot {
            kind,
            kdf: KdfSpec::from_ints([r.u32()?, r.u32()?, r.u32()?, r.u32()?])?,
            salt: r.array()?,
            wrapped_mdk: r.array::<WRAPPED_LEN>()?.to_vec(),
            wrapped_sdk: r.array::<WRAPPED_LEN>()?.to_vec(),
        };
        slot.check_params()?;
        if slots.iter().any(|s| s.kind == kind) {
            return Err(Error::Tampered);
        }
        slots.push(slot);
    }
    let salt: [u8; 32] = r.array()?;
    let head = &bytes[..bytes.len() - r.remaining_len()];

    let input = auth.input();
    let slot = slots
        .iter()
        .find(|s| s.kind == input.kind())
        .ok_or(Error::UnlockFailed)?;
    let keys = slot.unwrap_keys(&vault_id, &slot.kek(&input)?)?;

    let mut snap = Snapshot {
        vault_id,
        epoch,
        slots: slots.clone(),
        manifest: Manifest {
            generation: 0,
            blob: Vec::new(),
        },
        items: Vec::new(),
    };
    let padded = aead::open_raw(
        &body_key(&keys.mdk, &salt)?,
        body_aad(&snap, head).as_bytes(),
        r.rest(),
    )?;
    let body = aead::unpad(&padded)?;
    let mut b = Reader::new(&body);
    snap.manifest = Manifest {
        generation: b.u64()?,
        blob: b.bytes()?.to_vec(),
    };
    let n = b.count(16 + 8 + 4 + 4)?;
    for _ in 0..n {
        let id = ItemId(b.array()?);
        let rev = b.u64()?;
        let blob = b.bytes()?.to_vec();
        let m = b.count(16 + 8 + 4)?;
        let mut fields = Vec::with_capacity(m);
        for _ in 0..m {
            fields.push(RawField {
                id: b.array()?,
                rev: b.u64()?,
                blob: b.bytes()?.to_vec(),
            });
        }
        snap.items.push(RawItem {
            id,
            rev,
            blob,
            fields,
        });
    }
    b.finish()?;
    verify_snapshot(&snap, &keys)?;
    Ok((snap, keys))
}
