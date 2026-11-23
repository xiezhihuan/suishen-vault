//! 条目与清单的加解密、校验。
//!
//! 完整性链：清单（MDK 加密）固定每条的 rev 与元数据密文摘要；元数据密文里又固定该条
//! 每个机密字段的 rev 与密文摘要。所以交换、回滚、删除、插入任何单行都会被发现。

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::crypto::aead::{self, Aad, Purpose};
use crate::crypto::wrap::{DataKeys, KeySlot, SlotKind};
use crate::error::{Error, Result};
use crate::model::{FieldKind, FieldRef, ItemId, MetaRecord, Prepared, Secrets, hex, unhex};
use crate::search::MetaIndex;
use crate::secret::{Key, random_array};
use crate::store::{DeviceState, Manifest, RawField, RawItem, Snapshot};
use crate::vault::Entry;

pub(crate) fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn meta_aad(vault_id: &[u8; 16], id: ItemId, rev: u64) -> Aad {
    Aad::new(Purpose::ItemMeta, vault_id).part(&id.0).int(rev)
}

fn field_aad(vault_id: &[u8; 16], id: ItemId, field: &[u8; 16], kind: FieldKind, rev: u64) -> Aad {
    Aad::new(Purpose::ItemField, vault_id)
        .part(&id.0)
        .part(field)
        .part(&[kind as u8])
        .int(rev)
}

pub(crate) fn seal_meta(
    vault_id: &[u8; 16],
    mdk: &Key,
    id: ItemId,
    rev: u64,
    record: &MetaRecord,
) -> Result<Vec<u8>> {
    let json = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error::Storage)?);
    aead::seal(mdk, &meta_aad(vault_id, id, rev), &json)
}

fn open_meta(
    vault_id: &[u8; 16],
    mdk: &Key,
    id: ItemId,
    rev: u64,
    blob: &[u8],
) -> Result<MetaRecord> {
    let json = aead::open(mdk, &meta_aad(vault_id, id, rev), blob)?;
    serde_json::from_slice(&json).map_err(|_| Error::Tampered)
}

/// 加密一条：先加密各字段，再把它们的摘要写进元数据。
pub(crate) fn seal_item(
    vault_id: &[u8; 16],
    keys: &DataKeys,
    id: ItemId,
    rev: u64,
    p: Prepared,
) -> Result<(RawItem, MetaRecord)> {
    let mut record = p.record;
    let mut fields = Vec::with_capacity(p.fields.len());
    for f in p.fields {
        let fid: [u8; 16] = random_array()?;
        let blob = aead::seal(
            &keys.sdk,
            &field_aad(vault_id, id, &fid, f.kind, rev),
            &f.plain,
        )?;
        record.fields.push(FieldRef {
            kind: f.kind as u8,
            id: hex(&fid),
            rev,
            digest: hex(&sha256(&blob)),
        });
        fields.push(RawField { id: fid, rev, blob });
    }
    // 顺序打乱，库里看不出字段种类
    fields.sort_by_key(|f| f.id);
    let blob = seal_meta(vault_id, &keys.mdk, id, rev, &record)?;
    Ok((
        RawItem {
            id,
            rev,
            blob,
            fields,
        },
        record,
    ))
}

impl FieldRef {
    pub(crate) fn kind(&self) -> Result<FieldKind> {
        FieldKind::from_u8(self.kind).ok_or(Error::Tampered)
    }

    pub(crate) fn id(&self) -> Result<[u8; 16]> {
        unhex(&self.id).ok_or(Error::Tampered)
    }

    /// 解密一个字段的密文行。
    pub(crate) fn open(
        &self,
        vault_id: &[u8; 16],
        sdk: &Key,
        item: ItemId,
        rev: u64,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let digest: [u8; 32] = unhex(&self.digest).ok_or(Error::Tampered)?;
        if rev != self.rev || !bool::from(digest.ct_eq(&sha256(blob))) {
            return Err(Error::Tampered);
        }
        aead::open(
            sdk,
            &field_aad(vault_id, item, &self.id()?, self.kind()?, rev),
            blob,
        )
    }
}

pub(crate) fn open_entries<'a>(
    vault_id: &[u8; 16],
    mdk: &Key,
    rows: impl Iterator<Item = (ItemId, u64, &'a [u8])>,
) -> Result<BTreeMap<ItemId, Entry>> {
    let mut out = BTreeMap::new();
    for (id, rev, blob) in rows {
        let record = open_meta(vault_id, mdk, id, rev, blob)?;
        let entry = Entry {
            rev,
            digest: sha256(blob),
            index: MetaIndex::new(&record),
            record,
        };
        if out.insert(id, entry).is_some() {
            return Err(Error::Tampered);
        }
    }
    Ok(out)
}

/// 清单内容。
pub(crate) struct ManifestBody {
    pub epoch: u64,
    pub state: DeviceState,
    pub items: [u8; 32],
    pub count: u64,
    pub slots: [u8; 32],
}

impl ManifestBody {
    pub(crate) fn compute(
        epoch: u64,
        state: DeviceState,
        slots: &[KeySlot],
        items: impl Iterator<Item = (ItemId, u64, [u8; 32])>,
    ) -> Self {
        let mut h = Sha256::new();
        let mut count = 0;
        for (id, rev, digest) in items {
            h.update(id.0);
            h.update(rev.to_be_bytes());
            h.update(digest);
            count += 1;
        }
        Self {
            epoch,
            state,
            items: h.finalize().into(),
            count,
            slots: slots_digest(slots),
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::with_capacity(96);
        w.u64(self.epoch);
        w.u8(self.state as u8);
        w.u64(self.count);
        w.raw(&self.items);
        w.raw(&self.slots);
        w.finish()
    }

    pub(crate) fn seal(&self, vault_id: &[u8; 16], mdk: &Key, generation: u64) -> Result<Manifest> {
        let aad = Aad::new(Purpose::Manifest, vault_id).int(generation);
        Ok(Manifest {
            generation,
            blob: aead::seal(mdk, &aad, &self.encode())?,
        })
    }

    /// 与落盘的清单逐字节核对。
    pub(crate) fn verify(&self, vault_id: &[u8; 16], mdk: &Key, m: &Manifest) -> Result<()> {
        let aad = Aad::new(Purpose::Manifest, vault_id).int(m.generation);
        let plain = aead::open(mdk, &aad, &m.blob)?;
        if bool::from(plain.ct_eq(&self.encode())) {
            Ok(())
        } else {
            Err(Error::Tampered)
        }
    }

    /// 只读出记录的设备状态，用于发现明文状态被改动。
    pub(crate) fn recorded_state(
        vault_id: &[u8; 16],
        mdk: &Key,
        m: &Manifest,
    ) -> Result<DeviceState> {
        let aad = Aad::new(Purpose::Manifest, vault_id).int(m.generation);
        let plain = aead::open(mdk, &aad, &m.blob)?;
        let mut r = Reader::new(&plain);
        r.u64()?;
        DeviceState::from_u8(r.u8()?).ok_or(Error::Tampered)
    }
}

/// 设备槽绑定本机且不随备份走，不计入。
fn slots_digest(slots: &[KeySlot]) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in slots.iter().filter(|s| s.kind != SlotKind::Device) {
        h.update([s.kind as u8]);
        s.kdf
            .to_ints()
            .iter()
            .for_each(|v| h.update(v.to_be_bytes()));
        h.update(s.salt);
        h.update(sha256(&s.wrapped_mdk));
        h.update(sha256(&s.wrapped_sdk));
    }
    h.finalize().into()
}

/// 逐条逐字段解密校验整个快照。任何一处不符都拒绝。
pub(crate) fn verify_snapshot(snap: &Snapshot, keys: &DataKeys) -> Result<DeviceState> {
    let vid = &snap.vault_id;
    let entries = open_entries(
        vid,
        &keys.mdk,
        snap.items.iter().map(|i| (i.id, i.rev, &i.blob[..])),
    )?;
    let state = ManifestBody::recorded_state(vid, &keys.mdk, &snap.manifest)?;
    ManifestBody::compute(
        snap.epoch,
        state,
        &snap.slots,
        entries.iter().map(|(id, e)| (*id, e.rev, e.digest)),
    )
    .verify(vid, &keys.mdk, &snap.manifest)?;
    for item in &snap.items {
        let refs = &entries.get(&item.id).ok_or(Error::Tampered)?.record.fields;
        if refs.len() != item.fields.len() {
            return Err(Error::Tampered);
        }
        let mut probe = Secrets::default();
        for fr in refs {
            let fid = fr.id()?;
            let raw = item
                .fields
                .iter()
                .find(|f| f.id == fid)
                .ok_or(Error::Tampered)?;
            // 不仅能解密，内容也要能解析
            probe.set(
                fr.kind()?,
                fr.open(vid, &keys.sdk, item.id, raw.rev, &raw.blob)?,
            )?;
        }
    }
    Ok(state)
}

/// 单独验证每一层，不依赖外层清单掩护。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemDraft, ItemKind};

    const VID: [u8; 16] = [9; 16];
    const A: ItemId = ItemId([1; 16]);
    const B: ItemId = ItemId([2; 16]);

    fn sealed(keys: &DataKeys) -> (RawItem, MetaRecord) {
        let mut d = ItemDraft::new(ItemKind::Login, "标题");
        d.secrets.username = Some("fakeuser".into());
        d.secrets.password = Some("Fake-Pw-1".into());
        seal_item(&VID, keys, A, 3, d.prepare(0, 0).unwrap()).unwrap()
    }

    // AC-KEY-03
    #[test]
    fn metadata_is_bound_to_item_rev_vault_and_key() {
        let k = DataKeys::random().unwrap();
        let (raw, _) = sealed(&k);
        assert!(open_meta(&VID, &k.mdk, A, 3, &raw.blob).is_ok());
        assert!(open_meta(&VID, &k.mdk, B, 3, &raw.blob).is_err());
        assert!(open_meta(&VID, &k.mdk, A, 2, &raw.blob).is_err());
        assert!(open_meta(&[8; 16], &k.mdk, A, 3, &raw.blob).is_err());
        assert!(open_meta(&VID, &k.sdk, A, 3, &raw.blob).is_err());
    }

    // AC-KEY-02、AC-KEY-03
    #[test]
    fn fields_are_bound_to_everything_and_need_the_secret_key() {
        let k = DataKeys::random().unwrap();
        let (raw, rec) = sealed(&k);
        let pick = |fr: &FieldRef| {
            let id = fr.id().unwrap();
            raw.fields.iter().find(|f| f.id == id).unwrap().blob.clone()
        };
        let (u, p) = (&rec.fields[0], &rec.fields[1]);
        let open = |fr: &FieldRef, key: &Key, item, rev, blob: &[u8]| {
            fr.open(&VID, key, item, rev, blob).map(|x| x.to_vec())
        };
        assert_eq!(open(p, &k.sdk, A, 3, &pick(p)).unwrap(), b"Fake-Pw-1");
        // 只有元数据密钥时一律失败
        assert!(open(u, &k.mdk, A, 3, &pick(u)).is_err());
        assert!(open(p, &k.mdk, A, 3, &pick(p)).is_err());
        assert!(open(p, &k.sdk, B, 3, &pick(p)).is_err());
        assert!(open(p, &k.sdk, A, 2, &pick(p)).is_err());
        // 即使把摘要也改成对得上，AAD 仍会拒绝挪位置、改种类、改 rev
        let forge = |f: &dyn Fn(&mut FieldRef)| {
            let mut fr = p.clone();
            f(&mut fr);
            open(&fr, &k.sdk, A, fr.rev, &pick(p))
        };
        assert!(forge(&|_| ()).is_ok());
        assert!(forge(&|f| f.kind = FieldKind::Username as u8).is_err());
        assert!(forge(&|f| f.id = u.id.clone()).is_err());
        assert!(forge(&|f| f.rev = 4).is_err());
    }

    /// 同一位置、同一 rev 的另一份合法密文：AAD 分不出来，靠摘要拒绝。
    #[test]
    fn digest_pins_the_exact_ciphertext() {
        let k = DataKeys::random().unwrap();
        let (_, rec) = sealed(&k);
        let fr = &rec.fields[1];
        let aad = field_aad(&VID, A, &fr.id().unwrap(), FieldKind::Password, 3);
        let other = aead::seal(&k.sdk, &aad, b"Fake-Other").unwrap();
        assert!(aead::open(&k.sdk, &aad, &other).is_ok());
        assert!(fr.open(&VID, &k.sdk, A, 3, &other).is_err());
    }

    #[test]
    fn data_keys_are_independent() {
        let k = DataKeys::random().unwrap();
        assert_ne!(k.mdk.bytes(), k.sdk.bytes());
    }
}
