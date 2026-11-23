//! 密库：创建、解锁、锁定、改密、恢复、条目读写、授权时的重新解锁。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::backoff::Backoff;
use crate::clock::{Clock, SystemClock};
use crate::crypto::code::{RECOVERY_GROUPS, RecoveryKey};
use crate::crypto::wrap::{DataKeys, Input, KeySlot, SlotKind};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::model::{
    AiField, CustomField, FieldKind, Item, ItemDraft, ItemId, ItemMeta, MetaRecord, RevealedField,
    RevealedValue, Secrets, decode_custom,
};
use crate::policy;
use crate::sealed::{self, ManifestBody, open_entries};
use crate::search::ai::RefTable;
use crate::search::query::Query;
use crate::search::{self, AiGateway, LocalHit, MetaIndex, SecretIndex, SecretText, text};
use crate::secret::{Key, SecretString, random_array, random_below};
use crate::store::{self, DeviceState, Header, Manifest, RawField, RawItem, Snapshot, Store};
use crate::strength::check_master_password;
use crate::totp::{Totp, TotpCode};

/// 一条记录在内存中的元数据。
#[derive(Clone)]
pub(crate) struct Entry {
    pub rev: u64,
    /// 元数据密文的 SHA-256。
    pub digest: [u8; 32],
    pub record: MetaRecord,
    pub index: MetaIndex,
}

enum KeyState {
    Locked,
    /// 只有元数据密钥：AI 服务运行、界面锁定。
    Serving(Key),
    Unlocked(DataKeys),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Serving,
    Unlocked,
}

/// 锁定方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// 清除全部密钥。
    Full,
    /// 清除机密密钥，保留元数据密钥供 AI 服务使用。
    KeepServing,
}

/// 日常解锁与授权时的重新解锁。恢复密钥不在其中，它只能用来重设主密码。
#[derive(Clone, Copy)]
pub enum Auth<'a> {
    Password(&'a SecretString),
    /// 由系统钥匙库在生物识别通过后释放的密钥。
    DeviceKey(&'a Key),
}

impl<'a> Auth<'a> {
    fn input(self) -> Input<'a> {
        match self {
            Self::Password(p) => Input::Password(p),
            Self::DeviceKey(k) => Input::Device(k),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListFilter {
    #[default]
    Active,
    Trash,
}

fn challenge() -> Result<[u32; 2]> {
    let a = random_below(RECOVERY_GROUPS)?;
    let b = (a + 1 + random_below(RECOVERY_GROUPS - 1)?) % RECOVERY_GROUPS;
    Ok([a, b])
}

fn confirm(key: &RecoveryKey, challenge: [u32; 2], answers: [&str; 2]) -> Result<()> {
    if challenge
        .iter()
        .zip(answers)
        .all(|(c, a)| key.group_matches(*c, a))
    {
        Ok(())
    } else {
        Err(Error::RecoveryConfirmMismatch)
    }
}

/// 首次设置。核对恢复密钥之前不写任何文件。AC-VLT-01
pub struct Setup {
    vault_id: [u8; 16],
    keys: DataKeys,
    slots: Vec<KeySlot>,
    recovery: RecoveryKey,
    challenge: [u32; 2],
}

impl Setup {
    pub fn begin(password: &SecretString) -> Result<Self> {
        check_master_password(password)?;
        let vault_id = random_array()?;
        let keys = DataKeys::random()?;
        let recovery = RecoveryKey::generate()?;
        Ok(Self {
            vault_id,
            slots: vec![
                KeySlot::create(&vault_id, &Input::Password(password), &keys)?,
                KeySlot::create(&vault_id, &Input::Recovery(&recovery), &keys)?,
            ],
            keys,
            recovery,
            challenge: challenge()?,
        })
    }

    /// 恢复密钥，只在此时显示。
    pub fn recovery_key(&self) -> SecretString {
        self.recovery.display()
    }

    /// 要求用户填回的两组（0 起）。
    pub fn challenge(&self) -> [u32; 2] {
        self.challenge
    }

    /// 可重复核对，答错时保留本次设置。
    pub fn check_answers(&self, answers: [&str; 2]) -> Result<()> {
        confirm(&self.recovery, self.challenge, answers)
    }

    /// 核对通过后写盘，密钥的所有权转入新密库。
    pub fn confirm(self, path: &Path, answers: [&str; 2], clock: Arc<dyn Clock>) -> Result<Vault> {
        self.check_answers(answers)?;
        let manifest =
            ManifestBody::compute(1, DeviceState::Active, &self.slots, std::iter::empty()).seal(
                &self.vault_id,
                &self.keys.mdk,
                1,
            )?;
        let store = Store::create(
            path,
            &Snapshot {
                vault_id: self.vault_id,
                epoch: 1,
                slots: self.slots.clone(),
                manifest,
                items: Vec::new(),
            },
        )?;
        let mut v = Vault::from_store(store, clock)?;
        v.load(self.keys)?;
        Ok(v)
    }
}

/// 恢复密钥验证通过后的凭据，只能用于重设主密码，不能读取条目。
pub struct RecoveryTicket<'a> {
    credential: &'a RecoveryKey,
    session: Arc<()>,
}

/// 待核对的新恢复密钥。包裹密文只留在 Vault 中，锁定会取消本次恢复。
pub struct PendingRecovery {
    session: Arc<()>,
    recovery: RecoveryKey,
    challenge: [u32; 2],
}

#[derive(Default)]
struct RecoverySession {
    id: Option<Arc<()>>,
    slots: Vec<KeySlot>,
}

impl RecoverySession {
    fn start(&mut self, slots: Vec<KeySlot>) -> Arc<()> {
        let id = Arc::new(());
        self.id = Some(id.clone());
        self.slots = slots;
        id
    }

    fn check(&self, id: &Arc<()>) -> Result<()> {
        self.id
            .as_ref()
            .filter(|s| Arc::ptr_eq(s, id))
            .map(|_| ())
            .ok_or(Error::UnlockFailed)
    }
}

impl PendingRecovery {
    pub fn recovery_key(&self) -> SecretString {
        self.recovery.display()
    }

    pub fn challenge(&self) -> [u32; 2] {
        self.challenge
    }
}

pub struct Vault {
    store: Store,
    header: Header,
    clock: Arc<dyn Clock>,
    backoff: Backoff,
    recovery: RecoverySession,
    keys: KeyState,
    entries: BTreeMap<ItemId, Entry>,
    generation: u64,
    refs: RefTable,
    secret_index: Option<SecretIndex>,
}

/// 待写入的一行元数据；字段为 `None` 表示字段行不动。
pub type StoredClient = ([u8; 16], zeroize::Zeroizing<Vec<u8>>);

type RowPut = (ItemId, u64, Vec<u8>, Option<Vec<RawField>>);

/// 一次提交中的改动。
enum Change {
    /// 新增或整条替换。
    Put(RawItem, MetaRecord),
    /// 只改元数据，字段行不动。
    Meta(ItemId, MetaRecord),
    Delete(ItemId),
}

impl Vault {
    /// 打开已有密库，处于锁定状态。
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_clock(path, Arc::new(SystemClock::default()))
    }

    pub fn open_with_clock(path: &Path, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::from_store(Store::open(path)?, clock)
    }

    fn from_store(store: Store, clock: Arc<dyn Clock>) -> Result<Self> {
        let header = store.header()?;
        let backoff = Backoff::from_stored(
            header.fail_count,
            header.fail_at_ms,
            clock.wall_ms(),
            clock.mono_ms(),
        );
        Ok(Self {
            store,
            header,
            clock,
            backoff,
            recovery: RecoverySession::default(),
            keys: KeyState::Locked,
            entries: BTreeMap::new(),
            generation: 0,
            refs: RefTable::default(),
            secret_index: None,
        })
    }

    pub fn path(&self) -> &Path {
        self.store.path()
    }

    pub fn lock_state(&self) -> LockState {
        match self.keys {
            KeyState::Locked => LockState::Locked,
            KeyState::Serving(_) => LockState::Serving,
            KeyState::Unlocked(_) => LockState::Unlocked,
        }
    }

    pub fn device_state(&self) -> DeviceState {
        self.header.state
    }

    /// 还要等多久才能再次尝试解锁，毫秒。
    pub fn backoff_remaining_ms(&self) -> u64 {
        self.backoff.remaining(self.clock.mono_ms())
    }

    pub fn has_device_key(&self) -> bool {
        self.header.slot(SlotKind::Device).is_some()
    }

    // ---- 解锁与锁定 ----

    /// 统一的验证入口：退避、参数检查、先记失败再算、成功清零。
    fn authenticate<T>(
        &mut self,
        input: &Input<'_>,
        unwrap: impl FnOnce(&KeySlot, &[u8; 16], &Key) -> Result<T>,
    ) -> Result<T> {
        if self.header.state == DeviceState::Retired {
            return Err(Error::Retired);
        }
        let wait = self.backoff_remaining_ms();
        if wait > 0 {
            return Err(Error::Backoff(wait));
        }
        let slot = self
            .header
            .slot(input.kind())
            .cloned()
            .ok_or(Error::UnlockFailed)?;
        slot.check_params()?;
        let (old_count, old_at) = (self.header.fail_count, self.header.fail_at_ms);
        self.record_failures(old_count.saturating_add(1), self.clock.wall_ms())?;
        let r = slot
            .kek(input)
            .and_then(|kek| unwrap(&slot, &self.header.vault_id, &kek));
        match &r {
            Ok(_) => self.record_failures(0, 0)?,
            Err(Error::UnlockFailed) => {}
            // 内存不足一类的错误不算用户输错
            Err(_) => self.record_failures(old_count, old_at)?,
        }
        match self.header.fail_count {
            0 => self.backoff.reset(),
            n => self.backoff.failed(n, self.clock.mono_ms()),
        }
        r
    }

    fn record_failures(&mut self, count: u32, at_ms: i64) -> Result<()> {
        self.store.set_failures(count, at_ms)?;
        self.header.fail_count = count;
        self.header.fail_at_ms = at_ms;
        Ok(())
    }

    /// 完全解锁。
    pub fn unlock(&mut self, auth: Auth<'_>) -> Result<()> {
        let keys = self.authenticate(&auth.input(), |s, vid, kek| s.unwrap_keys(vid, kek))?;
        self.load(keys)?;
        if self.header.state == DeviceState::Active {
            self.purge_expired_trash()?;
        }
        Ok(())
    }

    /// 解密元数据并核对清单。失败时保持原状态。
    fn load(&mut self, keys: DataKeys) -> Result<()> {
        let vid = self.header.vault_id;
        let rows = self.store.item_rows()?;
        let manifest = self.store.manifest()?;
        let entries = open_entries(
            &vid,
            &keys.mdk,
            rows.iter().map(|(id, rev, b)| (*id, *rev, &b[..])),
        )?;
        if ManifestBody::recorded_state(&vid, &keys.mdk, &manifest)? == DeviceState::Retired {
            return Err(Error::Retired);
        }
        ManifestBody::compute(
            self.header.epoch,
            self.header.state,
            &self.header.slots,
            entries.iter().map(|(id, e)| (*id, e.rev, e.digest)),
        )
        .verify(&vid, &keys.mdk, &manifest)?;
        self.entries = entries;
        self.generation = manifest.generation;
        self.secret_index = None;
        self.keys = KeyState::Unlocked(keys);
        match self.build_secret_index() {
            Ok(index) => self.secret_index = Some(index),
            Err(error) => {
                self.lock(LockMode::Full);
                return Err(error);
            }
        }
        Ok(())
    }

    /// 锁定。机密密钥与机密索引总是清除。
    pub fn lock(&mut self, mode: LockMode) {
        self.recovery = RecoverySession::default();
        self.secret_index = None;
        let old = std::mem::replace(&mut self.keys, KeyState::Locked);
        if mode == LockMode::KeepServing && self.header.state == DeviceState::Active {
            match old {
                KeyState::Unlocked(k) => self.keys = KeyState::Serving(k.mdk),
                KeyState::Serving(k) => self.keys = KeyState::Serving(k),
                KeyState::Locked => {}
            }
        }
        if matches!(self.keys, KeyState::Locked) {
            self.entries.clear();
            self.refs.clear();
        }
    }

    /// 一键全部关闭时由服务层调用：所有不透明 ID 立即失效。
    pub fn revoke_item_refs(&mut self) {
        self.refs.clear();
    }

    fn data_keys(&self) -> Result<&DataKeys> {
        match &self.keys {
            KeyState::Unlocked(k) => Ok(k),
            _ => Err(Error::Locked),
        }
    }

    fn mdk(&self) -> Result<&Key> {
        match &self.keys {
            KeyState::Unlocked(k) => Ok(&k.mdk),
            KeyState::Serving(k) => Ok(k),
            KeyState::Locked => Err(Error::Locked),
        }
    }

    fn active(&self) -> Result<()> {
        match self.header.state {
            DeviceState::Active => Ok(()),
            DeviceState::Migrating => Err(Error::ReadOnly),
            DeviceState::Retired => Err(Error::Retired),
        }
    }

    pub(super) fn writable(&self) -> Result<&DataKeys> {
        let k = self.data_keys()?;
        self.active()?;
        Ok(k)
    }

    // ---- 主密码、恢复密钥、设备密钥 ----

    /// 改主密码。数据密钥不变，条目不重新加密。AC-KEY-08
    pub fn change_password(&mut self, old: &SecretString, new: &SecretString) -> Result<()> {
        self.writable()?;
        check_master_password(new)?;
        let keys = self.authenticate(&Input::Password(old), |s, v, k| s.unwrap_keys(v, k))?;
        let slot = KeySlot::create(&self.header.vault_id, &Input::Password(new), &keys)?;
        self.save_slots(vec![slot], false)
    }

    /// 用恢复密钥验证身份。之后必须重设主密码才能进入密库。AC-KEY-06
    pub fn unlock_with_recovery<'a>(&mut self, key: &'a RecoveryKey) -> Result<RecoveryTicket<'a>> {
        self.active()?;
        self.authenticate(&Input::Recovery(key), |s, v, k| {
            let keys = s.unwrap_keys(v, k)?;
            Ok(keys.mdk)
        })
        .and_then(|mdk| {
            let state =
                ManifestBody::recorded_state(&self.header.vault_id, &mdk, &self.store.manifest()?)?;
            if state == DeviceState::Retired {
                return Err(Error::Retired);
            }
            if state != self.header.state {
                return Err(Error::Tampered);
            }
            Ok(())
        })?;
        Ok(RecoveryTicket {
            credential: key,
            session: self.recovery.start(Vec::new()),
        })
    }

    /// 准备新主密码与恢复密钥，核对前不修改磁盘。
    pub fn prepare_password_reset(
        &mut self,
        ticket: &RecoveryTicket<'_>,
        new: &SecretString,
    ) -> Result<PendingRecovery> {
        self.recovery.check(&ticket.session)?;
        check_master_password(new)?;
        let input = Input::Recovery(ticket.credential);
        let slot = self.header.slot(input.kind()).ok_or(Error::UnlockFailed)?;
        let keys = slot.unwrap_keys(&self.header.vault_id, &slot.kek(&input)?)?;
        self.prepare_slots(keys, Some(new))
    }

    pub fn prepare_recovery_reissue(&mut self, password: &SecretString) -> Result<PendingRecovery> {
        self.writable()?;
        let keys = self.authenticate(&Input::Password(password), |s, v, k| s.unwrap_keys(v, k))?;
        self.prepare_slots(keys, None)
    }

    fn prepare_slots(
        &mut self,
        keys: DataKeys,
        password: Option<&SecretString>,
    ) -> Result<PendingRecovery> {
        let recovery = RecoveryKey::generate()?;
        let vid = &self.header.vault_id;
        let mut slots = vec![KeySlot::create(vid, &Input::Recovery(&recovery), &keys)?];
        if let Some(p) = password {
            slots.push(KeySlot::create(vid, &Input::Password(p), &keys)?);
        }
        let challenge = challenge()?;
        Ok(PendingRecovery {
            session: self.recovery.start(slots),
            recovery,
            challenge,
        })
    }

    /// 核对后原子更换密钥槽。写入失败后重新锁定。
    pub fn commit_recovery(&mut self, p: &PendingRecovery, answers: [&str; 2]) -> Result<()> {
        self.active()?;
        self.recovery.check(&p.session)?;
        confirm(&p.recovery, p.challenge, answers)?;
        let slots = std::mem::take(&mut self.recovery.slots);
        self.recovery = RecoverySession::default();
        let slot = slots.first().ok_or(Error::UnlockFailed)?;
        let keys = slot.unwrap_keys(
            &self.header.vault_id,
            &slot.kek(&Input::Recovery(&p.recovery))?,
        )?;
        self.load(keys)?;
        let drop_device = slots.iter().any(|s| s.kind == SlotKind::Password);
        let result = self.save_slots(slots, drop_device);
        if result.is_err() {
            self.lock(LockMode::Full);
        }
        result
    }

    /// 登记由系统钥匙库保护的设备密钥（生物识别解锁）。
    pub fn enroll_device_key(&mut self, password: &SecretString, device: &Key) -> Result<()> {
        self.writable()?;
        let keys = self.authenticate(&Input::Password(password), |s, v, k| s.unwrap_keys(v, k))?;
        let slot = KeySlot::create(&self.header.vault_id, &Input::Device(device), &keys)?;
        self.save_slots(vec![slot], false)
    }

    pub fn remove_device_key(&mut self) -> Result<()> {
        self.writable()?;
        self.save_slots(Vec::new(), true)
    }

    fn save_slots(&mut self, put: Vec<KeySlot>, drop_device: bool) -> Result<()> {
        let mut slots = self.header.slots.clone();
        slots.retain(|s| {
            let replaced = put.iter().any(|p| p.kind == s.kind);
            let dropped = drop_device && s.kind == SlotKind::Device;
            !replaced && !dropped
        });
        slots.extend(put.iter().cloned());
        slots.sort_by_key(|s| s.kind);
        let m = self.next_manifest(self.header.state, &slots, &self.entries)?;
        self.store.write(|tx| {
            if drop_device {
                store::delete_slot(tx, SlotKind::Device)?;
            }
            put.iter().try_for_each(|s| store::put_slot(tx, s))?;
            store::put_manifest(tx, &m)
        })?;
        self.recovery = RecoverySession::default();
        self.header.slots = slots;
        self.generation = m.generation;
        Ok(())
    }

    fn next_manifest(
        &self,
        state: DeviceState,
        slots: &[KeySlot],
        entries: &BTreeMap<ItemId, Entry>,
    ) -> Result<Manifest> {
        let items = entries.iter().map(|(id, e)| (*id, e.rev, e.digest));
        self.seal_manifest(ManifestBody::compute(
            self.header.epoch,
            state,
            slots,
            items,
        ))
    }

    fn seal_manifest(&self, body: ManifestBody) -> Result<Manifest> {
        let generation = self.generation.checked_add(1).ok_or(Error::Storage)?;
        body.seal(&self.header.vault_id, self.mdk()?, generation)
    }

    // ---- 条目 ----

    fn entry(&self, id: ItemId) -> Result<&Entry> {
        self.entries.get(&id).ok_or(Error::UnknownItem)
    }

    /// 提交一组改动：条目、字段、清单在同一事务里，全部成功或全部不变。
    fn commit(&mut self, changes: Vec<Change>) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        self.active()?;
        let vid = self.header.vault_id;
        // (条目, 新状态)；None 表示删除
        let mut after: BTreeMap<ItemId, Option<Entry>> = BTreeMap::new();
        let mut puts: Vec<RowPut> = Vec::new();
        let mut deletes = Vec::new();
        let mut secrets_changed = Vec::new();
        for c in changes {
            match c {
                Change::Put(raw, record) => {
                    after.insert(raw.id, Some(make_entry(raw.rev, &raw.blob, record)));
                    secrets_changed.push(raw.id);
                    puts.push((raw.id, raw.rev, raw.blob, Some(raw.fields)));
                }
                Change::Meta(id, record) => {
                    let rev = self.next_rev(id)?;
                    let blob = sealed::seal_meta(&vid, self.mdk()?, id, rev, &record)?;
                    after.insert(id, Some(make_entry(rev, &blob, record)));
                    puts.push((id, rev, blob, None));
                }
                Change::Delete(id) => {
                    after.insert(id, None);
                    secrets_changed.push(id);
                    deletes.push(id);
                }
            }
        }
        let mut triples: BTreeMap<ItemId, (u64, [u8; 32])> = self
            .entries
            .iter()
            .map(|(id, e)| (*id, (e.rev, e.digest)))
            .collect();
        for (id, e) in &after {
            match e {
                Some(e) => triples.insert(*id, (e.rev, e.digest)),
                None => triples.remove(id),
            };
        }
        let m = self.seal_manifest(ManifestBody::compute(
            self.header.epoch,
            self.header.state,
            &self.header.slots,
            triples.into_iter().map(|(id, (rev, d))| (id, rev, d)),
        ))?;
        self.store.write(|tx| {
            for id in &deletes {
                store::delete_item(tx, *id)?;
            }
            for (id, rev, blob, fields) in &puts {
                store::put_item_row(tx, *id, *rev, blob)?;
                if let Some(f) = fields {
                    store::replace_fields(tx, *id, f)?;
                }
            }
            store::put_manifest(tx, &m)
        })?;
        // 落盘成功后才更新内存
        self.generation = m.generation;
        for (id, e) in after {
            self.refs.invalidate(id);
            match e {
                Some(e) => self.entries.insert(id, e),
                None => self.entries.remove(&id),
            };
        }
        self.refresh_secret_index(&secrets_changed);
        Ok(())
    }

    fn next_rev(&self, id: ItemId) -> Result<u64> {
        self.entry(id)?.rev.checked_add(1).ok_or(Error::Storage)
    }

    pub fn add(&mut self, draft: &ItemDraft) -> Result<ItemId> {
        Ok(self.add_many(std::slice::from_ref(draft))?[0])
    }

    /// 一次事务写入多条。
    pub(crate) fn add_many(&mut self, drafts: &[ItemDraft]) -> Result<Vec<ItemId>> {
        let keys = self.writable()?;
        let now = self.clock.wall_ms();
        let mut ids = Vec::with_capacity(drafts.len());
        let mut changes = Vec::with_capacity(drafts.len());
        for d in drafts {
            let id = ItemId::random()?;
            let p = d.prepare(now, now)?;
            let (raw, record) = sealed::seal_item(&self.header.vault_id, keys, id, 1, p)?;
            ids.push(id);
            changes.push(Change::Put(raw, record));
        }
        self.commit(changes)?;
        Ok(ids)
    }

    /// 整条替换。回收站里的条目要先还原。
    pub fn update(&mut self, id: ItemId, draft: &ItemDraft) -> Result<()> {
        let keys = self.writable()?;
        let e = self.entry(id)?;
        if e.record.deleted_ms.is_some() {
            return Err(Error::UnknownItem);
        }
        let p = draft.prepare(e.record.created_ms, self.clock.wall_ms())?;
        let rev = self.next_rev(id)?;
        let (raw, record) = sealed::seal_item(&self.header.vault_id, keys, id, rev, p)?;
        self.commit(vec![Change::Put(raw, record)])
    }

    /// 读取整条，需完全解锁。
    pub fn get(&self, id: ItemId) -> Result<Item> {
        let sdk = &self.data_keys()?.sdk;
        let e = self.entry(id)?;
        let mut secrets = Secrets::default();
        for f in &e.record.fields {
            secrets.set(f.kind()?, self.read_field(sdk, id, f)?)?;
        }
        Ok(Item {
            meta: e.record.view(id),
            secrets,
        })
    }

    fn read_field(
        &self,
        sdk: &Key,
        id: ItemId,
        f: &crate::model::FieldRef,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (rev, blob) = self.store.field(id, &f.id()?)?.ok_or(Error::Tampered)?;
        f.open(&self.header.vault_id, sdk, id, rev, &blob)
    }

    /// 列出条目，需完全解锁。AC-VLT-05
    pub fn list(&self, filter: ListFilter) -> Result<Vec<ItemMeta>> {
        self.data_keys()?;
        let mut v: Vec<ItemMeta> = self
            .entries
            .iter()
            .filter(|(_, e)| e.record.deleted_ms.is_some() == (filter == ListFilter::Trash))
            .map(|(id, e)| e.record.view(*id))
            .collect();
        v.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms).then(a.id.cmp(&b.id)));
        Ok(v)
    }

    /// 批准页上显示的条目信息。界面锁定、服务运行时也可用。
    pub fn approval_meta(&self, id: ItemId) -> Result<ItemMeta> {
        self.mdk()?;
        let e = self.entry(id)?;
        if !e.record.ai_visible() {
            return Err(Error::UnknownItem);
        }
        Ok(e.record.view(id))
    }

    pub fn set_ai_hidden(&mut self, id: ItemId, hidden: bool) -> Result<()> {
        self.edit_meta(id, |r, _| r.ai_hidden = hidden)
    }

    /// 移入回收站。
    pub fn trash(&mut self, id: ItemId) -> Result<()> {
        self.edit_meta(id, |r, now| r.deleted_ms = r.deleted_ms.or(Some(now)))
    }

    /// 从回收站还原。
    pub fn restore(&mut self, id: ItemId) -> Result<()> {
        self.edit_meta(id, |r, _| r.deleted_ms = None)
    }

    fn edit_meta(&mut self, id: ItemId, f: impl FnOnce(&mut MetaRecord, i64)) -> Result<()> {
        self.writable()?;
        let mut record = self.entry(id)?.record.clone();
        f(&mut record, self.clock.wall_ms());
        self.commit(vec![Change::Meta(id, record)])
    }

    /// 物理删除，只能删回收站里的。
    pub fn purge(&mut self, id: ItemId) -> Result<()> {
        self.writable()?;
        if self.entry(id)?.record.deleted_ms.is_none() {
            return Err(Error::NotInTrash);
        }
        self.commit(vec![Change::Delete(id)])
    }

    pub fn empty_trash(&mut self) -> Result<usize> {
        self.writable()?;
        self.delete_where(|_| true)
    }

    /// 物理删除回收站中超过 30 天的条目。解锁时自动执行。AC-VLT-03
    pub fn purge_expired_trash(&mut self) -> Result<usize> {
        self.writable()?;
        let now = self.clock.wall_ms();
        let keep = policy::TRASH_RETENTION.as_millis() as i64;
        self.delete_where(|deleted| now.saturating_sub(deleted) >= keep)
    }

    fn delete_where(&mut self, f: impl Fn(i64) -> bool) -> Result<usize> {
        let changes: Vec<Change> = self
            .entries
            .iter()
            .filter(|(_, e)| e.record.deleted_ms.is_some_and(&f))
            .map(|(id, _)| Change::Delete(*id))
            .collect();
        let n = changes.len();
        self.commit(changes)?;
        Ok(n)
    }

    /// 当前动态口令，需完全解锁。
    pub fn totp_code(&self, id: ItemId) -> Result<TotpCode> {
        let sdk = &self.data_keys()?.sdk;
        let e = self.entry(id)?;
        let f = find_field(&e.record, FieldKind::Totp)?.ok_or(Error::UnknownField)?;
        let seed = SecretString::from_utf8(self.read_field(sdk, id, f)?)?;
        let secs = u64::try_from(self.clock.wall_ms() / 1000).map_err(|_| Error::InvalidTotp)?;
        Totp::parse(&seed)?.at(secs)
    }

    // ---- 设备服务的加密本地数据，不随备份或迁移转移 ----
    pub fn service_clients(&self) -> Result<Vec<StoredClient>> {
        use crate::crypto::aead::{self, Aad, Purpose};
        let key = self.mdk()?;
        let mut stmt = self
            .store
            .service_db()
            .prepare("SELECT id,blob FROM client ORDER BY id LIMIT 65")?;
        let mut rows = stmt.query([])?;
        let mut clients = Vec::new();
        while let Some(row) = rows.next()? {
            let id: [u8; 16] = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let aad = Aad::new(Purpose::Client, &self.header.vault_id).part(&id);
            clients.push((id, aead::open(key, &aad, &blob)?));
        }
        Ok(clients)
    }

    pub fn store_client(&self, id: [u8; 16], data: &[u8]) -> Result<()> {
        use crate::crypto::aead::{self, Aad, Purpose};
        self.active()?;
        let aad = Aad::new(Purpose::Client, &self.header.vault_id).part(&id);
        let blob = aead::seal(self.mdk()?, &aad, data)?;
        self.store.service_db().execute(
            "INSERT OR REPLACE INTO client VALUES (?1,?2)",
            rusqlite::params![id, blob],
        )?;
        Ok(())
    }

    pub fn remove_client(&self, id: [u8; 16]) -> Result<()> {
        self.active()?;
        self.store
            .service_db()
            .execute("DELETE FROM client WHERE id=?1", [id])?;
        Ok(())
    }

    /// 查询可能夹带密码，记录带密钥的查询指纹，供主设备核对。
    pub fn query_fingerprint(&self, query: &str) -> Result<String> {
        use hmac::{Hmac, KeyInit, Mac};
        let key = crate::crypto::hkdf_sha256(
            self.mdk()?.expose(),
            &self.header.vault_id,
            b"audit-query",
        )?;
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(key.expose()).map_err(|_| Error::Storage)?;
        mac.update(query.as_bytes());
        Ok(crate::model::hex(&mac.finalize().into_bytes()))
    }

    pub fn append_service_audit(&self, record: &[u8]) -> Result<()> {
        use crate::crypto::aead::{self, Aad, Purpose};
        let db = self.store.service_db();
        let tx = db.unchecked_transaction()?;
        let id: i64 = tx.query_row("SELECT COALESCE(MAX(id),0)+1 FROM audit", [], |r| r.get(0))?;
        let aad = Aad::new(Purpose::Audit, &self.header.vault_id).int(id as u64);
        let blob = aead::seal(self.mdk()?, &aad, record)?;
        tx.execute(
            "INSERT INTO audit VALUES (?1,?2)",
            rusqlite::params![id, blob],
        )?;
        tx.execute(
            "DELETE FROM audit WHERE id <= ?1",
            [id.saturating_sub(10000)],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn recent_service_audit(&self) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
        use crate::crypto::aead::{self, Aad, Purpose};
        self.writable()?;
        let mut stmt = self
            .store
            .service_db()
            .prepare("SELECT id,blob FROM audit ORDER BY id DESC LIMIT 100")?;
        let mut rows = stmt.query([])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let aad =
                Aad::new(Purpose::Audit, &self.header.vault_id).int(row.get::<_, i64>(0)? as u64);
            events.push(aead::open(self.mdk()?, &aad, &row.get::<_, Vec<u8>>(1)?)?);
        }
        Ok(events)
    }

    pub fn ai_item(&self, id: ItemId, tags: &[String]) -> Result<(u64, ItemMeta)> {
        self.active()?;
        self.mdk()?;
        let e = self.entry(id)?;
        if !e.record.ai_visible()
            || !(tags.is_empty() || tags.iter().any(|tag| e.record.tags.contains(tag)))
        {
            return Err(Error::UnknownItem);
        }
        Ok((e.rev, e.record.view(id)))
    }

    // ---- 授权 ----

    /// 批准一次授权：无论当前是否已解锁，都重新验证，临时取得机密密钥，只解密获批字段。
    ///
    /// 条目里不存在的字段会省略。AC-GRT-04
    pub fn reveal_for_grant(
        &mut self,
        id: ItemId,
        fields: &[AiField],
        auth: Auth<'_>,
    ) -> Result<Vec<RevealedField>> {
        self.mdk()?;
        self.active()?;
        let e = self.entry(id)?;
        if !e.record.ai_visible() {
            return Err(Error::NotAllowedForAi);
        }
        let allowed = AiField::requestable(e.record.kind);
        if fields.is_empty() || fields.iter().any(|f| !allowed.contains(f)) {
            return Err(Error::UnknownField);
        }
        let sdk = self.authenticate(&auth.input(), |s, v, k| s.unwrap_secret_key(v, k))?;
        let record = &self.entry(id)?.record;
        let mut out = Vec::new();
        for f in allowed.iter().filter(|f| fields.contains(f)) {
            let Some(fr) = find_field(record, f.field())? else {
                continue;
            };
            let plain = self.read_field(&sdk, id, fr)?;
            out.push(RevealedField {
                name: *f,
                value: match f {
                    AiField::Custom => RevealedValue::Pairs(decode_custom(&plain)?),
                    _ => RevealedValue::Text(SecretString::from_utf8(plain)?),
                },
            });
        }
        Ok(out)
    }

    /// AI 搜索入口。只借出元数据，不需要也接触不到机密密钥。
    pub fn ai(&mut self) -> Result<AiGateway<'_>> {
        self.active()?;
        let mdk = match &self.keys {
            KeyState::Serving(k) => k,
            KeyState::Unlocked(k) => &k.mdk,
            KeyState::Locked => return Err(Error::Locked),
        };
        Ok(AiGateway {
            quota: search::quota::QuotaStore::new(&self.store, mdk, &self.header.vault_id),
            entries: &self.entries,
            refs: &mut self.refs,
            clock: &*self.clock,
        })
    }

    /// 主设备上的用户解除枚举暂停。时间窗口内的请求仍会计数。
    pub fn resume_ai_search(&self, client: search::ClientId) -> Result<()> {
        let keys = self.writable()?;
        search::quota::QuotaStore::new(&self.store, &keys.mdk, &self.header.vault_id).resume(client)
    }

    // ---- 本机搜索 ----

    /// 本机搜索，需完全解锁；除元数据外还匹配账号、正文、备注、网址。
    pub fn search(&mut self, query: &str, limit: usize) -> Result<Vec<LocalHit>> {
        self.data_keys()?;
        let q = Query::parse_lenient(query);
        if q.terms.is_empty() {
            return Ok(Vec::new());
        }
        if self.secret_index.is_none() {
            self.secret_index = Some(self.build_secret_index()?);
        }
        let secrets = self.secret_index.as_ref().map(|s| &s.0);
        let mut hits: Vec<(f32, ItemId, &Entry, Vec<search::MatchedIn>)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.record.deleted_ms.is_none())
            .filter_map(|(id, e)| {
                let s = search::score(&q, &e.index, secrets.and_then(|m| m.get(id)))?;
                Some((s.total, *id, e, s.matched))
            })
            .collect();
        hits.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        hits.truncate(limit);
        Ok(hits
            .into_iter()
            .map(|(score, id, e, matched)| LocalHit {
                meta: e.record.view(id),
                score,
                matched,
            })
            .collect())
    }

    fn build_secret_index(&self) -> Result<SecretIndex> {
        self.entries
            .iter()
            .map(|(id, e)| Ok((*id, self.secret_text(*id, &e.record)?)))
            .collect::<Result<_>>()
            .map(SecretIndex)
    }

    fn secret_text(&self, id: ItemId, record: &MetaRecord) -> Result<SecretText> {
        let sdk = &self.data_keys()?.sdk;
        let mut account = Zeroizing::new(String::new());
        let mut parts: Vec<Zeroizing<String>> = Vec::new();
        for f in &record.fields {
            match f.kind()? {
                FieldKind::Username => {
                    let s = SecretString::from_utf8(self.read_field(sdk, id, f)?)?;
                    account = text::compact(&text::fold(s.expose()));
                }
                FieldKind::Url | FieldKind::Note | FieldKind::Body => {
                    let s = SecretString::from_utf8(self.read_field(sdk, id, f)?)?;
                    parts.push(text::compact(&text::fold(s.expose())));
                }
                FieldKind::Custom => {
                    let pairs: Vec<CustomField> = decode_custom(&self.read_field(sdk, id, f)?)?;
                    parts.extend(
                        pairs
                            .iter()
                            .map(|c| text::compact(&text::fold(c.name.expose()))),
                    );
                }
                // 密码与 TOTP 种子不进索引
                FieldKind::Password | FieldKind::Totp => {}
            }
        }
        let mut content = Zeroizing::new(String::with_capacity(
            parts.iter().map(|p| p.len() + 1).sum(),
        ));
        for p in &parts {
            content.push_str(p);
            content.push(' ');
        }
        Ok(SecretText { account, content })
    }

    fn refresh_secret_index(&mut self, ids: &[ItemId]) {
        let Some(mut index) = self.secret_index.take() else {
            return;
        };
        for id in ids {
            index.0.remove(id);
            if let Some(e) = self.entries.get(id) {
                match self.secret_text(*id, &e.record) {
                    Ok(t) => {
                        index.0.insert(*id, t);
                    }
                    // 读不出来就整个作废，下次搜索重建并报错
                    Err(_) => return,
                }
            }
        }
        self.secret_index = Some(index);
    }

    // ---- 供备份与迁移模块使用 ----

    pub(crate) fn snapshot(&self) -> Result<(Snapshot, &DataKeys)> {
        let keys = self.data_keys()?;
        Ok((self.store.snapshot()?, keys))
    }

    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    pub(crate) fn mdk_for_migration(&self) -> Result<&Key> {
        self.mdk()
    }

    pub fn reauthenticate(&mut self, auth: Auth<'_>) -> Result<()> {
        self.authenticate(&auth.input(), |s, v, k| s.unwrap_secret_key(v, k))
            .map(drop)
    }

    /// 改设备状态，同时写进清单，单独改明文状态会被发现。
    pub(crate) fn set_device_state(
        &mut self,
        state: DeviceState,
        migration: Option<Vec<u8>>,
    ) -> Result<()> {
        let m = self.next_manifest(state, &self.header.slots, &self.entries)?;
        self.store.write(|tx| {
            store::put_device_state(tx, state, migration.as_deref())?;
            store::put_manifest(tx, &m)
        })?;
        self.recovery = RecoverySession::default();
        self.header.state = state;
        self.header.migration = migration;
        self.generation = m.generation;
        self.refs.clear();
        Ok(())
    }

    /// 清除已停用的密库文件。AC-MIG-04
    pub fn wipe_retired(self) -> Result<()> {
        if self.header.state != DeviceState::Retired {
            return Err(Error::ReadOnly);
        }
        let path: PathBuf = self.store.close()?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let p = fsutil::with_suffix(&path, suffix);
            if p.exists() {
                fsutil::overwrite_and_remove(&p)?;
            }
        }
        fsutil::overwrite_and_remove(&path)
    }

    #[cfg(test)]
    pub(crate) fn store_for_test(&self) -> &Store {
        &self.store
    }
}

fn make_entry(rev: u64, blob: &[u8], record: MetaRecord) -> Entry {
    Entry {
        rev,
        digest: sealed::sha256(blob),
        index: MetaIndex::new(&record),
        record,
    }
}

fn find_field(r: &MetaRecord, kind: FieldKind) -> Result<Option<&crate::model::FieldRef>> {
    for f in &r.fields {
        if f.kind()? == kind {
            return Ok(Some(f));
        }
    }
    Ok(None)
}
