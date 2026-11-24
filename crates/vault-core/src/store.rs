//! SQLite 存储。这一层只搬运密文与明文头部，不接触密钥。

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::crypto::wrap::{KdfSpec, KeySlot, SlotKind, WRAPPED_LEN};
use crate::error::{Error, Result};
use crate::fsutil::{self, TempFile};
use crate::model::ItemId;
use crate::policy::FORMAT_VERSION;

const APPLICATION_ID: i32 = 0x5356_4C54; // "SVLT"

/// 建表语句，同时是打开时核对结构的依据。没有索引、触发器、视图。
const SCHEMA: [(&str, &str); 10] = [
    (
        "audit",
        "CREATE TABLE audit (id INTEGER PRIMARY KEY, blob BLOB NOT NULL) STRICT",
    ),
    (
        "client",
        "CREATE TABLE client (id BLOB NOT NULL PRIMARY KEY, blob BLOB NOT NULL) STRICT, WITHOUT ROWID",
    ),
    (
        "draft_inbox",
        "CREATE TABLE draft_inbox (id BLOB PRIMARY KEY, owner BLOB NOT NULL, created INTEGER NOT NULL, blob BLOB NOT NULL) STRICT, WITHOUT ROWID",
    ),
    (
        "header",
        "CREATE TABLE header (id INTEGER PRIMARY KEY CHECK (id = 1), vault_id BLOB NOT NULL, \
         epoch INTEGER NOT NULL, device_state INTEGER NOT NULL, fail_count INTEGER NOT NULL, \
         fail_at_ms INTEGER NOT NULL, migration BLOB) STRICT",
    ),
    (
        "item",
        "CREATE TABLE item (item_id BLOB NOT NULL PRIMARY KEY, rev INTEGER NOT NULL, \
         blob BLOB NOT NULL) STRICT, WITHOUT ROWID",
    ),
    (
        "item_field",
        "CREATE TABLE item_field (item_id BLOB NOT NULL, field_id BLOB NOT NULL, \
         rev INTEGER NOT NULL, blob BLOB NOT NULL, PRIMARY KEY (item_id, field_id)) \
         STRICT, WITHOUT ROWID",
    ),
    (
        "key_slot",
        "CREATE TABLE key_slot (slot INTEGER PRIMARY KEY, kdf INTEGER NOT NULL, m INTEGER NOT NULL, \
         t INTEGER NOT NULL, p INTEGER NOT NULL, salt BLOB NOT NULL, wrapped_mdk BLOB NOT NULL, \
         wrapped_sdk BLOB NOT NULL) STRICT",
    ),
    (
        "manifest",
        "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK (id = 1), gen INTEGER NOT NULL, \
         blob BLOB NOT NULL) STRICT",
    ),
    (
        "remote",
        "CREATE TABLE remote (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL) STRICT",
    ),
    (
        "search_quota",
        "CREATE TABLE search_quota (client_id BLOB NOT NULL PRIMARY KEY, blob BLOB NOT NULL) STRICT, WITHOUT ROWID",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceState {
    Active = 1,
    /// 已开始迁移：只读，AI 服务不可用。
    Migrating = 2,
    /// 已停用：只能清除。
    Retired = 3,
}

impl DeviceState {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        [Self::Active, Self::Migrating, Self::Retired]
            .into_iter()
            .find(|s| *s as u8 == v)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RawField {
    pub id: [u8; 16],
    pub rev: u64,
    pub blob: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RawItem {
    pub id: ItemId,
    pub rev: u64,
    pub blob: Vec<u8>,
    pub fields: Vec<RawField>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub generation: u64,
    pub blob: Vec<u8>,
}

/// 密库的全部持久内容（除失败计数与迁移状态），备份与迁移也用它。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub vault_id: [u8; 16],
    pub epoch: u64,
    pub slots: Vec<KeySlot>,
    pub manifest: Manifest,
    pub items: Vec<RawItem>,
}

#[derive(Clone)]
pub(crate) struct Header {
    pub vault_id: [u8; 16],
    pub epoch: u64,
    pub state: DeviceState,
    pub fail_count: u32,
    pub fail_at_ms: i64,
    pub migration: Option<Vec<u8>>,
    pub slots: Vec<KeySlot>,
}

impl Header {
    pub(crate) fn slot(&self, kind: SlotKind) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.kind == kind)
    }
}

pub(crate) struct Store {
    conn: Connection,
    path: PathBuf,
}

fn int(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::Storage)
}

fn uint(v: i64) -> Result<u64> {
    u64::try_from(v).map_err(|_| Error::Tampered)
}

fn arr<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into().map_err(|_| Error::Tampered)
}

impl Store {
    /// 在临时文件里建好完整的库，落盘后再改名到位。
    pub(crate) fn create(path: &Path, snap: &Snapshot) -> Result<Self> {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let tmp = TempFile(fsutil::temp_sibling(path)?);
        drop(fsutil::create_private(&tmp.0)?);
        let mut conn = connect(&tmp.0)?;
        configure(&conn)?;
        conn.pragma_update(None, "application_id", APPLICATION_ID)?;
        conn.pragma_update(None, "user_version", FORMAT_VERSION)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        for (_, sql) in SCHEMA {
            tx.execute_batch(sql)?;
        }
        tx.execute(
            "INSERT INTO header VALUES (1, ?1, ?2, ?3, 0, 0, NULL)",
            params![snap.vault_id, int(snap.epoch)?, DeviceState::Active as u8],
        )?;
        for s in &snap.slots {
            put_slot(&tx, s)?;
        }
        put_manifest(&tx, &snap.manifest)?;
        for i in &snap.items {
            put_item(&tx, i)?;
        }
        tx.commit()?;
        conn.close().map_err(|(_, e)| Error::from(e))?;
        fsutil::publish(&tmp.0, path)?;
        Self::open(path)
    }

    /// 打开并独占。结构、应用标识、格式版本、页完整性都要核对。
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !fs::metadata(path)?.is_file() {
            return Err(Error::NotFound);
        }
        let conn = connect(path)?;
        // 先认身份：不是本应用的文件（包括空文件）一个字节都不能改
        let app: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if app != APPLICATION_ID {
            return Err(Error::Tampered);
        }
        configure(&conn)?;
        // 拿到独占锁；有残留日志时 SQLite 会在此回滚未完成的事务
        conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
        let ver: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if ver != i64::from(FORMAT_VERSION) {
            return Err(Error::UnsupportedFormat);
        }
        upgrade(&conn)?;
        let ok: String = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if ok != "ok" {
            return Err(Error::Tampered);
        }
        Ok(Self {
            conn,
            path: path.to_owned(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn header(&self) -> Result<Header> {
        let (vid, epoch, state, fails, fail_at_ms, migration) = self.conn.query_row(
            "SELECT vault_id, epoch, device_state, fail_count, fail_at_ms, migration FROM header",
            [],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT slot, kdf, m, t, p, salt, wrapped_mdk, wrapped_sdk FROM key_slot ORDER BY slot",
        )?;
        let mut rows = stmt.query([])?;
        let mut slots = Vec::new();
        while let Some(r) = rows.next()? {
            let num = |i| -> Result<u32> {
                u32::try_from(r.get::<_, i64>(i)?).map_err(|_| Error::KdfParamsRejected)
            };
            let slot = KeySlot {
                kind: u8::try_from(r.get::<_, i64>(0)?)
                    .ok()
                    .and_then(SlotKind::from_u8)
                    .ok_or(Error::Tampered)?,
                kdf: KdfSpec::from_ints([num(1)?, num(2)?, num(3)?, num(4)?])?,
                salt: arr(&r.get::<_, Vec<u8>>(5)?)?,
                wrapped_mdk: r.get(6)?,
                wrapped_sdk: r.get(7)?,
            };
            if slot.wrapped_mdk.len() != WRAPPED_LEN || slot.wrapped_sdk.len() != WRAPPED_LEN {
                return Err(Error::Tampered);
            }
            slot.check_params()?;
            slots.push(slot);
        }
        Ok(Header {
            vault_id: arr(&vid)?,
            epoch: uint(epoch)?,
            state: u8::try_from(state)
                .ok()
                .and_then(DeviceState::from_u8)
                .ok_or(Error::Tampered)?,
            // 被改成怪值时按最大处理，不给绕过退避的机会
            fail_count: u32::try_from(fails).unwrap_or(u32::MAX),
            fail_at_ms,
            migration,
            slots,
        })
    }

    pub(crate) fn set_failures(&mut self, count: u32, at_ms: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE header SET fail_count = ?1, fail_at_ms = ?2",
            params![count, at_ms],
        )?;
        Ok(())
    }

    pub(crate) fn service_db(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn search_quota(&self, client: [u8; 16]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT blob FROM search_quota WHERE client_id = ?1",
                [client],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub(crate) fn set_search_quota(&self, client: [u8; 16], blob: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO search_quota VALUES (?1, ?2)",
            params![client, blob],
        )?;
        Ok(())
    }

    pub(crate) fn manifest(&self) -> Result<Manifest> {
        let (g, blob) = self
            .conn
            .query_row("SELECT gen, blob FROM manifest", [], |r| {
                Ok((r.get::<_, i64>(0)?, r.get(1)?))
            })?;
        Ok(Manifest {
            generation: uint(g)?,
            blob,
        })
    }

    /// 全部条目的元数据密文，不含机密字段。
    pub(crate) fn item_rows(&self) -> Result<Vec<(ItemId, u64, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT item_id, rev, blob FROM item ORDER BY item_id")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push((
                ItemId(arr(&r.get::<_, Vec<u8>>(0)?)?),
                uint(r.get(1)?)?,
                r.get(2)?,
            ));
        }
        Ok(out)
    }

    pub(crate) fn field(&self, item: ItemId, field: &[u8; 16]) -> Result<Option<(u64, Vec<u8>)>> {
        self.conn
            .prepare_cached(
                "SELECT rev, blob FROM item_field WHERE item_id = ?1 AND field_id = ?2",
            )?
            .query_row(params![item.0, field], |r| {
                Ok((r.get::<_, i64>(0)?, r.get(1)?))
            })
            .optional()?
            .map(|(rev, blob)| Ok((uint(rev)?, blob)))
            .transpose()
    }

    /// 一致性快照。设备槽（生物识别）绑定本机，不带走。
    pub(crate) fn snapshot(&self) -> Result<Snapshot> {
        let tx = self.conn.unchecked_transaction()?;
        let h = self.header()?;
        let mut items: Vec<RawItem> = self
            .item_rows()?
            .into_iter()
            .map(|(id, rev, blob)| RawItem {
                id,
                rev,
                blob,
                fields: Vec::new(),
            })
            .collect();
        {
            let mut stmt = tx.prepare(
                "SELECT item_id, field_id, rev, blob FROM item_field ORDER BY item_id, field_id",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let id = ItemId(arr(&r.get::<_, Vec<u8>>(0)?)?);
                let at = items
                    .binary_search_by(|i| i.id.cmp(&id))
                    .map_err(|_| Error::Tampered)?;
                items[at].fields.push(RawField {
                    id: arr(&r.get::<_, Vec<u8>>(1)?)?,
                    rev: uint(r.get(2)?)?,
                    blob: r.get(3)?,
                });
            }
        }
        let snap = Snapshot {
            vault_id: h.vault_id,
            epoch: h.epoch,
            slots: h
                .slots
                .into_iter()
                .filter(|s| s.kind != SlotKind::Device)
                .collect(),
            manifest: self.manifest()?,
            items,
        };
        tx.commit()?;
        Ok(snap)
    }

    /// 所有修改都在一个事务里，连同新的清单。
    pub(crate) fn write(&mut self, f: impl FnOnce(&Transaction<'_>) -> Result<()>) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        f(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn close(self) -> Result<PathBuf> {
        self.conn.close().map_err(|(_, e)| Error::from(e))?;
        Ok(self.path)
    }

    #[cfg(test)]
    pub(crate) fn conn_for_test(&self) -> &Connection {
        &self.conn
    }
}

pub(crate) fn put_slot(tx: &Transaction<'_>, s: &KeySlot) -> Result<()> {
    let [kdf, m, t, p] = s.kdf.to_ints();
    tx.execute(
        "INSERT OR REPLACE INTO key_slot VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            s.kind as u8,
            kdf,
            m,
            t,
            p,
            s.salt,
            s.wrapped_mdk,
            s.wrapped_sdk
        ],
    )?;
    Ok(())
}

pub(crate) fn delete_slot(tx: &Transaction<'_>, kind: SlotKind) -> Result<()> {
    tx.execute("DELETE FROM key_slot WHERE slot = ?1", [kind as u8])?;
    Ok(())
}

pub(crate) fn put_manifest(tx: &Transaction<'_>, m: &Manifest) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO manifest VALUES (1, ?1, ?2)",
        params![int(m.generation)?, m.blob],
    )?;
    step::hit("manifest");
    Ok(())
}

pub(crate) fn put_device_state(
    tx: &Transaction<'_>,
    state: DeviceState,
    migration: Option<&[u8]>,
) -> Result<()> {
    tx.execute(
        "UPDATE header SET device_state = ?1, migration = ?2",
        params![state as u8, migration],
    )?;
    Ok(())
}

pub(crate) fn put_item_row(tx: &Transaction<'_>, id: ItemId, rev: u64, blob: &[u8]) -> Result<()> {
    tx.prepare_cached("INSERT OR REPLACE INTO item VALUES (?1, ?2, ?3)")?
        .execute(params![id.0, int(rev)?, blob])?;
    step::hit("item");
    Ok(())
}

pub(crate) fn replace_fields(tx: &Transaction<'_>, id: ItemId, fields: &[RawField]) -> Result<()> {
    tx.prepare_cached("DELETE FROM item_field WHERE item_id = ?1")?
        .execute([id.0])?;
    let mut ins = tx.prepare_cached("INSERT INTO item_field VALUES (?1, ?2, ?3, ?4)")?;
    for f in fields {
        ins.execute(params![id.0, f.id, int(f.rev)?, f.blob])?;
        step::hit("field");
    }
    Ok(())
}

fn put_item(tx: &Transaction<'_>, i: &RawItem) -> Result<()> {
    put_item_row(tx, i.id, i.rev, &i.blob)?;
    replace_fields(tx, i.id, &i.fields)
}

pub(crate) fn delete_item(tx: &Transaction<'_>, id: ItemId) -> Result<()> {
    tx.execute("DELETE FROM item_field WHERE item_id = ?1", [id.0])?;
    tx.execute("DELETE FROM item WHERE item_id = ?1", [id.0])?;
    step::hit("delete");
    Ok(())
}

fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    // journal_mode 会返回一行，其余设置不返回
    let set = |k: &str, v: &str| {
        conn.pragma_update_and_check(None, k, v, |_| Ok(()))
            .optional()
    };
    set("locking_mode", "EXCLUSIVE")?;
    set("trusted_schema", "OFF")?;
    set("cell_size_check", "ON")?;
    set("secure_delete", "ON")?;
    set("temp_store", "MEMORY")?;
    // 回滚日志而不是 WAL：提交后只有一个文件，便于备份、搬移与清除
    set("journal_mode", "DELETE")?;
    set("journal_size_limit", "0")?;
    set("synchronous", "EXTRA")?;
    set("fullfsync", "ON")?;
    set("checkpoint_fullfsync", "ON")?;
    set("mmap_size", "0")?;
    Ok(())
}

/// 同一格式内后来增加的表，按加入的先后分批。
const ADDED: [&[&str]; 3] = [&["audit", "client"], &["remote"], &["draft_inbox"]];

/// 只有完整核对旧结构后才补表，事务可重试。
fn upgrade(conn: &Connection) -> Result<()> {
    for batches in (0..=ADDED.len()).rev() {
        let missing = |name: &str| ADDED[batches..].iter().any(|b| b.contains(&name));
        let (add, known): (Vec<_>, Vec<_>) = SCHEMA.iter().partition(|(n, _)| missing(n));
        match check_schema(conn, &known) {
            Err(Error::Tampered) if batches > 0 => continue,
            r => r?,
        }
        let tx = conn.unchecked_transaction()?;
        for (_, sql) in add {
            tx.execute_batch(sql)?;
        }
        tx.commit()?;
        break;
    }
    Ok(())
}

fn check_schema(conn: &Connection, schema: &[&(&str, &str)]) -> Result<()> {
    let mut stmt =
        conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name")?;
    let mut rows = stmt.query([])?;
    let mut expected = schema.iter();
    while let Some(r) = rows.next()? {
        let (name, sql) = expected.next().ok_or(Error::Tampered)?;
        let same = r.get::<_, String>(0)? == "table"
            && r.get::<_, String>(1)? == *name
            && r.get::<_, String>(2)? == *name
            && r.get::<_, Option<String>>(3)?.as_deref() == Some(*sql);
        if !same {
            return Err(Error::Tampered);
        }
    }
    if expected.next().is_some() {
        return Err(Error::Tampered);
    }
    Ok(())
}

/// 测试钩子：真实提交过程中每执行一步就回调一次，用来截取断电瞬间的文件。
#[cfg(test)]
pub(crate) mod step {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut(&'static str)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(h: Option<Hook>) {
        HOOK.with(|c| *c.borrow_mut() = h);
    }

    pub(super) fn hit(name: &'static str) {
        HOOK.with(|c| {
            if let Some(h) = c.borrow_mut().as_mut() {
                h(name);
            }
        });
    }
}

#[cfg(not(test))]
mod step {
    pub(super) fn hit(_: &'static str) {}
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;

    #[test]
    fn older_layouts_gain_the_missing_tables_but_partial_ones_are_refused() {
        for (drop, ok) in [
            (&[][..], true),
            (&["draft_inbox"], true),
            (&["remote", "draft_inbox"], true),
            (&["remote"], false),
            (&["audit", "client", "remote", "draft_inbox"], true),
            (&["client"], false),
            (&["audit", "client"], false),
            (&["item", "remote"], false),
        ] {
            let conn = Connection::open_in_memory().unwrap();
            for (name, sql) in SCHEMA {
                if !drop.contains(&name) {
                    conn.execute_batch(sql).unwrap();
                }
            }
            assert_eq!(upgrade(&conn).is_ok(), ok, "{drop:?}");
            if ok {
                let all: Vec<_> = SCHEMA.iter().collect();
                check_schema(&conn, &all).unwrap();
            }
        }
    }
}
