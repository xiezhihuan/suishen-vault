//! 主设备的待核对收件箱。账号全文只能用 SDK 加密。备份快照只选正式条目。
use super::*;
use crate::crypto::aead::{self, Aad, Purpose};
use crate::model::{ItemKind, host_of};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

pub const TTL_MS: i64 = 24 * 3600 * 1000;
pub const CLIENT_CAP: usize = 12;

#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub title: String,
    #[serde(rename = "type")]
    #[zeroize(skip)]
    pub kind: ItemKind,
    #[serde(
        default,
        deserialize_with = "optional_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub hint: String,
    #[serde(
        default,
        deserialize_with = "optional_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub username: Option<String>,
}

// 可省略，显式提供时必须是字符串，与工具 schema 一致。
fn optional_text<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(input).map(Some)
}

fn looks_like_key(word: &str) -> bool {
    let bytes = word.as_bytes();
    let seed = bytes.len() >= 16
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(b));
    let mixed = bytes.len() >= 12
        && bytes.iter().all(u8::is_ascii_graphic)
        && bytes.iter().any(u8::is_ascii_uppercase)
        && bytes.iter().any(u8::is_ascii_lowercase)
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes.iter().any(|b| b"!#$^*{}|~".contains(b));
    seed || mixed
}

fn safe(s: &str, max: usize) -> bool {
    let unsafe_display = |c: char| {
        c.is_control()
            || matches!(
                c as u32, 0x061c | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff | 0xe0000..=0xe007f
            )
    };
    if s.trim().is_empty() || s.chars().count() > max || s.chars().any(unsafe_display) {
        return false;
    }
    let folded = Zeroizing::new(s.nfkc().flat_map(char::to_lowercase).collect::<String>());
    let compact = Zeroizing::new(folded.split_whitespace().collect::<String>());
    let keywords = [
        "密码",
        "口令",
        "密钥",
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "totp",
        "authorization",
    ];
    let labeled = keywords.iter().any(|k| {
        folded
            .match_indices(k)
            .any(|(i, _)| folded[i + k.len()..].starts_with(char::is_whitespace))
            || compact
                .match_indices(k)
                .any(|(i, _)| compact[i + k.len()..].starts_with([':', '=', '是']))
    });
    !labeled
        && !s.split_whitespace().any(looks_like_key)
        && !["otpauth://", "-----begin", "sk-", "ghp_", "bearer "]
            .iter()
            .any(|m| folded.contains(m))
        && !folded.split_whitespace().any(|w| {
            w.len() >= 32
                && (w.bytes().all(|b| b.is_ascii_hexdigit())
                    || w.bytes()
                        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)))
        })
}
impl Proposal {
    pub fn host(&self) -> Option<String> {
        let s = self.url.as_deref()?;
        if !safe(s, 2048)
            || s.contains(['\\', '@', '?', '#', '%'])
            || s.chars().any(char::is_whitespace)
        {
            return None;
        }
        let u = url::Url::parse(s).ok()?;
        if !matches!(u.scheme(), "http" | "https")
            || s.split_once("://")
                .is_none_or(|(_, rest)| rest.starts_with('/'))
        {
            return None;
        }
        Some(u.host_str()?.to_owned())
    }
    pub fn valid(&self) -> bool {
        safe(&self.title, 200)
            && (self.hint.is_empty() || safe(&self.hint, 500))
            && self.tags.len() <= 8
            && self.tags.iter().all(|t| safe(t, 48) && t.trim() == t)
            && self
                .username
                .as_ref()
                .is_none_or(|u| safe(u, 254) && !u.chars().any(char::is_whitespace))
            && (self.url.is_none() || self.host().is_some())
            && (self.kind == ItemKind::Login || (self.url.is_none() && self.username.is_none()))
    }
    fn complete(mut self, secret: SecretString) -> ItemDraft {
        let mut item = ItemDraft::new(self.kind, &self.title);
        item.tags = std::mem::take(&mut self.tags);
        item.hint = std::mem::take(&mut self.hint);
        match self.kind {
            ItemKind::Login => {
                item.secrets.password = Some(secret);
                item.secrets.username = self.username.take().map(SecretString::new);
                item.secrets.urls = self.url.take().into_iter().map(SecretString::new).collect();
            }
            ItemKind::Note => item.secrets.body = Some(secret),
            ItemKind::Custom => item.secrets.custom.push(CustomField {
                name: "内容".into(),
                value: secret,
            }),
        }
        item
    }
}

pub struct PendingDraft {
    pub id: ItemId,
    pub owner: [u8; 16],
    pub created: i64,
    pub proposal: Proposal,
}
fn aad(vid: &[u8; 16], id: ItemId, owner: [u8; 16], created: i64) -> Aad {
    Aad::new(Purpose::DraftInbox, vid)
        .part(&id.0)
        .part(&owner)
        .int(created as u64)
}
// 决定与审计同一事务，表单字段不进入审计。
fn audit(
    tx: &Transaction,
    mdk: &Key,
    vid: &[u8; 16],
    owner: [u8; 16],
    now: i64,
    action: &str,
    id: ItemId,
) -> Result<()> {
    let record = serde_json::json!({
        "time_ms": now, "client": crate::model::hex(&owner), "action":action,
        "subject":{"draft":id.to_hex()}, "result":"ok"
    });
    Vault::audit_in(
        tx,
        mdk,
        vid,
        &serde_json::to_vec(&record).map_err(|_| Error::Storage)?,
    )
}

impl Vault {
    pub fn expire_drafts(&self) -> Result<()> {
        let now = self.clock.wall_ms();
        self.store.service_db().execute(
            "DELETE FROM draft_inbox WHERE created<=?1 OR created>?2",
            params![now.saturating_sub(TTL_MS), now],
        )?;
        Ok(())
    }
    pub fn enqueue_draft(&self, owner: [u8; 16], p: &Proposal) -> Result<()> {
        let keys = self.writable()?;
        if !p.valid() {
            return Err(Error::NotAllowedForAi);
        }
        self.expire_drafts()?;
        let tx = self.store.service_db().unchecked_transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM draft_inbox WHERE owner=?1",
            [owner],
            |r| r.get(0),
        )?;
        if count >= CLIENT_CAP as i64 {
            return Err(Error::TooLarge);
        }
        let id = ItemId::random()?;
        let now = self.clock.wall_ms();
        let bytes = Zeroizing::new(serde_json::to_vec(p).map_err(|_| Error::Storage)?);
        let blob = aead::seal(
            &keys.sdk,
            &aad(&self.header.vault_id, id, owner, now),
            &bytes,
        )?;
        tx.execute(
            "INSERT INTO draft_inbox VALUES (?1,?2,?3,?4)",
            params![id.0, owner, now, blob],
        )?;
        audit(
            &tx,
            &keys.mdk,
            &self.header.vault_id,
            owner,
            now,
            "draft_submit",
            id,
        )?;
        Ok(tx.commit()?)
    }
    pub fn pending_drafts(&self) -> Result<Vec<PendingDraft>> {
        let keys = self.writable()?;
        self.expire_drafts()?;
        let mut stmt = self
            .store
            .service_db()
            .prepare("SELECT id,owner,created,blob FROM draft_inbox ORDER BY created,id")?;
        let mut rows = stmt.query([])?;
        let mut out = vec![];
        while let Some(row) = rows.next()? {
            let id = ItemId(row.get(0)?);
            let owner = row.get(1)?;
            let created = row.get(2)?;
            let bytes = aead::open(
                &keys.sdk,
                &aad(&self.header.vault_id, id, owner, created),
                &row.get::<_, Vec<u8>>(3)?,
            )?;
            out.push(PendingDraft {
                id,
                owner,
                created,
                proposal: serde_json::from_slice(&bytes).map_err(|_| Error::Tampered)?,
            });
        }
        Ok(out)
    }
    pub fn reject_drafts(&self, selected: Option<ItemId>) -> Result<()> {
        let drafts = self.pending_drafts()?;
        let tx = self.store.service_db().unchecked_transaction()?;
        for d in drafts
            .into_iter()
            .filter(|d| selected.is_none_or(|id| id == d.id))
        {
            tx.execute("DELETE FROM draft_inbox WHERE id=?1", [d.id.0])?;
            audit(
                &tx,
                self.mdk()?,
                &self.header.vault_id,
                d.owner,
                self.clock.wall_ms(),
                "draft_reject",
                d.id,
            )?;
        }
        Ok(tx.commit()?)
    }
    pub fn accept_draft(&mut self, id: ItemId, secret: SecretString) -> Result<ItemId> {
        if secret.is_empty() {
            return Err(Error::InvalidItem(crate::InvalidItem::Empty));
        }
        let d = self
            .pending_drafts()?
            .into_iter()
            .find(|d| d.id == id)
            .ok_or(Error::UnknownItem)?;
        let now = self.clock.wall_ms();
        let vid = self.header.vault_id;
        let p = d.proposal.complete(secret).prepare(now, now)?;
        let keys = self.writable()?;
        let item = ItemId::random()?;
        let (raw, record) = sealed::seal_item(&vid, keys, item, 1, p)?;
        let mdk = Key::from_slice(keys.mdk.bytes())?;
        self.commit_with(vec![Change::Put(raw, record)], |tx| {
            if tx.execute("DELETE FROM draft_inbox WHERE id=?1", [id.0])? != 1 {
                return Err(Error::UnknownItem);
            }
            audit(tx, &mdk, &vid, d.owner, now, "draft_accept", id)
        })?;
        Ok(item)
    }
    /// 仅解锁界面调用。域名按既有规则比较，账号逐字符比较。
    pub fn duplicate_login(&self, url: &str, user: &str) -> Result<bool> {
        self.writable()?;
        let Some(host) = host_of(url) else {
            return Ok(false);
        };
        if user.is_empty() {
            return Ok(false);
        }
        let masked = crate::mask::mask_account(user);
        for (&id, e) in &self.entries {
            if e.record.deleted_ms.is_some() || e.record.masked_account.as_ref() != Some(&masked) {
                continue;
            }
            let item = self.get(id)?;
            if item
                .secrets
                .username
                .as_ref()
                .is_some_and(|u| u.ct_eq(user))
                && (item.meta.domains.contains(&host)
                    || item
                        .secrets
                        .urls
                        .iter()
                        .any(|url| host_of(url.expose()).as_ref() == Some(&host)))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Vault {
    pub fn has_duplicate_logins(&self, rows: &[ItemDraft]) -> Result<bool> {
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            let Some(account) = row.secrets.username.as_ref() else {
                continue;
            };
            for url in &row.secrets.urls {
                let Some(host) = host_of(url.expose()) else {
                    continue;
                };
                if !seen.insert((host, account.expose()))
                    || self.duplicate_login(url.expose(), account.expose())?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
