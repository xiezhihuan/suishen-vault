//! 给 AI 用的受限搜索。
//!
//! 搜索读取元数据索引与客户端配额，不接触机密密钥或机密索引，
//! 返回类型里也不存在机密字段。没有列出全部、导出、写入的方法。

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::clock::{Clock, Stamp};
use crate::error::{Error, Result};
use crate::model::{ItemId, ItemKind, hex, unhex};
use crate::policy;
use crate::search::query::Query;
use crate::search::score;
use crate::secret::random_array;
use crate::vault::Entry;

/// AI 客户端标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub [u8; 16]);

/// 不透明条目 ID：每次搜索随机生成，绑定客户端，30 分钟失效。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ItemRef(String);

impl ItemRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// AI 能得到的全部内容。不要在这里增加字段。AC-SRC-01
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AiSearchHit {
    pub item_ref: ItemRef,
    pub title: String,
    #[serde(rename = "type")]
    pub kind: ItemKind,
    pub domain: Option<String>,
    pub masked_account: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AiSearchError {
    #[error("查询太短")]
    QueryTooShort,
    #[error("查询太长")]
    QueryTooLong,
    #[error("搜索次数已达上限，请在 {retry_after_ms} 毫秒后重试")]
    RateLimited { retry_after_ms: u64 },
    #[error("此客户端的搜索已暂停，请在主设备上恢复")]
    Paused,
    #[error("暂时无法搜索")]
    Unavailable,
}

struct RefEntry {
    client: ClientId,
    item: ItemId,
    issued: Stamp,
    seq: u64,
}

/// 不透明 ID 表，只在内存。
#[derive(Default)]
pub(crate) struct RefTable {
    map: HashMap<[u8; 16], RefEntry>,
    seq: u64,
}

impl RefTable {
    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    pub(crate) fn invalidate(&mut self, id: ItemId) {
        self.map.retain(|_, entry| entry.item != id);
    }

    fn prune(&mut self, now: Stamp) {
        let ttl = policy::ITEM_REF_TTL.as_millis() as u64;
        self.map.retain(|_, e| !e.issued.expired(now, ttl));
    }

    fn issue(&mut self, client: ClientId, item: ItemId, now: Stamp) -> Result<ItemRef> {
        let mine = self.map.iter().filter(|(_, e)| e.client == client);
        if mine.clone().count() >= policy::ITEM_REF_MAX_PER_CLIENT {
            let oldest = mine.min_by_key(|(_, e)| e.seq).map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.map.remove(&k);
            }
        }
        let token: [u8; 16] = random_array()?;
        self.seq += 1;
        self.map.insert(
            token,
            RefEntry {
                client,
                item,
                issued: now,
                seq: self.seq,
            },
        );
        Ok(ItemRef(format!("itm_{}", hex(&token))))
    }
}

/// AI 一侧的唯一入口。
pub struct AiGateway<'a> {
    pub(crate) quota: super::quota::QuotaStore<'a>,
    pub(crate) entries: &'a BTreeMap<ItemId, Entry>,
    pub(crate) refs: &'a mut RefTable,
    pub(crate) clock: &'a dyn Clock,
}

impl AiGateway<'_> {
    /// 客户端标识应由调用方从已验证的配对凭据取得。
    pub fn search(
        &mut self,
        client: ClientId,
        query: &str,
    ) -> std::result::Result<Vec<AiSearchHit>, AiSearchError> {
        let mut usage = self
            .quota
            .read(client)
            .map_err(|_| AiSearchError::Unavailable)?;
        let charged_at = usage.charge(self.clock.wall_ms())?;
        let parsed = if query.chars().nth(policy::SEARCH_MAX_QUERY_CHARS).is_some() {
            Err(AiSearchError::QueryTooLong)
        } else {
            let q = Query::parse(query);
            if q.long_enough_for_ai() {
                Ok(q)
            } else {
                Err(AiSearchError::QueryTooShort)
            }
        };
        let q = match parsed {
            Ok(q) => q,
            Err(err) => {
                self.quota
                    .write(client, &usage)
                    .map_err(|_| AiSearchError::Unavailable)?;
                return Err(err);
            }
        };
        let mut found: Vec<(f32, ItemId, &Entry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.record.ai_visible())
            .filter_map(|(id, e)| score(&q, &e.index, None).map(|s| (s.total, *id, e)))
            .collect();
        found.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        found.truncate(policy::SEARCH_MAX_RESULTS);
        usage.register(charged_at, found.iter().map(|(_, id, _)| *id));
        self.quota
            .write(client, &usage)
            .map_err(|_| AiSearchError::Unavailable)?;
        if usage.paused() {
            return Err(AiSearchError::Paused);
        }
        let now = Stamp::now(self.clock);
        self.refs.prune(now);
        found
            .into_iter()
            .map(|(_, id, e)| {
                let item_ref = self
                    .refs
                    .issue(client, id, now)
                    .map_err(|_| AiSearchError::Unavailable)?;
                Ok(AiSearchHit {
                    item_ref,
                    title: e.record.title.clone(),
                    kind: e.record.kind,
                    domain: e.record.domains.first().cloned(),
                    masked_account: e.record.masked_account.clone(),
                })
            })
            .collect()
    }

    /// 把不透明 ID 还原成条目。别人的、过期的、不存在的、已隐藏的一律同样返回错误。AC-SRC-05
    pub fn resolve(&mut self, client: ClientId, item_ref: &str) -> Result<ItemId> {
        let now = Stamp::now(self.clock);
        self.refs.prune(now);
        item_ref
            .strip_prefix("itm_")
            .and_then(unhex)
            .and_then(|t: [u8; 16]| self.refs.map.get(&t))
            .filter(|e| e.client == client)
            .map(|e| e.item)
            .filter(|id| self.entries.get(id).is_some_and(|e| e.record.ai_visible()))
            .ok_or(Error::UnknownItem)
    }
}
