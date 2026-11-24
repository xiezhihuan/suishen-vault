//! 每个已配对客户端的滚动窗口。只记录时间和条目 ID，不记录查询文本。
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{AiSearchError, ClientId};
use crate::crypto::aead::{self, Aad, Purpose};
use crate::error::{Error, Result};
use crate::model::ItemId;
use crate::secret::Key;
use crate::store::Store;

const MINUTE: i64 = 60_000;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;
const WINDOWS: [(usize, i64); 3] = [(10, MINUTE), (60, HOUR), (200, DAY)];

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Usage {
    requests: Vec<i64>,
    seen: BTreeMap<String, i64>,
    paused: bool,
}

impl Usage {
    pub(super) fn charge(&mut self, wall: i64) -> std::result::Result<i64, AiSearchError> {
        if self.paused {
            return Err(AiSearchError::Paused);
        }
        // 系统时间回拨时沿用最后一次请求的时间，不提前释放配额。
        let now = wall.max(self.requests.last().copied().unwrap_or(wall));
        self.requests.retain(|t| now.saturating_sub(*t) < DAY);
        self.seen.retain(|_, t| now.saturating_sub(*t) < DAY);
        let mut retry = 0;
        for (cap, window) in WINDOWS {
            if let Some(i) = self.requests.len().checked_sub(cap) {
                retry = retry.max(self.requests[i].saturating_add(window).saturating_sub(wall));
            }
        }
        if retry > 0 {
            return Err(AiSearchError::RateLimited {
                retry_after_ms: retry as u64,
            });
        }
        self.requests.push(now);
        Ok(now)
    }

    pub(super) fn register(&mut self, now: i64, ids: impl Iterator<Item = ItemId>) {
        for id in ids {
            self.seen.insert(id.to_hex(), now);
        }
        self.paused = self.seen.len() > 30;
    }

    pub(super) fn paused(&self) -> bool {
        self.paused
    }

    pub(crate) fn resume(&mut self) {
        self.paused = false;
        self.seen.clear();
    }
}

/// AI 入口只拿到这个受限视图；不能经它访问条目或机密密钥。
pub(crate) struct QuotaStore<'a> {
    store: &'a Store,
    mdk: &'a Key,
    vault_id: &'a [u8; 16],
}

impl<'a> QuotaStore<'a> {
    pub(crate) fn new(store: &'a Store, mdk: &'a Key, vault_id: &'a [u8; 16]) -> Self {
        Self {
            store,
            mdk,
            vault_id,
        }
    }
    fn aad(&self, client: ClientId) -> Aad {
        Aad::new(Purpose::SearchQuota, self.vault_id).part(&client.0)
    }

    pub(super) fn read(&self, client: ClientId) -> Result<Usage> {
        match self.store.search_quota(client.0)? {
            None => Ok(Usage::default()),
            Some(blob) => {
                let plain = aead::open(self.mdk, &self.aad(client), &blob)?;
                serde_json::from_slice(&plain).map_err(|_| Error::Tampered)
            }
        }
    }

    pub(super) fn write(&self, client: ClientId, usage: &Usage) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(usage).map_err(|_| Error::Storage)?);
        let blob = aead::seal(self.mdk, &self.aad(client), &plain)?;
        self.store.set_search_quota(client.0, &blob)
    }

    pub(crate) fn paused(&self, client: ClientId) -> Result<bool> {
        Ok(self.read(client)?.paused)
    }

    pub(crate) fn resume(&self, client: ClientId) -> Result<()> {
        let mut usage = self.read(client)?;
        usage.resume();
        self.write(client, &usage)
    }
}
