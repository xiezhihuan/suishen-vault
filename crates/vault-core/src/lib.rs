//! 密库共享核心：加密与密钥层级、存储、检索、备份、迁移、导入，以及授权状态转移表。
//!
//! 本 crate 不做网络、不依赖 Tauri。依据见 `docs/设计.md`。
//!
//! 两条搜索入口刻意分开：
//! - [`Vault::search`]：本机用，需完全解锁。
//! - [`Vault::ai`]：给 AI 用，返回 [`search::AiSearchHit`]，其中不存在机密字段。

mod backoff;
mod backup;
pub mod clock;
mod codec;
mod crypto;
mod error;
mod fsutil;
pub mod generator;
pub mod grant;
pub mod import;
mod mask;
mod migrate;
pub mod model;
pub mod policy;
pub mod scope;
mod sealed;
pub mod search;
mod secret;
mod store;
mod strength;
mod totp;
mod vault;

#[cfg(test)]
mod crash_tests;

pub use backup::{RestoreAuth, RestoreReport, restore_backup};
pub use clock::{Clock, SystemClock};
pub use crypto::code::{MigrationCode, RecoveryKey};
pub use error::{Error, InvalidItem, Result};
pub use generator::{GeneratorOptions, generate_password};
pub use grant::{GrantEvent, GrantState};
pub use migrate::{Imported, import_migration};
pub use scope::ExposureScope;
pub use secret::{Key, SecretString};
pub use store::DeviceState;
pub use strength::check_master_password;
pub use totp::TotpCode;
pub use vault::{
    Auth, ListFilter, LockMode, LockState, PendingRecovery, RecoveryTicket, Setup, Vault,
};
