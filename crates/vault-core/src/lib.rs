//! 密库共享核心。
//!
//! 本 crate 不做网络、不依赖 Tauri，将承载：加密与密钥层级、存储、检索、授权状态机、迁移。
//! 目前是骨架，只包含后续实现必须遵守的常量、开放范围与授权状态转移表，
//! 依据见 `docs/设计.md`。

pub mod grant;
pub mod policy;
pub mod scope;

pub use grant::{GrantEvent, GrantState};
pub use scope::ExposureScope;
