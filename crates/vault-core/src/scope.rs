//! 开放范围。

use serde::{Deserialize, Serialize};

/// 服务对外开放范围。刻意不持久化：重启后一律回到 [`ExposureScope::Closed`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureScope {
    /// 关闭，不监听任何端口。
    #[default]
    Closed,
    /// 仅本机回环地址。
    Loopback,
    /// 本机 + 局域网（TLS）。
    Lan,
    /// 本机 + 经用户自己的跳板的公网隧道；不附带开放局域网。
    Public,
}

impl ExposureScope {
    /// 是否监听回环地址。
    pub const fn listens_loopback(self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// 是否监听局域网地址。
    pub const fn listens_lan(self) -> bool {
        matches!(self, Self::Lan)
    }

    /// 是否主动连接公网跳板。
    pub const fn dials_relay(self) -> bool {
        matches!(self, Self::Public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_closed_and_opens_nothing() {
        let s = ExposureScope::default();
        assert_eq!(s, ExposureScope::Closed);
        assert!(!s.listens_loopback() && !s.listens_lan() && !s.dials_relay());
    }

    #[test]
    fn public_scope_does_not_open_lan() {
        assert!(ExposureScope::Public.dials_relay());
        assert!(!ExposureScope::Public.listens_lan());
    }

    #[test]
    fn wire_names_are_stable() {
        let json = serde_json::to_string(&ExposureScope::Loopback).unwrap();
        assert_eq!(json, "\"loopback\"");
    }
}
