//! 授权状态机的状态与合法转移（纯逻辑，不含明文与授权码）。
//!
//! 转移表与 `docs/设计.md` 第 5 节一致。实现授权流程时必须经由
//! [`GrantState::apply`]，不得绕过它直接改状态。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// 等待用户处理。
    Pending,
    /// 已批准交给 AI，授权码已生成并只显示在 App 上。
    CodeIssued,
    /// 用户选择仅在本机查看，AI 得不到明文。
    ViewOnly,
    /// 用户拒绝。
    Denied,
    /// 申请超时未处理。
    Expired,
    /// 授权码已成功使用一次。
    Redeemed,
    /// 授权码超时未使用。
    CodeExpired,
    /// 授权码错误次数用尽。
    Locked,
    /// 被撤销（一键关闭、撤销客户端、条目改为对 AI 不可见、条目被删改等）。
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantEvent {
    ApproveForAi,
    ApproveViewOnly,
    Deny,
    RequestTimeout,
    RedeemOk,
    CodeTimeout,
    FailuresExhausted,
    Revoke,
}

impl GrantState {
    pub const ALL: [GrantState; 9] = [
        Self::Pending,
        Self::CodeIssued,
        Self::ViewOnly,
        Self::Denied,
        Self::Expired,
        Self::Redeemed,
        Self::CodeExpired,
        Self::Locked,
        Self::Revoked,
    ];

    /// 终态不再接受任何事件。
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::CodeIssued)
    }

    /// 只有这个状态下 GET 明文接口才可能返回明文。
    pub const fn may_redeem(self) -> bool {
        matches!(self, Self::CodeIssued)
    }

    /// 返回转移后的状态；非法转移返回 `None`，调用方必须当作拒绝处理。
    pub const fn apply(self, event: GrantEvent) -> Option<GrantState> {
        use GrantEvent as E;
        use GrantState as S;
        match (self, event) {
            (S::Pending, E::ApproveForAi) => Some(S::CodeIssued),
            (S::Pending, E::ApproveViewOnly) => Some(S::ViewOnly),
            (S::Pending, E::Deny) => Some(S::Denied),
            (S::Pending, E::RequestTimeout) => Some(S::Expired),
            (S::CodeIssued, E::RedeemOk) => Some(S::Redeemed),
            (S::CodeIssued, E::CodeTimeout) => Some(S::CodeExpired),
            (S::CodeIssued, E::FailuresExhausted) => Some(S::Locked),
            (S::Pending | S::CodeIssued, E::Revoke) => Some(S::Revoked),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENTS: [GrantEvent; 8] = [
        GrantEvent::ApproveForAi,
        GrantEvent::ApproveViewOnly,
        GrantEvent::Deny,
        GrantEvent::RequestTimeout,
        GrantEvent::RedeemOk,
        GrantEvent::CodeTimeout,
        GrantEvent::FailuresExhausted,
        GrantEvent::Revoke,
    ];

    #[test]
    fn terminal_states_reject_every_event() {
        for s in GrantState::ALL.into_iter().filter(|s| s.is_terminal()) {
            for e in EVENTS {
                assert_eq!(s.apply(e), None, "{s:?} 不应接受 {e:?}");
            }
        }
    }

    #[test]
    fn redeem_is_single_use() {
        let used = GrantState::CodeIssued.apply(GrantEvent::RedeemOk).unwrap();
        assert_eq!(used, GrantState::Redeemed);
        assert!(!used.may_redeem());
        assert_eq!(used.apply(GrantEvent::RedeemOk), None);
    }

    #[test]
    fn only_explicit_ai_approval_reaches_code_issued() {
        for s in GrantState::ALL {
            for e in EVENTS {
                if s.apply(e) == Some(GrantState::CodeIssued) {
                    assert_eq!((s, e), (GrantState::Pending, GrantEvent::ApproveForAi));
                }
            }
        }
    }

    #[test]
    fn view_only_never_becomes_redeemable() {
        let s = GrantState::Pending
            .apply(GrantEvent::ApproveViewOnly)
            .unwrap();
        assert!(s.is_terminal() && !s.may_redeem());
    }

    #[test]
    fn revoke_works_from_every_live_state() {
        for s in GrantState::ALL.into_iter().filter(|s| !s.is_terminal()) {
            assert_eq!(s.apply(GrantEvent::Revoke), Some(GrantState::Revoked));
        }
    }
}
