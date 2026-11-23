//! 安全策略常量。改动任何一个都要同步 `docs/设计.md` 与对应验收标准。

use std::time::Duration;

/// 授权码字母表：Crockford Base32（去掉 I、L、O、U）。
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 授权码长度（字符）。
pub const AUTH_CODE_LEN: usize = 8;
/// 授权码有效期。
pub const AUTH_CODE_TTL: Duration = Duration::from_secs(120);
/// 授权码允许的错误次数，达到即作废。
pub const AUTH_CODE_MAX_FAILURES: u32 = 5;
/// 申请等待用户处理的有效期。
pub const REQUEST_TTL: Duration = Duration::from_secs(600);
/// 搜索最多返回条数。
pub const SEARCH_MAX_RESULTS: usize = 5;
/// 查询最小长度：含中日韩字符时的有效字符数。
pub const SEARCH_MIN_CHARS_CJK: usize = 2;
/// 查询最小长度：不含中日韩字符时的有效字符数。
pub const SEARCH_MIN_CHARS_LATIN: usize = 3;
/// 单个客户端同时等待处理的申请数。
pub const MAX_PENDING_PER_CLIENT: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crockford_alphabet_has_no_ambiguous_letters() {
        for c in b"ILOU" {
            assert!(!CROCKFORD_ALPHABET.contains(c));
        }
        let mut sorted = CROCKFORD_ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 32, "字母表不得重复，否则熵会低于 5 bit/字符");
    }

    #[test]
    fn limits_match_the_approved_plan() {
        assert_eq!(AUTH_CODE_LEN, 8);
        assert_eq!(AUTH_CODE_TTL.as_secs(), 120);
        assert_eq!(AUTH_CODE_MAX_FAILURES, 5);
        assert_eq!(SEARCH_MAX_RESULTS, 5);
    }
}
