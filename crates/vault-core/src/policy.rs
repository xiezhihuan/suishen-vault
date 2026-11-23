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

/// 磁盘格式版本。
pub const FORMAT_VERSION: u32 = 1;

/// Argon2id 下限（同时是默认值）与上限。
pub const KDF_MIN_M_KIB: u32 = 64 * 1024;
pub const KDF_MIN_T: u32 = 3;
pub const KDF_MIN_P: u32 = 4;
pub const KDF_MAX_M_KIB: u32 = 1024 * 1024;
pub const KDF_MAX_T: u32 = 20;
pub const KDF_MAX_P: u32 = 8;

/// 主密码最少字符数。
pub const MASTER_PASSWORD_MIN_CHARS: usize = 10;
/// 前几次解锁失败不等待，避免偶尔输错就被拖慢。
pub const UNLOCK_FREE_FAILURES: u32 = 2;
/// 解锁失败等待上限。
pub const UNLOCK_MAX_DELAY: Duration = Duration::from_secs(300);

/// 回收站保留时间。
pub const TRASH_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
/// 不透明条目 ID 的有效期。
pub const ITEM_REF_TTL: Duration = Duration::from_secs(30 * 60);
/// 每个客户端同时保留的不透明 ID 上限，超出时丢弃最早的。
pub const ITEM_REF_MAX_PER_CLIENT: usize = 1000;
/// AI 查询最大长度（字符）。
pub const SEARCH_MAX_QUERY_CHARS: usize = 100;

pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_TAGS: usize = 32;
pub const MAX_TAG_CHARS: usize = 64;
pub const MAX_DOMAINS: usize = 16;
pub const MAX_HINT_CHARS: usize = 1000;
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
pub const MAX_CUSTOM_FIELDS: usize = 64;
pub const MAX_CSV_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;

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
