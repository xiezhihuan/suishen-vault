//! 打码账号。固定三个星号，不泄露长度。AC-SRC-04

const STARS: &str = "***";

pub fn mask_account(account: &str) -> String {
    let a = account.trim();
    let n = a.chars().count();
    if n < 4 {
        return STARS.to_owned();
    }
    if let Some((local, domain)) = a.rsplit_once('@')
        && let Some((name, tld)) = domain.rsplit_once('.')
        && let (Some(l), Some(d)) = (safe_first(local), safe_first(name))
        && !tld.is_empty()
        && tld.chars().all(char::is_alphanumeric)
    {
        return format!("{l}{STARS}@{d}{STARS}.{tld}");
    }
    if n == 11 && a.bytes().all(|b| b.is_ascii_digit()) {
        return format!("{}{STARS}{}", &a[..3], &a[9..]);
    }
    match safe_first(a) {
        Some(c) => format!("{c}{STARS}"),
        None => STARS.to_owned(),
    }
}

fn safe_first(s: &str) -> Option<char> {
    s.chars().next().filter(|c| c.is_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn documented_shapes() {
        for (a, m) in [
            ("zhangsan@example.com", "z***@e***.com"),
            ("a@b.cn", "a***@b***.cn"),
            ("13800001234", "138***34"),
            ("zhangsan", "z***"),
            ("张三丰的号", "张***"),
            ("abc", "***"),
            ("", "***"),
            ("张三", "***"),
            ("\u{202E}abcd", "***"),
            ("me@nodot", "m***"),
        ] {
            assert_eq!(mask_account(a), m, "{a}");
        }
    }

    proptest! {
        #[test]
        fn never_reveals_full_account_or_length(a in "[a-z0-9]{4,40}") {
            let m = mask_account(&a);
            prop_assert!(!m.contains(&a));
            prop_assert!(m.len() == 4 || m.len() == 8);
            prop_assert_eq!(m.matches('*').count(), 3);
        }

        #[test]
        fn email_length_is_hidden(l in "[a-z]{1,30}", d in "[a-z]{1,30}") {
            let m = mask_account(&format!("{l}@{d}.com"));
            prop_assert_eq!(m.len(), "z***@e***.com".len());
        }

        #[test]
        fn never_panics(s in "\\PC{0,40}") { let _ = mask_account(&s); }
    }
}
