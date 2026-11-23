//! 主密码的最低要求。AC-VLT-07

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::policy;
use crate::secret::SecretString;

/// 常见弱密码的词根：去掉数字与符号后等于其中之一即拒绝。
const WEAK_ROOTS: &[&str] = &[
    "password",
    "passwd",
    "passw",
    "pass",
    "pwd",
    "admin",
    "administrator",
    "root",
    "welcome",
    "letmein",
    "iloveyou",
    "woaini",
    "woaiwojia",
    "wodemima",
    "mima",
    "qwerty",
    "qwertyuiop",
    "qwert",
    "asdfghjkl",
    "asdfgh",
    "zxcvbnm",
    "zxcvbn",
    "qazwsx",
    "qazwsxedc",
    "wsxedc",
    "abc",
    "abcd",
    "abcdef",
    "abcdefg",
    "aa",
    "aaa",
    "test",
    "changeme",
    "default",
    "dragon",
    "monkey",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "batman",
    "master",
    "login",
    "hello",
    "trustno",
    "shadow",
    "qwe",
    "qweasd",
    "qweasdzxc",
    "asd",
    "zxc",
    "q",
    "a",
    "w",
    "x",
    "qq",
    "wx",
    "weixin",
    "taobao",
    "baidu",
    "google",
    "facebook",
    "computer",
    "internet",
    "secret",
    "mypassword",
    "passwordpassword",
    "mimamima",
    "suishen",
    "suishenvault",
    "vault",
    "我爱你",
    "密码",
    "我的密码",
    "主密码",
];

const SEQUENCES: &[&str] = &[
    "01234567890123456789",
    "98765432109876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiopasdfghjklzxcvbnm",
    "poiuytrewqlkjhgfdsamnbvcxz",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
    "1q2w3e4r5t6y7u8i9o0p",
    "qazwsxedcrfvtgbyhnujmikolp",
];

pub fn check_master_password(pw: &SecretString) -> Result<()> {
    let count = pw.expose().nfc().count();
    if count < policy::MASTER_PASSWORD_MIN_CHARS {
        return Err(Error::PasswordTooShort);
    }
    let fold = || pw.expose().nfkc().flat_map(char::to_lowercase);
    let mut s = Zeroizing::new(String::with_capacity(fold().map(char::len_utf8).sum()));
    s.extend(fold());
    if is_weak(&s) {
        Err(Error::PasswordTooCommon)
    } else {
        Ok(())
    }
}

fn is_weak(s: &str) -> bool {
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(s.chars().collect());
    // 全是数字：生日、手机号、身份证号一类，离线猜测空间太小
    if chars.iter().all(char::is_ascii_digit) && chars.len() < 20 {
        return true;
    }
    // 短片段重复：aaaaaaaaaa、abcabcabcabc
    for p in 1..=4 {
        if chars.iter().zip(chars.iter().skip(p)).all(|(a, b)| a == b) {
            return true;
        }
    }
    if SEQUENCES.iter().any(|seq| seq.contains(s)) {
        return true;
    }
    // 去掉数字与符号，并还原常见替换后是弱词根：password123!、P@ssw0rd2024
    let core: &[char] = {
        let first = chars.iter().position(|c| c.is_alphabetic());
        let last = chars.iter().rposition(|c| c.is_alphabetic());
        match (first, last) {
            (Some(a), Some(b)) => &chars[a..=b],
            _ => &[],
        }
    };
    let strip = |map: bool| {
        let mut t = Zeroizing::new(String::with_capacity(s.len()));
        for c in core {
            let c = match (map, c) {
                (true, '@') => 'a',
                (true, '0') => 'o',
                (true, '$') => 's',
                _ => *c,
            };
            if c.is_alphabetic() {
                t.push(c);
            }
        }
        t
    };
    [strip(false), strip(true)].iter().any(|t| {
        WEAK_ROOTS.contains(&t.as_str())
            || SEQUENCES
                .iter()
                .any(|q| t.len() >= 6 && q.contains(t.as_str()))
    }) && chars.len() < 24
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_common() {
        for s in ["", "短密码", "Ab3$xyz9!"] {
            assert_eq!(
                check_master_password(&s.into()),
                Err(Error::PasswordTooShort),
                "{s}"
            );
        }
        for s in [
            "password123",
            "P@ssw0rd2024",
            "1234567890",
            "qwertyuiop",
            "1qaz2wsx3edc",
            "aaaaaaaaaaaa",
            "abcabcabcabc",
            "13800001234",
            "woaini1314520",
            "Admin@123456",
            "19900101199001",
            "qwerty123456",
            "我爱你1234567",
            "1q2w3e4r5t6y",
            "ｐａｓｓｗｏｒｄ１２３",
        ] {
            assert_eq!(
                check_master_password(&s.into()),
                Err(Error::PasswordTooCommon),
                "{s}"
            );
        }
        for s in [
            "fake-correct-horse-42",
            "蓝色的鲸鱼在唱歌跳舞",
            "假主密码-Test-2026",
        ] {
            assert_eq!(check_master_password(&s.into()), Ok(()), "{s}");
        }
    }
}
