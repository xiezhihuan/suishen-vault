//! 查询解析。

use zeroize::Zeroizing;

use crate::model::host_of;
use crate::policy;
use crate::search::text::{compact, fold, is_cjk};

/// 拉丁停用词。除常用词外，还包括会命中大量域名的后缀。
const STOP_LATIN: &[&str] = &[
    "com",
    "www",
    "http",
    "https",
    "net",
    "org",
    "cn",
    "io",
    "co",
    "gov",
    "edu",
    "html",
    "htm",
    "the",
    "a",
    "an",
    "of",
    "for",
    "my",
    "and",
    "or",
    "in",
    "to",
    "is",
    "account",
    "accounts",
    "password",
    "passwords",
    "passwd",
    "login",
    "user",
    "username",
    "site",
    "website",
    "all",
    "any",
];

/// 中文停用短语，从长到短。
const STOP_CJK: &[&str] = &[
    "帮我找一下",
    "帮我找",
    "找一下",
    "用户名",
    "登录名",
    "账号",
    "帐号",
    "账户",
    "帐户",
    "密码",
    "登录",
    "登陆",
    "网站",
    "网址",
    "那个",
    "这个",
    "一下",
    "我的",
    "哪个",
    "所有",
    "全部",
    "什么",
];

pub(crate) enum Term {
    Latin(String),
    Cjk {
        text: String,
        chars: Vec<char>,
    },
    /// 形如域名的输入。
    Host(String),
}

impl Term {
    pub(crate) fn weight(&self) -> f32 {
        let n = match self {
            Self::Latin(s) | Self::Host(s) => s.chars().count(),
            Self::Cjk { chars, .. } => chars.len() * 2,
        };
        1.0 + n.min(8) as f32
    }
}

pub(crate) struct Query {
    pub terms: Vec<Term>,
    pub compact: Zeroizing<String>,
    /// 去掉停用词后的有效字符数，以及其中是否含中日韩文字。
    effective: usize,
    has_cjk: bool,
}

impl Query {
    pub(crate) fn parse(raw: &str) -> Self {
        Self::parse_with(raw, true)
    }

    /// 本机搜索：若全是停用词，就按原样搜。
    pub(crate) fn parse_lenient(raw: &str) -> Self {
        let q = Self::parse_with(raw, true);
        if q.terms.is_empty() {
            Self::parse_with(raw, false)
        } else {
            q
        }
    }

    fn parse_with(raw: &str, drop_stop: bool) -> Self {
        let stop = |w: &str| drop_stop && STOP_LATIN.contains(&w);
        let mut q = Self {
            terms: Vec::new(),
            compact: compact(&fold(raw)),
            effective: 0,
            has_cjk: false,
        };
        for token in raw.split_whitespace() {
            if let Some(h) = domain_token(token) {
                let n: usize = fold(&h)
                    .split(' ')
                    .filter(|l| !stop(l))
                    .map(|l| l.chars().count())
                    .sum();
                if n > 0 {
                    q.effective += n;
                    q.terms.push(Term::Host(h));
                }
                continue;
            }
            for word in fold(token).split(' ').filter(|w| !w.is_empty()) {
                for run in split_runs(word) {
                    if run.starts_with(is_cjk) {
                        for part in strip_cjk(run, drop_stop) {
                            let chars: Vec<char> = part.chars().collect();
                            q.effective += chars.len();
                            q.has_cjk = true;
                            q.terms.push(Term::Cjk { text: part, chars });
                        }
                    } else if !stop(run) {
                        q.effective += run.chars().count();
                        q.terms.push(Term::Latin(run.to_owned()));
                    }
                }
            }
        }
        q
    }

    /// AC-SRC-02
    pub(crate) fn long_enough_for_ai(&self) -> bool {
        let min = if self.has_cjk {
            policy::SEARCH_MIN_CHARS_CJK
        } else {
            policy::SEARCH_MIN_CHARS_LATIN
        };
        self.effective >= min
    }
}

fn domain_token(token: &str) -> Option<String> {
    if !token.contains('.') || token.chars().any(is_cjk) {
        return None;
    }
    let h = host_of(token)?;
    // 1.2 这样的版本号不算域名
    h.contains(|c: char| c.is_ascii_alphabetic()).then_some(h)
}

fn split_runs(word: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev = None;
    for (i, c) in word.char_indices() {
        let k = is_cjk(c);
        if prev.is_some_and(|p| p != k) {
            out.push(&word[start..i]);
            start = i;
        }
        prev = Some(k);
    }
    if start < word.len() {
        out.push(&word[start..]);
    }
    out
}

fn strip_cjk(run: &str, drop_stop: bool) -> Vec<String> {
    let mut parts = vec![run.to_owned()];
    if drop_stop {
        for s in STOP_CJK {
            parts = parts
                .iter()
                .flat_map(|p| p.split(s))
                .map(|p| p.trim_matches(['的', '了', '吗', '呢']))
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    // AC-SRC-02
    #[test]
    fn ai_minimum_length() {
        for ok in [
            "微信",
            "git",
            "公司那个GitHub账号",
            "a 微b",
            "github.com",
            "qq邮箱",
            "12306",
        ] {
            assert!(Query::parse(ok).long_enough_for_ai(), "{ok}");
        }
        for bad in [
            "",
            " ",
            "微",
            "ab",
            "***",
            "%%%",
            "。。。",
            "com",
            "www com cn",
            "账号密码",
            "的",
            "所有账号",
            "全部密码",
            "password",
            "gov.cn",
            "www.com",
            "a.com",
            "我的密码",
            "１２",
            "\u{200B}\u{200B}\u{200B}",
            "all accounts",
            "com.",
            ".com",
        ] {
            assert!(!Query::parse(bad).long_enough_for_ai(), "{bad}");
        }
    }

    #[test]
    fn natural_language_is_segmented() {
        let q = Query::parse("帮我找一下公司那个GitHub账号");
        let t: Vec<&str> = q
            .terms
            .iter()
            .map(|t| match t {
                Term::Latin(s) | Term::Host(s) => s.as_str(),
                Term::Cjk { text, .. } => text.as_str(),
            })
            .collect();
        assert_eq!(t, ["公司", "github"]);
    }
}
