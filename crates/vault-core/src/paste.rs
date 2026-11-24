//! 本机录入规则。跨度为原始 UTF-8 字节，首尾相接，语法字符也保留。
use crate::{Error, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Title,
    Url,
    Username,
    Password,
    Totp,
    Note,
    Unknown,
    Syntax,
}
use Field::*;

#[derive(Debug, Serialize)]
pub struct Span {
    pub entry: usize,
    pub kind: Field,
    pub start: usize,
    pub end: usize,
}

/// 后续识别器也只能标注区间，不能向表单提供生成的字符串。
pub trait Recognizer {
    fn recognize(&self, source: &str) -> Result<Vec<Span>>;
}
pub struct Rules;

const LABELS: &[(Field, &[&str])] = &[
    (Title, &["标题", "名称", "title", "name"]),
    (
        Username,
        &[
            "账号",
            "帐号",
            "用户名",
            "登录名",
            "邮箱",
            "手机号",
            "手机",
            "username",
            "user",
            "login",
            "email",
            "phone",
            "account",
        ],
    ),
    (Url, &["网址", "网站", "域名", "url", "domain", "website"]),
    (Password, &["密码", "口令", "password", "passwd", "pwd"]),
    (
        Totp,
        &[
            "动态口令密钥",
            "TOTP 密钥",
            "TOTP密钥",
            "totp",
            "otp secret",
        ],
    ),
    (Note, &["备注", "说明", "notes", "note"]),
];

fn label(s: &str) -> Option<(Field, usize)> {
    for &(field, names) in LABELS {
        for &name in names {
            if !s
                .get(..name.len())
                .is_some_and(|x| x.eq_ignore_ascii_case(name))
            {
                continue;
            }
            let tail = &s[name.len()..];
            // 只消耗紧贴标签的一个分隔字符。比如「pwd =Fake」的等号属于值。
            if let Some(separator) = tail
                .chars()
                .next()
                .filter(|c| c.is_whitespace() || matches!(c, ':' | '：' | '=' | '＝'))
            {
                return Some((field, name.len() + separator.len_utf8()));
            }
        }
    }
    None
}

fn bare(s: &str) -> Field {
    if s.starts_with("otpauth://totp/") {
        return Totp;
    }
    if s.contains(char::is_whitespace) {
        return Unknown;
    }
    if s.starts_with("https://") || s.starts_with("http://") {
        return if url::Url::parse(s).is_ok_and(|u| u.host().is_some()) {
            Url
        } else {
            Unknown
        };
    }
    if let Some((account, domain)) = s.split_once('@')
        && !account.is_empty()
        && account
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
        && bare_domain(domain)
    {
        return Username;
    }
    let phone = s.strip_prefix('+').unwrap_or(s);
    if (10..=15).contains(&phone.len()) && phone.bytes().all(|b| b.is_ascii_digit()) {
        return Username;
    }
    if bare_domain(s) {
        return Url;
    }
    Unknown
}

fn bare_domain(s: &str) -> bool {
    s.contains('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_alphanumeric() || c == '-')
        })
}

/// 正式条目会规整标题与网址。录入助手先让用户改正，不能静默丢弃字符。
pub fn fits_storage(draft: &crate::model::ItemDraft) -> bool {
    crate::model::clean_line(&draft.title) == draft.title
        && draft.secrets.urls.iter().all(|url| {
            let text = url.expose();
            text.trim() == text && !text.contains(['\r', '\n'])
        })
}

struct Output {
    parts: Vec<Span>,
    seen: Vec<Field>,
    entry: usize,
    new_entry: bool,
}
impl Output {
    fn push(&mut self, mut kind: Field, start: usize, end: usize) {
        if start == end {
            return;
        }
        if kind != Syntax {
            if self.new_entry
                || (self.seen.contains(&kind) && matches!(kind, Title | Url | Username))
            {
                self.entry += 1;
                self.seen.clear();
                self.new_entry = false;
            }
            if self.seen.contains(&kind) {
                kind = Unknown
            }
            if !self.seen.contains(&kind) {
                self.seen.push(kind)
            }
        }
        self.parts.push(Span {
            entry: self.entry,
            kind,
            start,
            end,
        });
    }
    fn unlabeled(&mut self, line: &str, off: usize) {
        let word = line.trim();
        if word.is_empty() {
            self.push(Syntax, off, off + line.len());
            self.new_entry = !self.seen.is_empty();
            return;
        }
        // 从表格复制的三列或四列。最后一列按原样保留，包括首尾空格。
        let columns: Vec<_> = line.split('\t').collect();
        let fields: &[Field] = match columns.as_slice() {
            [site, account, password]
                if bare(site) == Url && !account.trim().is_empty() && !password.is_empty() =>
            {
                &[Url, Username, Password]
            }
            [title, site, account, password]
                if !title.trim().is_empty()
                    && bare(site) == Url
                    && !account.trim().is_empty()
                    && !password.is_empty() =>
            {
                &[Title, Url, Username, Password]
            }
            _ => &[],
        };
        if !fields.is_empty() {
            let mut at = off;
            for (i, (&value, &field)) in columns.iter().zip(fields).enumerate() {
                if i > 0 {
                    self.push(Syntax, at, at + 1);
                    at += 1;
                }
                self.push(field, at, at + value.len());
                at += value.len();
            }
            return;
        }
        let tokens: Vec<_> = word.split_whitespace().collect();
        // 只有网址 + 可辨认的账号才足以识别横排；第三段仍须人工指定。
        if tokens.len() >= 2 && bare(tokens[0]) == Url && bare(tokens[1]) == Username {
            let mut at = 0;
            for &t in &tokens[..2] {
                let i = at + line[at..].find(t).unwrap();
                self.push(Syntax, off + at, off + i);
                self.push(bare(t), off + i, off + i + t.len());
                at = i + t.len();
            }
            let tail = &line[at..];
            let sep = tail.chars().next().map_or(0, char::len_utf8);
            self.push(Syntax, off + at, off + at + sep);
            self.push(Unknown, off + at + sep, off + line.len());
            return;
        }
        let kind = bare(word);
        if kind == Unknown {
            self.push(Unknown, off, off + line.len());
            return;
        }
        let i = line.find(word).unwrap();
        self.push(Syntax, off, off + i);
        self.push(kind, off + i, off + i + word.len());
        self.push(Syntax, off + i + word.len(), off + line.len());
    }
    fn line(&mut self, line: &str, off: usize) {
        let mut markers = Vec::new();
        let mut boundary = true;
        for (i, c) in line.char_indices() {
            if boundary
                && !c.is_whitespace()
                && let Some((kind, n)) = label(&line[i..])
            {
                if markers
                    .last()
                    .is_some_and(|&(_, _, k)| matches!(k, Password | Totp | Note))
                {
                    // 自由文本中出现类似下一栏的标签，整段留待确认。
                    if let Some(last) = markers.last_mut() {
                        let (_, _, k) = last;
                        *k = Unknown;
                    }
                    break;
                }
                markers.push((i, i + n, kind));
            }
            boundary = c.is_whitespace();
        }
        if markers.is_empty() {
            self.unlabeled(line, off);
            return;
        }
        let first = markers[0].0;
        if first > 0 {
            let prefix = &line[..first];
            self.push(
                if prefix.trim().is_empty() {
                    Syntax
                } else {
                    Unknown
                },
                off,
                off + first,
            );
        }
        for (j, &(i, v, k)) in markers.iter().enumerate() {
            let next = markers.get(j + 1).map_or(line.len(), |m| m.0);
            let end = if j + 1 < markers.len() {
                next - line[v..next]
                    .chars()
                    .next_back()
                    .filter(|c| c.is_whitespace())
                    .map_or(0, char::len_utf8)
            } else {
                next
            };
            self.push(Syntax, off + i, off + v);
            if matches!(k, Title | Url) {
                let value = &line[v..end];
                let lead = value.len() - value.trim_start().len();
                let len = value.trim().len();
                self.push(Syntax, off + v, off + v + lead);
                self.push(k, off + v + lead, off + v + lead + len);
                self.push(Syntax, off + v + lead + len, off + end);
            } else {
                self.push(k, off + v, off + end);
            }
            self.push(Syntax, off + end, off + next);
        }
    }
}
impl Recognizer for Rules {
    fn recognize(&self, source: &str) -> Result<Vec<Span>> {
        if source.len() > 65536 {
            return Err(Error::TooLarge);
        }
        let mut out = Output {
            parts: vec![],
            seen: vec![],
            entry: 0,
            new_entry: false,
        };
        let mut off = 0;
        for chunk in source.split_inclusive(['\r', '\n']) {
            let line = chunk.trim_end_matches(['\r', '\n']);
            // CRLF 的 LF 已由前一个 CR 分隔，不能再当作空行。
            if !(line.is_empty() && chunk == "\n" && source[..off].ends_with('\r')) {
                out.line(line, off);
            }
            out.push(Syntax, off + line.len(), off + chunk.len());
            off += chunk.len();
        }
        Ok(out.parts)
    }
}
