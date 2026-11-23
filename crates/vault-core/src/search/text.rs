//! 文本归一化、拼音单元与匹配。只处理字符串，不涉及密钥与存储。

use pinyin::{ToPinyin, ToPinyinMulti};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub(crate) fn is_han(c: char) -> bool {
    matches!(c, '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}' | '\u{F900}'..='\u{FAFF}'
        | '\u{20000}'..='\u{323AF}')
}

/// 中日韩文字（含假名、谚文）。
pub(crate) fn is_cjk(c: char) -> bool {
    is_han(c)
        || matches!(c, '\u{3041}'..='\u{30FF}' | '\u{31F0}'..='\u{31FF}'
        | '\u{AC00}'..='\u{D7A3}' | '\u{1100}'..='\u{11FF}')
}

/// NFKC、转小写、标点变空格、合并空白。
pub(crate) fn fold(s: &str) -> Zeroizing<String> {
    let it = || s.nfkc().flat_map(char::to_lowercase);
    let mut out = Zeroizing::new(String::with_capacity(it().map(char::len_utf8).sum()));
    for c in it() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with(' ') {
            out.push(' ');
        }
    }
    let n = out.trim_end().len();
    out.truncate(n);
    out
}

pub(crate) fn compact(folded: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(folded.len()));
    out.extend(folded.chars().filter(|c| *c != ' '));
    out
}

/// 一个字符的读法。多音字有多个。
#[derive(Clone)]
enum Unit {
    Plain(char),
    Han(char, Vec<&'static str>),
}

fn readings(c: char) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    let mut add = |p: &'static str| {
        // ü 用 v 输入
        let p = match p {
            "lü" => "lv",
            "nü" => "nv",
            "lüe" => "lve",
            "nüe" => "nve",
            p => p,
        };
        if p.is_ascii() && !v.contains(&p) {
            v.push(p);
        }
    };
    if let Some(p) = c.to_pinyin() {
        add(p.plain());
    }
    if let Some(m) = c.to_pinyin_multi() {
        for i in 0..m.count() {
            if let Some(p) = m.get_opt(i) {
                add(p.plain());
            }
        }
    }
    v
}

/// 建好索引的一段元数据文本。
#[derive(Clone)]
pub(crate) struct Indexed {
    pub folded: Zeroizing<String>,
    pub compact: Zeroizing<String>,
    units: Vec<Unit>,
    has_han: bool,
}

impl Indexed {
    pub(crate) fn new(s: &str) -> Self {
        let folded = fold(s);
        let compact = compact(&folded);
        let has_han = compact.chars().any(is_han);
        let units = if has_han {
            compact
                .chars()
                .map(|c| {
                    let r = if is_han(c) { readings(c) } else { Vec::new() };
                    if r.is_empty() {
                        Unit::Plain(c)
                    } else {
                        Unit::Han(c, r)
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        Self {
            folded,
            compact,
            units,
            has_han,
        }
    }

    fn words(&self) -> impl Iterator<Item = &str> {
        self.folded.split(' ').filter(|w| !w.is_empty())
    }
}

/// 拉丁词与一个字段的匹配程度，0..=1。
pub(crate) fn match_latin(term: &str, f: &Indexed) -> f32 {
    let mut best: f32 = 0.0;
    let n = term.chars().count();
    for w in f.words() {
        // “GitHub公司号”这样中英相连的词，也按拉丁片段比较
        for part in w.split(is_cjk).filter(|p| !p.is_empty()) {
            let s = if part == term {
                1.0
            } else if part.starts_with(term) {
                0.9
            } else {
                fuzzy(term, part)
            };
            best = best.max(s);
        }
    }
    if best < 0.75 && n >= 2 && f.compact.contains(term) {
        best = 0.75;
    }
    if best < 0.85 && n >= 2 && f.has_han && term.bytes().all(|b| b.is_ascii_alphanumeric()) {
        best = best.max(match_pinyin(term, f));
    }
    best
}

/// 全拼 0.85，首字母 0.72，混合 0.65。
fn match_pinyin(term: &str, f: &Indexed) -> f32 {
    // 合并已匹配相同查询前缀的路径，避免多音字重复展开。标志分别记录
    // 是否仍有全拼、全首字母或任意混合方式可以走到当前位置。
    const MIXED: u8 = 1;
    const INITIAL: u8 = 2;
    const FULL: u8 = 4;
    let mut current = vec![0u8; term.len() + 1];
    let mut next = current.clone();
    let mut active = 0;
    let mut best = 0;
    let plain_start = !f.compact.contains(term);
    for unit in &f.units {
        current[0] = if plain_start || matches!(unit, Unit::Han(..)) {
            MIXED | INITIAL | FULL
        } else {
            0
        };
        let mut end = 0;
        for (start, &flags) in current[..=active].iter().enumerate() {
            if flags == 0 {
                continue;
            }
            let rest = &term[start..];
            match unit {
                Unit::Plain(c) if rest.starts_with(*c) => {
                    let pos = start + c.len_utf8();
                    next[pos] |= flags;
                    end = end.max(pos);
                }
                Unit::Plain(_) => {}
                Unit::Han(_, readings) => {
                    for p in readings {
                        let common = p
                            .bytes()
                            .zip(rest.bytes())
                            .take_while(|(a, b)| a == b)
                            .count();
                        for n in 1..=common {
                            let pos = start + n;
                            let mut keep = MIXED;
                            if n == 1 {
                                keep |= INITIAL;
                            }
                            if n == p.len() || (pos == term.len() && n > 1) {
                                keep |= FULL;
                            }
                            next[pos] |= flags & keep;
                        }
                        end = end.max(start + common);
                    }
                }
            }
        }
        best |= next[term.len()];
        if best & FULL != 0 {
            return 0.85;
        }
        current[..=active].fill(0);
        next[term.len()] = 0;
        std::mem::swap(&mut next, &mut current);
        active = end.min(term.len() - 1);
    }
    if best & INITIAL != 0 {
        0.72
    } else if best != 0 {
        0.65
    } else {
        0.0
    }
}

/// 允许少量拼写错误；短词不做模糊，避免误中。
fn fuzzy(a: &str, b: &str) -> f32 {
    let (la, lb) = (a.chars().count(), b.chars().count());
    let max = match la {
        0..=3 => return 0.0,
        4..=7 => 1,
        _ => 2,
    };
    if la.abs_diff(lb) > max || lb > 64 || la > 64 {
        return 0.0;
    }
    match osa_distance(a, b, max) {
        Some(0) => 1.0,
        Some(1) => 0.6,
        Some(_) => 0.45,
        None => 0.0,
    }
}

/// 编辑距离（含相邻换位），超过 `max` 返回 `None`。
fn osa_distance(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut pp: Vec<usize> = vec![0; b.len() + 1];
    let mut p: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let sub = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (p[j] + 1).min(cur[j - 1] + 1).min(p[j - 1] + sub);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(pp[j - 2] + 1);
            }
            cur[j] = v;
        }
        if cur.iter().min().is_some_and(|m| *m > max) {
            return None;
        }
        pp = std::mem::replace(&mut p, cur);
    }
    p.last().copied().filter(|d| *d <= max)
}

/// 中日韩片段：整段命中。
pub(crate) fn match_cjk_exact(term: &str, f: &Indexed) -> f32 {
    if !f.compact.contains(term) {
        0.0
    } else if term.chars().count() == 1 {
        0.8
    } else {
        1.0
    }
}

/// 缩写（“招行”对“招商银行”）与同音字（“招伤银行”）。
pub(crate) fn match_cjk_loose(term: &[char], f: &Indexed) -> f32 {
    if term.len() < 2 || f.compact.is_empty() {
        return 0.0;
    }
    if homophone(term, f) {
        return 0.55;
    }
    if subsequence(term, &f.compact) {
        0.5
    } else {
        0.0
    }
}

fn subsequence(term: &[char], text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let window = term.len() * 2 + 1;
    chars
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == term[0])
        .any(|(i, _)| {
            let mut it = chars[i..].iter().take(window);
            term.iter().all(|t| it.any(|c| c == t))
        })
}

fn homophone(term: &[char], f: &Indexed) -> bool {
    if !f.has_han || term.len() > f.units.len() {
        return false;
    }
    let rs: Vec<Vec<&str>> = term.iter().map(|c| readings(*c)).collect();
    f.units.windows(term.len()).any(|w| {
        w.iter()
            .zip(term.iter().zip(&rs))
            .all(|(u, (c, r))| match u {
                Unit::Plain(x) => x == c,
                Unit::Han(x, ur) => x == c || ur.iter().any(|p| r.contains(p)),
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn folding() {
        assert_eq!(&*fold("  ＧｉｔＨｕｂ（公司）_账号!! "), "github 公司 账号");
        assert_eq!(&*compact("github 公司 账号"), "github公司账号");
        assert_eq!(&*fold("*** %% __"), "");
    }

    #[test]
    fn pinyin_forms() {
        let f = Indexed::new("招商银行");
        for (q, min, max) in [
            ("zhaoshangyinhang", 0.85, 0.85),
            ("yinhang", 0.85, 0.85),
            ("zsyh", 0.72, 0.72),
            ("zhsyh", 0.65, 0.65),
            ("zhaoshyh", 0.65, 0.65),
            ("zhaoshangyinh", 0.6, 0.85),
            ("xyz", 0.0, 0.0),
        ] {
            let s = match_latin(q, &f);
            assert!((min..=max).contains(&s), "{q} {s}");
        }
        // 多音字与 ü
        assert!(match_latin("chongqing", &Indexed::new("重庆")) >= 0.85);
        assert!(match_latin("lvyou", &Indexed::new("旅游")) >= 0.85);
        assert!(match_latin("nvzhuang", &Indexed::new("女装")) >= 0.85);
        // 中英混合
        assert!(match_latin("qqyx", &Indexed::new("QQ邮箱")) >= 0.65);
        assert!(match_latin("qqyouxiang", &Indexed::new("QQ邮箱")) >= 0.85);
    }

    #[test]
    fn typos() {
        assert_eq!(osa_distance("github", "githbu", 1), Some(1));
        assert_eq!(osa_distance("github", "gitlab", 1), None);
        assert!(match_latin("gihtub", &Indexed::new("GitHub")) > 0.5);
        assert!(match_latin("cloudflear", &Indexed::new("Cloudflare")) > 0.4);
        assert_eq!(match_latin("abc", &Indexed::new("abd")), 0.0);
    }

    #[test]
    fn cjk_loose() {
        let f = Indexed::new("招商银行");
        assert_eq!(match_cjk_exact("银行", &f), 1.0);
        assert!(match_cjk_loose(&['招', '行'], &f) > 0.0);
        assert!(match_cjk_loose(&"招伤银行".chars().collect::<Vec<_>>(), &f) > 0.0);
        assert_eq!(match_cjk_loose(&['行', '招'], &f), 0.0);
    }

    proptest! {
        #[test]
        fn never_panics_and_is_bounded(q in "\\PC{1,30}", t in "\\PC{0,60}") {
            let f = Indexed::new(&t);
            let q = compact(&fold(&q));
            let s = match_latin(&q, &f);
            prop_assert!((0.0..=1.0).contains(&s));
            let cs: Vec<char> = q.chars().collect();
            prop_assert!((0.0..=1.0).contains(&match_cjk_loose(&cs, &f)));
        }

        #[test]
        fn fold_is_idempotent(s in "\\PC{0,40}") {
            let a = fold(&s);
            prop_assert_eq!(&fold(&a)[..], &a[..]);
        }
    }
}
