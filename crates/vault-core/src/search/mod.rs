//! 检索。本机搜索与 AI 搜索共用打分算法，但入口、可见范围、返回类型都不同：
//!
//! - 本机：[`crate::Vault::search`]，需完全解锁，返回 [`LocalHit`]。
//! - AI：[`crate::Vault::ai`] 得到 [`AiGateway`]，只用元数据，返回 [`AiSearchHit`]。

pub(crate) mod ai;
pub(crate) mod query;
pub(crate) mod quota;
pub(crate) mod text;

pub use ai::{AiGateway, AiSearchError, AiSearchHit, ClientId, ItemRef};

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::model::{ItemId, ItemMeta, MetaRecord};
use query::{Query, Term};
use text::{Indexed, match_cjk_exact, match_cjk_loose, match_latin};

/// 命中位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedIn {
    Title,
    Domain,
    Tag,
    Hint,
    /// 账号全文，只在本机搜索中出现。
    Account,
    /// 正文、备注、网址、自定义字段名，只在本机搜索中出现。
    Content,
}

/// 本机搜索的一条结果。
#[derive(Clone)]
pub struct LocalHit {
    pub meta: ItemMeta,
    pub score: f32,
    pub matched: Vec<MatchedIn>,
}

const W_TITLE: f32 = 1.0;
const W_DOMAIN: f32 = 0.95;
const W_TAG: f32 = 0.85;
const W_HINT: f32 = 0.75;
const W_ACCOUNT: f32 = 0.8;
const W_CONTENT: f32 = 0.5;
const THRESHOLD: f32 = 0.35;

/// 一条记录的元数据索引，只在内存中。
#[derive(Clone)]
pub(crate) struct MetaIndex {
    title: Indexed,
    domains: Vec<(String, Indexed)>,
    tags: Vec<Indexed>,
    hint: Indexed,
}

impl MetaIndex {
    pub(crate) fn new(r: &MetaRecord) -> Self {
        Self {
            title: Indexed::new(&r.title),
            domains: r
                .domains
                .iter()
                .map(|d| (d.clone(), Indexed::new(d)))
                .collect(),
            tags: r.tags.iter().map(|t| Indexed::new(t)).collect(),
            hint: Indexed::new(&r.hint),
        }
    }

    fn fields(&self) -> impl Iterator<Item = (MatchedIn, f32, &Indexed)> {
        std::iter::once((MatchedIn::Title, W_TITLE, &self.title))
            .chain(
                self.domains
                    .iter()
                    .map(|(_, d)| (MatchedIn::Domain, W_DOMAIN, d)),
            )
            .chain(self.tags.iter().map(|t| (MatchedIn::Tag, W_TAG, t)))
            .chain(std::iter::once((MatchedIn::Hint, W_HINT, &self.hint)))
    }
}

/// 账号与正文的内存索引，只在完全解锁时存在，锁定即清零。不含密码、TOTP 与自定义字段值。
pub(crate) struct SecretIndex(pub BTreeMap<ItemId, SecretText>);

pub(crate) struct SecretText {
    pub account: Zeroizing<String>,
    pub content: Zeroizing<String>,
}

#[derive(Default)]
pub(crate) struct Score {
    pub total: f32,
    pub matched: Vec<MatchedIn>,
}

impl Score {
    fn note(&mut self, m: MatchedIn) {
        if !self.matched.contains(&m) {
            self.matched.push(m);
        }
    }
}

/// 打分。`secret` 为 `None` 时只看元数据；AI 搜索永远传 `None`。
pub(crate) fn score(q: &Query, idx: &MetaIndex, secret: Option<&SecretText>) -> Option<Score> {
    if q.terms.is_empty() {
        return None;
    }
    let mut out = Score::default();
    let (mut sum, mut weights) = (0.0f32, 0.0f32);
    for t in &q.terms {
        let w = t.weight();
        weights += w;
        sum += w * term_score(t, idx, secret, &mut out);
    }
    out.total = sum / weights;
    if out.total < THRESHOLD {
        return None;
    }
    if *q.compact == *idx.title.compact {
        out.total += 0.2;
    }
    Some(out)
}

fn term_score(t: &Term, idx: &MetaIndex, secret: Option<&SecretText>, out: &mut Score) -> f32 {
    let mut best = 0.0f32;
    let mut take = |m: MatchedIn, s: f32, out: &mut Score| {
        if s > 0.0 {
            out.note(m);
            best = best.max(s);
        }
    };
    match t {
        Term::Latin(s) => {
            for (m, w, f) in idx.fields() {
                take(m, w * match_latin(s, f), out);
            }
        }
        Term::Host(h) => {
            for (d, _) in &idx.domains {
                take(MatchedIn::Domain, host_score(h, d), out);
            }
            let words = text::fold(h);
            let c = text::compact(&words);
            for (m, w, f) in idx.fields() {
                let s = if f.compact.contains(c.as_str()) {
                    0.8
                } else {
                    0.0
                };
                take(m, w * s, out);
            }
            // 标题里常只写站名：github.com 也应找到“GitHub”
            if let Some(name) = words.split(' ').rev().nth(1).filter(|n| n.len() >= 3) {
                let s = match_latin(name, &idx.title);
                take(MatchedIn::Title, if s >= 0.9 { 0.7 } else { 0.0 }, out);
            }
        }
        Term::Cjk { text, chars } => {
            for (m, w, f) in idx.fields() {
                take(m, w * match_cjk_exact(text, f), out);
            }
            if chars.len() > 2 {
                let s = bigram_score(chars, idx, out);
                take_max(&mut best, s);
            }
            if best < 0.5 {
                for (m, w, f) in idx.fields() {
                    let s = w * match_cjk_loose(chars, f);
                    if s > 0.0 {
                        out.note(m);
                        take_max(&mut best, s);
                    }
                }
            }
        }
    }
    if let Some(sec) = secret {
        let needle = match t {
            Term::Latin(s) => s.clone(),
            Term::Host(h) => text::compact(&text::fold(h)).to_string(),
            Term::Cjk { text, .. } => text.clone(),
        };
        for (m, w, hay) in [
            (MatchedIn::Account, W_ACCOUNT, &sec.account),
            (MatchedIn::Content, W_CONTENT, &sec.content),
        ] {
            if hay.contains(&needle) {
                out.note(m);
                take_max(&mut best, w);
            }
        }
    }
    best
}

fn take_max(best: &mut f32, s: f32) {
    *best = best.max(s);
}

/// 相邻二字的命中率，跨字段合并。命中不到三分之一视为无关。
fn bigram_score(chars: &[char], idx: &MetaIndex, out: &mut Score) -> f32 {
    let mut total = 0.0;
    let mut hits = 0;
    let mut where_hit = Vec::new();
    let n = chars.len() - 1;
    for pair in chars.windows(2) {
        let gram: String = pair.iter().collect();
        let best = idx
            .fields()
            .filter(|(_, _, f)| f.compact.contains(&gram))
            .max_by(|a, b| a.1.total_cmp(&b.1));
        if let Some((m, w, _)) = best {
            total += w;
            hits += 1;
            where_hit.push(m);
        }
    }
    if hits * 3 < n {
        return 0.0;
    }
    where_hit.into_iter().for_each(|m| out.note(m));
    0.85 * total / n as f32
}

/// 完全相等 1.0；子域关系 0.9；子域关系要求较短一方至少两级且不只是公共后缀。
fn host_score(query: &str, domain: &str) -> f32 {
    if query == domain {
        return 1.0;
    }
    let under = |long: &str, short: &str| {
        short.contains('.')
            && long
                .strip_suffix(short)
                .is_some_and(|head| head.ends_with('.'))
    };
    if under(domain, query) || under(query, domain) {
        0.9
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemDraft, ItemKind};

    fn idx(title: &str, domain: &str, tags: &[&str], hint: &str) -> MetaIndex {
        let mut d = ItemDraft::new(ItemKind::Login, title);
        if !domain.is_empty() {
            d.domains = vec![domain.into()];
        }
        d.tags = tags.iter().map(|s| (*s).to_owned()).collect();
        d.hint = hint.into();
        d.secrets.password = Some("假-FAKE-0000".into());
        MetaIndex::new(&d.prepare(0, 0).unwrap().record)
    }

    fn sample() -> Vec<MetaIndex> {
        vec![
            idx("GitHub", "github.com", &["公司"], "代码仓库"),
            idx("GitHub 个人", "github.com", &["个人"], ""),
            idx(
                "招商银行",
                "cmbchina.com",
                &["银行", "信用卡"],
                "工资卡网银",
            ),
            idx("QQ 邮箱", "mail.qq.com", &["邮箱"], ""),
            idx("家里路由器", "192.168.1.1", &["网络"], "客厅的 TP-Link"),
            idx("重庆社保", "", &[], "公积金查询"),
        ]
    }

    fn rank(q: &str) -> Vec<usize> {
        let q = Query::parse_lenient(q);
        let mut v: Vec<(usize, f32)> = sample()
            .iter()
            .enumerate()
            .filter_map(|(i, x)| score(&q, x, None).map(|s| (i, s.total)))
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter().map(|x| x.0).collect()
    }

    #[test]
    fn finds_by_every_route() {
        for (q, want) in [
            ("GitHub", 0),
            ("公司那个github账号", 0),
            ("个人 github", 1),
            ("ＧＩＴＨＵＢ 个人", 1),
            ("gihtub 个人", 1),
            ("招商", 2),
            ("招行", 2),
            ("zsyh", 2),
            ("zhaoshang", 2),
            ("招伤银行", 2),
            ("工资卡", 2),
            ("招商银行信用卡网银", 2),
            ("cmbchina.com", 2),
            ("https://www.cmbchina.com/login?x=1", 2),
            ("qq邮箱", 3),
            ("qq.com", 3),
            ("youxiang", 3),
            ("路由器", 4),
            ("luyouqi", 4),
            ("tplink", 4),
            ("客厅", 4),
            ("cqsb", 5),
            ("chongqing", 5),
            ("公积金", 5),
        ] {
            assert_eq!(rank(q).first(), Some(&want), "{q} -> {:?}", rank(q));
        }
    }

    #[test]
    fn unrelated_queries_return_nothing() {
        for q in [
            "支付宝",
            "netflix",
            "xyzzy",
            "淘宝网购物",
            "example.org",
            "?",
        ] {
            assert_eq!(rank(q), Vec::<usize>::new(), "{q}");
        }
    }

    #[test]
    fn github_com_finds_both_and_not_lookalikes() {
        assert_eq!(rank("github.com").len(), 2);
        assert_eq!(host_score("hub.com", "github.com"), 0.0);
        assert_eq!(host_score("com", "github.com"), 0.0);
    }
}
