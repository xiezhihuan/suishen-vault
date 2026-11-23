//! 条目模型。元数据与机密内容是两组不同的类型。

use std::fmt;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::error::{Error, InvalidItem, Result};
use crate::mask::mask_account;
use crate::policy;
use crate::secret::{SecretString, random_array};
use crate::totp::Totp;

/// 条目 ID。刻意不实现 `Serialize`：给 AI 的只能是 [`crate::search::ItemRef`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId(pub(crate) [u8; 16]);

impl ItemId {
    pub(crate) fn random() -> Result<Self> {
        random_array().map(Self)
    }

    pub fn to_hex(self) -> String {
        hex(&self.0)
    }

    pub fn parse(s: &str) -> Option<Self> {
        unhex(s).map(Self)
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    b.iter()
        .flat_map(|b| {
            [
                D[usize::from(b >> 4)] as char,
                D[usize::from(b & 15)] as char,
            ]
        })
        .collect()
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0; N];
    for (o, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        let d = |c: u8| (c as char).to_digit(16);
        *o = (d(pair[0])? * 16 + d(pair[1])?) as u8;
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Note,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaField {
    Title,
    Domain,
    Tag,
    Hint,
}

impl fmt::Display for MetaField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Title => "标题",
            Self::Domain => "域名",
            Self::Tag => "标签",
            Self::Hint => "检索提示",
        })
    }
}

/// 机密字段种类。数值写入 AAD，不得改动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FieldKind {
    Username = 1,
    Password = 2,
    Url = 3,
    Note = 4,
    Totp = 5,
    Body = 6,
    Custom = 7,
}

impl FieldKind {
    const ALL: [Self; 7] = [
        Self::Username,
        Self::Password,
        Self::Url,
        Self::Note,
        Self::Totp,
        Self::Body,
        Self::Custom,
    ];

    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u8 == v)
    }

    fn allowed_for(self, kind: ItemKind) -> bool {
        match kind {
            ItemKind::Login => self != Self::Body,
            ItemKind::Note => matches!(self, Self::Body | Self::Custom),
            ItemKind::Custom => self == Self::Custom,
        }
    }
}

/// AI 可以申请的字段。TOTP 种子不在其中。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiField {
    Username,
    Password,
    Url,
    Note,
    Body,
    Custom,
}

impl AiField {
    /// 由类型固定决定，所以不会泄露某条实际有哪些字段。
    pub const fn requestable(kind: ItemKind) -> &'static [AiField] {
        match kind {
            ItemKind::Login => &[Self::Username, Self::Password, Self::Url, Self::Note],
            ItemKind::Note => &[Self::Body],
            ItemKind::Custom => &[Self::Custom],
        }
    }

    pub(crate) const fn field(self) -> FieldKind {
        match self {
            Self::Username => FieldKind::Username,
            Self::Password => FieldKind::Password,
            Self::Url => FieldKind::Url,
            Self::Note => FieldKind::Note,
            Self::Body => FieldKind::Body,
            Self::Custom => FieldKind::Custom,
        }
    }
}

/// 自定义字段，名称与值都按机密保存。
pub struct CustomField {
    pub name: SecretString,
    pub value: SecretString,
}

/// 一条记录的全部机密内容。
#[derive(Default)]
pub struct Secrets {
    pub username: Option<SecretString>,
    pub password: Option<SecretString>,
    pub urls: Vec<SecretString>,
    pub note: Option<SecretString>,
    /// Base32 种子或 `otpauth://` 链接。
    pub totp: Option<SecretString>,
    pub body: Option<SecretString>,
    pub custom: Vec<CustomField>,
}

/// 新增或修改时的输入。
pub struct ItemDraft {
    pub kind: ItemKind,
    pub title: String,
    /// 用户另外填写的域名；网址里的域名在 `auto_domains` 打开时自动加入。
    pub domains: Vec<String>,
    pub auto_domains: bool,
    pub tags: Vec<String>,
    /// 检索提示，AI 能按它搜索，不要写密码。
    pub hint: String,
    pub ai_hidden: bool,
    pub secrets: Secrets,
}

impl ItemDraft {
    pub fn new(kind: ItemKind, title: &str) -> Self {
        Self {
            kind,
            title: title.to_owned(),
            domains: Vec::new(),
            auto_domains: true,
            tags: Vec::new(),
            hint: String::new(),
            ai_hidden: false,
            secrets: Secrets::default(),
        }
    }
}

/// 元数据视图。不含任何机密字段。
#[derive(Clone, PartialEq, Eq)]
pub struct ItemMeta {
    pub id: ItemId,
    pub kind: ItemKind,
    pub title: String,
    pub domains: Vec<String>,
    pub tags: Vec<String>,
    pub hint: String,
    pub masked_account: Option<String>,
    pub ai_hidden: bool,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub deleted_ms: Option<i64>,
}

/// 完整条目，只在完全解锁时可得。
pub struct Item {
    pub meta: ItemMeta,
    pub secrets: Secrets,
}

/// 批准后解密出的单个字段。
pub struct RevealedField {
    pub name: AiField,
    pub value: RevealedValue,
}

pub enum RevealedValue {
    Text(SecretString),
    Pairs(Vec<CustomField>),
}

/// 加密后写入 `item.blob` 的元数据。
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MetaRecord {
    pub kind: ItemKind,
    pub title: String,
    pub domains: Vec<String>,
    pub tags: Vec<String>,
    pub hint: String,
    pub masked_account: Option<String>,
    pub ai_hidden: bool,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub deleted_ms: Option<i64>,
    pub fields: Vec<FieldRef>,
}

/// 指向 `item_field` 的一行。`digest` 是该行密文的 SHA-256，单行被换成旧版本会被发现。
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FieldRef {
    pub kind: u8,
    pub id: String,
    pub rev: u64,
    pub digest: String,
}

impl MetaRecord {
    pub(crate) fn view(&self, id: ItemId) -> ItemMeta {
        ItemMeta {
            id,
            kind: self.kind,
            title: self.title.clone(),
            domains: self.domains.clone(),
            tags: self.tags.clone(),
            hint: self.hint.clone(),
            masked_account: self.masked_account.clone(),
            ai_hidden: self.ai_hidden,
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
            deleted_ms: self.deleted_ms,
        }
    }

    /// 是否允许出现在 AI 搜索与授权中。
    pub(crate) fn ai_visible(&self) -> bool {
        !self.ai_hidden && self.deleted_ms.is_none()
    }
}

/// 去掉控制字符、双向文本与零宽字符，合并空白。
pub(crate) fn clean_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_unsafe_display(c) {
            continue;
        }
        if c.is_whitespace() || c.is_control() {
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }
    out.truncate(out.trim_end().len());
    out
}

fn is_unsafe_display(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// 从网址或域名取主机名，去掉 `www.`。没有协议且不像域名的文本返回 `None`，
/// 以免把误填的内容写进元数据。
pub(crate) fn host_of(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() || s.chars().any(char::is_whitespace) {
        return None;
    }
    let has_scheme = s.contains("://");
    let parsed = if has_scheme {
        url::Url::parse(s).ok()?
    } else {
        url::Url::parse(&format!("https://{s}")).ok()?
    };
    let host = parsed
        .host_str()?
        .trim_matches(['[', ']', '.'])
        .to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    let looks_like_host = host.contains(['.', ':']) || host == "localhost";
    (!host.is_empty() && (has_scheme || looks_like_host)).then_some(host)
}

fn fold_for_check(s: &str) -> Zeroizing<String> {
    let it = || {
        s.nfkc()
            .flat_map(char::to_lowercase)
            .filter(|c| !c.is_whitespace())
    };
    let mut out = Zeroizing::new(String::with_capacity(it().map(char::len_utf8).sum()));
    out.extend(it());
    out
}

/// 编码后的单个机密字段。
pub(crate) struct EncodedField {
    pub kind: FieldKind,
    pub plain: Zeroizing<Vec<u8>>,
}

/// 校验并规整后的草稿。
pub(crate) struct Prepared {
    pub record: MetaRecord,
    pub fields: Vec<EncodedField>,
}

/// 整理元数据部分。
pub(crate) fn normalize_meta(d: &ItemDraft) -> Result<(String, Vec<String>, Vec<String>, String)> {
    let invalid = |e| Err(Error::InvalidItem(e));
    let title = clean_line(&d.title);
    if title.is_empty() {
        return invalid(InvalidItem::EmptyTitle);
    }
    if title.chars().count() > policy::MAX_TITLE_CHARS {
        return invalid(InvalidItem::TooLong(MetaField::Title));
    }
    let mut tags: Vec<String> = Vec::new();
    for t in d
        .tags
        .iter()
        .map(|t| clean_line(t))
        .filter(|t| !t.is_empty())
    {
        if t.chars().count() > policy::MAX_TAG_CHARS {
            return invalid(InvalidItem::TooLong(MetaField::Tag));
        }
        if !tags.contains(&t) {
            tags.push(t);
        }
    }
    if tags.len() > policy::MAX_TAGS {
        return invalid(InvalidItem::TooManyTags);
    }
    let hint = clean_line(&d.hint);
    if hint.chars().count() > policy::MAX_HINT_CHARS {
        return invalid(InvalidItem::TooLong(MetaField::Hint));
    }
    let mut domains: Vec<String> = Vec::new();
    for raw in &d.domains {
        let Some(h) = host_of(raw) else {
            return invalid(InvalidItem::BadDomain);
        };
        if !domains.contains(&h) {
            domains.push(h);
        }
    }
    if d.auto_domains {
        for h in d.secrets.urls.iter().filter_map(|u| host_of(u.expose())) {
            if !domains.contains(&h) {
                domains.push(h);
            }
        }
    }
    if domains.len() > policy::MAX_DOMAINS {
        return invalid(InvalidItem::TooManyDomains);
    }
    if domains.iter().any(|h| h.len() > 255) {
        return invalid(InvalidItem::TooLong(MetaField::Domain));
    }
    Ok((title, domains, tags, hint))
}

/// 元数据里是否混入本条的密码、账号全文或 TOTP 种子（长度不少于 4）。AC-VLT-08
pub(crate) fn leaked_into(secrets: &Secrets, text: &str) -> bool {
    let hay = fold_for_check(text);
    [&secrets.password, &secrets.username, &secrets.totp]
        .into_iter()
        .flatten()
        .map(|s| fold_for_check(s.expose()))
        .any(|n| n.chars().count() >= 4 && hay.contains(n.as_str()))
}

impl ItemDraft {
    pub(crate) fn prepare(&self, created_ms: i64, now_ms: i64) -> Result<Prepared> {
        let (title, domains, tags, hint) = normalize_meta(self)?;
        let s = &self.secrets;
        let leaks = [
            (MetaField::Title, leaked_into(s, &title)),
            (MetaField::Domain, domains.iter().any(|x| leaked_into(s, x))),
            (MetaField::Tag, tags.iter().any(|x| leaked_into(s, x))),
            (MetaField::Hint, leaked_into(s, &hint)),
        ];
        if let Some((f, _)) = leaks.into_iter().find(|(_, hit)| *hit) {
            return Err(Error::SecretInMetadata(f));
        }
        if let Some(t) = &s.totp {
            Totp::parse(t)?;
        }
        let fields = s.encode()?;
        if fields.is_empty() {
            return Err(Error::InvalidItem(InvalidItem::Empty));
        }
        if fields.iter().any(|f| !f.kind.allowed_for(self.kind)) {
            return Err(Error::InvalidItem(InvalidItem::FieldNotForKind));
        }
        Ok(Prepared {
            record: MetaRecord {
                kind: self.kind,
                title,
                domains,
                tags,
                hint,
                masked_account: s.username.as_ref().map(|u| mask_account(u.expose())),
                ai_hidden: self.ai_hidden,
                created_ms,
                updated_ms: now_ms,
                deleted_ms: None,
                fields: Vec::new(),
            },
            fields,
        })
    }
}

impl Secrets {
    fn encode(&self) -> Result<Vec<EncodedField>> {
        let mut out = Vec::new();
        let mut push = |kind, plain: Zeroizing<Vec<u8>>| {
            if plain.len() > policy::MAX_SECRET_BYTES {
                return Err(Error::InvalidItem(InvalidItem::SecretTooLong));
            }
            out.push(EncodedField { kind, plain });
            Ok(())
        };
        for (kind, v) in [
            (FieldKind::Username, &self.username),
            (FieldKind::Password, &self.password),
            (FieldKind::Note, &self.note),
            (FieldKind::Totp, &self.totp),
            (FieldKind::Body, &self.body),
        ] {
            if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
                push(kind, Zeroizing::new(v.expose().as_bytes().to_vec()))?;
            }
        }
        let urls: Vec<&str> = self
            .urls
            .iter()
            .map(|u| u.expose().trim())
            .filter(|u| !u.is_empty())
            .collect();
        if !urls.is_empty() {
            let mut buf =
                Zeroizing::new(Vec::with_capacity(urls.iter().map(|u| u.len() + 1).sum()));
            for (i, u) in urls.iter().enumerate() {
                if i > 0 {
                    buf.push(b'\n');
                }
                buf.extend(u.bytes().filter(|b| !matches!(b, b'\n' | b'\r')));
            }
            push(FieldKind::Url, buf)?;
        }
        if !self.custom.is_empty() {
            push(FieldKind::Custom, encode_custom(&self.custom)?)?;
        }
        Ok(out)
    }

    pub(crate) fn set(&mut self, kind: FieldKind, plain: Zeroizing<Vec<u8>>) -> Result<()> {
        match kind {
            FieldKind::Username => self.username = Some(SecretString::from_utf8(plain)?),
            FieldKind::Password => self.password = Some(SecretString::from_utf8(plain)?),
            FieldKind::Note => self.note = Some(SecretString::from_utf8(plain)?),
            FieldKind::Totp => self.totp = Some(SecretString::from_utf8(plain)?),
            FieldKind::Body => self.body = Some(SecretString::from_utf8(plain)?),
            FieldKind::Url => {
                let all = SecretString::from_utf8(plain)?;
                self.urls = all.expose().split('\n').map(SecretString::from).collect();
            }
            FieldKind::Custom => self.custom = decode_custom(&plain)?,
        }
        Ok(())
    }

    /// 完整复制，用于编辑时由现有条目构造草稿。
    pub fn duplicate(&self) -> Self {
        let dup = |o: &Option<SecretString>| o.as_ref().map(SecretString::duplicate);
        Self {
            username: dup(&self.username),
            password: dup(&self.password),
            urls: self.urls.iter().map(SecretString::duplicate).collect(),
            note: dup(&self.note),
            totp: dup(&self.totp),
            body: dup(&self.body),
            custom: self
                .custom
                .iter()
                .map(|c| CustomField {
                    name: c.name.duplicate(),
                    value: c.value.duplicate(),
                })
                .collect(),
        }
    }
}

impl Item {
    /// 由现有条目得到可编辑的草稿。
    pub fn to_draft(&self) -> ItemDraft {
        ItemDraft {
            kind: self.meta.kind,
            title: self.meta.title.clone(),
            domains: self.meta.domains.clone(),
            auto_domains: true,
            tags: self.meta.tags.clone(),
            hint: self.meta.hint.clone(),
            ai_hidden: self.meta.ai_hidden,
            secrets: self.secrets.duplicate(),
        }
    }
}

pub(crate) fn encode_custom(fields: &[CustomField]) -> Result<Zeroizing<Vec<u8>>> {
    if fields.len() > policy::MAX_CUSTOM_FIELDS {
        return Err(Error::InvalidItem(InvalidItem::TooManyCustomFields));
    }
    let cap = fields
        .iter()
        .map(|f| 8 + f.name.expose().len() + f.value.expose().len())
        .sum::<usize>();
    let mut w = Writer::with_capacity(4 + cap);
    w.len(fields.len())?;
    for f in fields {
        w.bytes(f.name.expose().as_bytes())?;
        w.bytes(f.value.expose().as_bytes())?;
    }
    Ok(w.finish())
}

pub(crate) fn decode_custom(plain: &[u8]) -> Result<Vec<CustomField>> {
    let mut r = Reader::new(plain);
    let n = r.count(8)?;
    let text = |r: &mut Reader<'_>| SecretString::from_utf8(Zeroizing::new(r.bytes()?.to_vec()));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(CustomField {
            name: text(&mut r)?,
            value: text(&mut r)?,
        });
    }
    r.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn host_extraction() {
        for (i, want) in [
            (
                "https://user:pw@www.Example.com:8443/a?b=c",
                Some("example.com"),
            ),
            ("example.com/login", Some("example.com")),
            ("http://192.168.1.1/", Some("192.168.1.1")),
            ("android://hash@com.example.app/", Some("com.example.app")),
            ("http://nas/", Some("nas")),
            ("localhost:3000", Some("localhost")),
            ("P@ssw0rd", None),
            ("随便写的 文字", None),
            ("", None),
        ] {
            assert_eq!(host_of(i).as_deref(), want, "{i}");
        }
    }

    #[test]
    fn clean_line_removes_control_and_bidi() {
        assert_eq!(clean_line(" a\u{202E}b\u{0}\n\tc\u{200B} "), "ab c");
    }

    // AC-VLT-08
    #[test]
    fn secrets_in_metadata_are_rejected() {
        let base = || {
            let mut d = ItemDraft::new(ItemKind::Login, "公司邮箱");
            d.secrets.username = Some("fake.user@example.test".into());
            d.secrets.password = Some("Fake-Pw-123".into());
            d
        };
        assert!(base().prepare(0, 0).is_ok());
        type Edit = fn(&mut ItemDraft);
        let cases: [(MetaField, Edit); 5] = [
            (MetaField::Title, |d| {
                d.title = "邮箱 ＦＡＫＥ-pw-123".into()
            }),
            (MetaField::Hint, |d| {
                d.hint = "密码是 fake - PW - 123".into()
            }),
            (MetaField::Tag, |d| {
                d.tags = vec!["Fake.User@example.test".into()]
            }),
            (MetaField::Domain, |d| {
                d.secrets.username = Some("admin".into());
                d.secrets.urls = vec!["https://admin.example.test".into()];
            }),
            (MetaField::Title, |d| {
                d.title = "x FAKEFAKEFAKEFAKE".into();
                d.secrets.totp = Some("FAKEFAKEFAKEFAKE".into());
            }),
        ];
        for (f, edit) in cases {
            let mut d = base();
            edit(&mut d);
            assert_eq!(d.prepare(0, 0).err(), Some(Error::SecretInMetadata(f)));
        }
        // 短于 4 个字符不检查
        let mut d = base();
        d.secrets.password = Some("公司".into());
        assert!(d.prepare(0, 0).is_ok());
        // 域名冲突时可关掉自动域名
        let mut d = base();
        d.secrets.username = Some("admin".into());
        d.secrets.urls = vec!["https://admin.example.test".into()];
        d.auto_domains = false;
        assert!(d.prepare(0, 0).is_ok());
    }

    #[test]
    fn fields_must_fit_the_kind() {
        let mut d = ItemDraft::new(ItemKind::Note, "笔记");
        assert_eq!(
            d.prepare(0, 0).err(),
            Some(Error::InvalidItem(InvalidItem::Empty))
        );
        d.secrets.password = Some("假".into());
        assert_eq!(
            d.prepare(0, 0).err(),
            Some(Error::InvalidItem(InvalidItem::FieldNotForKind))
        );
    }

    #[test]
    fn totp_is_never_requestable() {
        for k in [ItemKind::Login, ItemKind::Note, ItemKind::Custom] {
            for f in AiField::requestable(k) {
                assert_ne!(f.field(), FieldKind::Totp);
                assert!(f.field().allowed_for(k));
            }
        }
    }

    proptest! {
        #[test]
        fn custom_round_trip(v in prop::collection::vec(("\\PC{0,20}", "\\PC{0,40}"), 0..10)) {
            let fields: Vec<_> = v.iter()
                .map(|(n, x)| CustomField { name: n.as_str().into(), value: x.as_str().into() })
                .collect();
            let back = decode_custom(&encode_custom(&fields).unwrap()).unwrap();
            prop_assert_eq!(back.len(), v.len());
            for (b, (n, x)) in back.iter().zip(&v) {
                prop_assert_eq!(b.name.expose(), n);
                prop_assert_eq!(b.value.expose(), x);
            }
        }

        #[test]
        fn custom_decoding_never_panics(b in prop::collection::vec(any::<u8>(), 0..200)) {
            let _ = decode_custom(&b);
        }

        #[test]
        fn host_never_panics(s in "\\PC{0,60}") {
            let _ = host_of(&s);
            let _ = clean_line(&s);
        }
    }
}
