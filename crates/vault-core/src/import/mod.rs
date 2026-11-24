//! 从其他密码管理器导入 CSV：Chrome、Bitwarden、KeePass（1.x/2.x 的 CSV 与 KeePassXC）。
//!
//! 原则：不丢数据。元数据里混有机密时自动挪到机密字段并在报告中说明；
//! 无法识别的内容列出行号，不静默丢弃。导入完成后提示用户删除明文 CSV。

mod csv;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::model::{CustomField, ItemDraft, ItemKind, clean_line, host_of, leaked_into};
use crate::policy;
use crate::sealed::sha256;
use crate::secret::SecretString;
use crate::vault::Vault;

pub use csv::Dialect;
use csv::{Row, parse};

/// 导入后界面必须显示的提示。
pub const DELETE_CSV_PROMPT: &str = "导入完成。原 CSV 文件是未加密的明文，任何人打开都能看到全部密码。\
请确认内容无误后立即删除它，并清空回收站、删除网盘或聊天软件里的副本。";
/// 有行未能导入时改用的提示。
pub const DELETE_CSV_PROMPT_PARTIAL: &str = "有部分行没有导入。请先核对下列行号并手工补录，\
再删除这个未加密的明文 CSV 文件。";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvFormat {
    Chrome,
    Bitwarden,
    /// KeePass 1.x/2.x 导出的 CSV。
    KeePass,
    KeePassXc,
}

/// 自动调整，按行报告，不含内容。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjustment {
    /// 标题为空，用域名或序号代替。
    TitleGenerated,
    /// 标题含账号或密码，原标题改存为机密的自定义字段。
    TitleMoved,
    /// 标题过长，完整标题改存为自定义字段。
    TitleShortened,
    /// 域名与账号重合，未写入元数据（网址仍保存在机密字段）。
    DomainOmitted,
    /// 标签含账号或密码，改存为自定义字段。
    TagMoved,
    /// TOTP 无法识别，原文改存为自定义字段。
    TotpMoved,
    /// 该类型没有对应位置的列，改存为自定义字段。
    ExtraKept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// 列数与表头不符。
    ColumnCount,
    /// 内容超出大小限制。
    TooLarge,
    /// 内容不符合要求。
    Invalid,
}

/// 导入报告。不含任何明文内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub format: CsvFormat,
    pub imported: usize,
    /// 完全空白的行数。
    pub blank: usize,
    /// (数据行序号，从 1 起；调整)
    pub adjusted: Vec<(usize, Adjustment)>,
    pub rejected: Vec<(usize, RejectReason)>,
    source: PathBuf,
    source_digest: [u8; 32],
}

impl ImportReport {
    /// 界面必须显示的删除提示。
    pub fn delete_prompt(&self) -> &'static str {
        if self.rejected.is_empty() {
            DELETE_CSV_PROMPT
        } else {
            DELETE_CSV_PROMPT_PARTIAL
        }
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    /// 用户同意后删除明文 CSV：先核对内容没有变化，再覆写并删除。
    ///
    /// 固态硬盘与网盘同步无法保证不留副本。
    pub fn delete_source(&self) -> Result<()> {
        let now = fsutil::read_limited(&self.source, policy::MAX_CSV_BYTES)?;
        if sha256(&now) != self.source_digest {
            return Err(Error::SourceChanged);
        }
        fsutil::overwrite_and_remove(&self.source)
    }
}

impl Vault {
    /// 导入 CSV。`format` 为 `None` 时按表头识别。全部条目在一个事务里写入。
    pub fn import_csv(&mut self, path: &Path, format: Option<CsvFormat>) -> Result<ImportReport> {
        self.writable()?;
        let bytes = fsutil::read_limited(path, policy::MAX_CSV_BYTES)?;
        let mut report = self.import_csv_bytes(&bytes, format)?;
        report.source = path.to_owned();
        Ok(report)
    }

    /// 从系统文档流导入，不在磁盘上另存一份明文 CSV。
    pub fn import_csv_bytes(
        &mut self,
        bytes: &[u8],
        format: Option<CsvFormat>,
    ) -> Result<ImportReport> {
        self.writable()?;
        if bytes.len() as u64 > policy::MAX_CSV_BYTES {
            return Err(Error::TooLarge);
        }
        let parsed = parse_drafts(bytes, format)?;
        if !parsed.drafts.is_empty() {
            self.add_many(&parsed.drafts)?;
        }
        Ok(ImportReport {
            format: parsed.format,
            imported: parsed.drafts.len(),
            blank: parsed.blank,
            adjusted: parsed.adjusted,
            rejected: parsed.rejected,
            source: PathBuf::new(),
            source_digest: sha256(bytes),
        })
    }
}

pub(crate) struct Parsed {
    pub format: CsvFormat,
    pub drafts: Vec<ItemDraft>,
    pub blank: usize,
    pub adjusted: Vec<(usize, Adjustment)>,
    pub rejected: Vec<(usize, RejectReason)>,
}

struct Header {
    format: CsvFormat,
    names: Vec<String>,
}

fn header_of(row: &Row) -> Option<Header> {
    let names: Vec<String> = row
        .iter()
        .map(|c| c.expose().trim().to_lowercase())
        .collect();
    let has = |want: &[&str]| want.iter().all(|w| names.iter().any(|n| n == w));
    let format = if has(&["type", "name", "login_username", "login_password"]) {
        CsvFormat::Bitwarden
    } else if has(&["account", "login name", "password", "web site"]) {
        CsvFormat::KeePass
    } else if has(&["title", "username", "password", "url"]) {
        CsvFormat::KeePassXc
    } else if has(&["name", "url", "username", "password"]) {
        CsvFormat::Chrome
    } else {
        return None;
    };
    Some(Header { format, names })
}

pub(crate) fn parse_drafts(bytes: &[u8], want: Option<CsvFormat>) -> Result<Parsed> {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    std::str::from_utf8(text).map_err(|_| Error::CsvEncoding)?;
    // KeePass 1.x 用反斜杠转义引号，其余用两个引号
    let mut rows = parse(text, Dialect::DoubledQuotes)?;
    let mut head = rows.first().and_then(header_of).ok_or(Error::CsvFormat)?;
    if head.format == CsvFormat::KeePass {
        rows = parse(text, Dialect::Backslash)?;
        head = rows.first().and_then(header_of).ok_or(Error::CsvFormat)?;
    }
    if want.is_some_and(|w| w != head.format) {
        return Err(Error::CsvFormat);
    }
    let mut out = Parsed {
        format: head.format,
        drafts: Vec::new(),
        blank: 0,
        adjusted: Vec::new(),
        rejected: Vec::new(),
    };
    for (i, row) in rows.iter().skip(1).enumerate() {
        let n = i + 1;
        if row.iter().all(|c| c.expose().is_empty()) {
            out.blank += 1;
            continue;
        }
        if row.len() != head.names.len() {
            out.rejected.push((n, RejectReason::ColumnCount));
            continue;
        }
        let mut notes = Vec::new();
        let draft = build(&head, row, n, &mut notes);
        match draft.prepare(0, 0) {
            Ok(_) => {
                out.adjusted.extend(notes.into_iter().map(|a| (n, a)));
                out.drafts.push(draft);
            }
            Err(Error::InvalidItem(crate::error::InvalidItem::SecretTooLong)) => {
                out.rejected.push((n, RejectReason::TooLarge));
            }
            Err(_) => out.rejected.push((n, RejectReason::Invalid)),
        }
    }
    Ok(out)
}

struct Fields<'a> {
    head: &'a Header,
    row: &'a Row,
}

impl<'a> Fields<'a> {
    fn raw(&self, name: &str) -> &'a str {
        self.head
            .names
            .iter()
            .position(|n| n == name)
            .and_then(|i| self.row.get(i))
            .map_or("", |c| c.expose())
    }

    /// 仅空字符串视为缺失，密码可以包含任意空白。
    fn secret(&self, name: &str) -> Option<SecretString> {
        let v = self.raw(name);
        (!v.is_empty()).then(|| v.into())
    }

    fn trimmed(&self, name: &str) -> Option<SecretString> {
        let v = self.raw(name).trim();
        (!v.is_empty()).then(|| v.into())
    }
}

/// 各格式中除已对应的列之外，有内容的列都作为自定义字段保留。
/// 这里列出的是明确不需要保留的列（图标、时间戳、界面状态）。
const IGNORED: &[&str] = &[
    "icon",
    "last modified",
    "created",
    "favorite",
    "reprompt",
    "archiveddate",
];

fn build(head: &Header, row: &Row, n: usize, notes: &mut Vec<Adjustment>) -> ItemDraft {
    let f = Fields { head, row };
    let mut d = ItemDraft::new(ItemKind::Login, "");
    let used: &[&str];
    match head.format {
        CsvFormat::Chrome => {
            used = &["name", "url", "username", "password", "note", "notes"];
            d.title = f.raw("name").to_owned();
            d.secrets.username = f.trimmed("username");
            d.secrets.password = f.secret("password");
            d.secrets.urls.extend(f.trimmed("url"));
            d.secrets.note = f.secret("note").or_else(|| f.secret("notes"));
        }
        CsvFormat::Bitwarden => {
            used = &[
                "folder",
                "type",
                "name",
                "notes",
                "fields",
                "login_uri",
                "login_username",
                "login_password",
                "login_totp",
            ];
            d.title = f.raw("name").to_owned();
            d.tags
                .extend(f.trimmed("folder").map(|t| t.expose().to_owned()));
            d.secrets.username = f.trimmed("login_username");
            d.secrets.password = f.secret("login_password");
            d.secrets.totp = f.trimmed("login_totp");
            // 多个网址用逗号连接；网址自身也可能含逗号，只在后面确实是新网址时才拆
            d.secrets.urls = split_uris(f.raw("login_uri"));
            d.secrets.note = f.secret("notes");
            for line in f.raw("fields").lines().filter(|l| !l.trim().is_empty()) {
                let (k, v) = line.split_once(": ").unwrap_or(("", line));
                push_custom(&mut d, k, v);
            }
        }
        CsvFormat::KeePass => {
            used = &["account", "login name", "password", "web site", "comments"];
            d.title = f.raw("account").to_owned();
            d.secrets.username = f.trimmed("login name");
            d.secrets.password = f.secret("password");
            d.secrets.urls.extend(f.trimmed("web site"));
            d.secrets.note = f.secret("comments");
        }
        CsvFormat::KeePassXc => {
            used = &[
                "group", "title", "username", "password", "url", "notes", "totp",
            ];
            d.title = f.raw("title").to_owned();
            d.tags.extend(
                f.raw("group")
                    .split('/')
                    .map(str::trim)
                    .filter(|g| !g.is_empty() && !matches!(*g, "Root" | "根目录"))
                    .map(str::to_owned),
            );
            d.secrets.username = f.trimmed("username");
            d.secrets.password = f.secret("password");
            d.secrets.urls.extend(f.trimmed("url"));
            d.secrets.note = f.secret("notes");
            d.secrets.totp = f.trimmed("totp");
        }
    }
    for (name, cell) in head.names.iter().zip(row.iter()) {
        let known = used.contains(&name.as_str()) || IGNORED.contains(&name.as_str());
        if !known && !cell.expose().trim().is_empty() {
            push_custom(&mut d, name, cell.expose());
            notes.push(Adjustment::ExtraKept);
        }
    }
    let is_note = head.format == CsvFormat::Bitwarden && f.raw("type").trim() == "note";
    let s = &d.secrets;
    if is_note
        && s.username.is_none()
        && s.password.is_none()
        && s.urls.is_empty()
        && s.totp.is_none()
    {
        d.kind = ItemKind::Note;
        d.secrets.body = d.secrets.note.take();
    }
    sanitize(&mut d, n, notes);
    // 只有标题、没有内容的行：保留为一条笔记
    if d.prepare(0, 0).err() == Some(Error::InvalidItem(crate::error::InvalidItem::Empty)) {
        d.kind = ItemKind::Note;
        d.secrets.body = Some(SecretString::new(d.title.clone()));
    }
    d
}

fn push_custom(d: &mut ItemDraft, name: &str, value: &str) {
    d.secrets.custom.push(CustomField {
        name: name.into(),
        value: value.into(),
    });
}

fn split_uris(s: &str) -> Vec<SecretString> {
    let mut out: Vec<String> = Vec::new();
    for part in s.split(',') {
        let starts_new = out.is_empty() || part.contains("://") || host_of(part).is_some();
        match out.last_mut() {
            Some(last) if !starts_new => {
                last.push(',');
                last.push_str(part);
            }
            _ => out.push(part.to_owned()),
        }
    }
    out.into_iter()
        .map(SecretString::new)
        .filter(|u| !u.expose().trim().is_empty())
        .collect()
}

/// 让草稿满足 AC-VLT-08 与长度限制，同时不丢内容。
fn sanitize(d: &mut ItemDraft, n: usize, notes: &mut Vec<Adjustment>) {
    // 网址列里可能不是网址：host_of 会返回 None，不会进元数据
    let hosts: Vec<String> = d
        .secrets
        .urls
        .iter()
        .filter_map(|u| host_of(u.expose()))
        .collect();
    if hosts.iter().any(|h| leaked_into(&d.secrets, h)) {
        d.auto_domains = false;
        d.domains = hosts
            .iter()
            .filter(|h| !leaked_into(&d.secrets, h))
            .cloned()
            .collect();
        notes.push(Adjustment::DomainOmitted);
    }
    let fallback = || {
        hosts
            .iter()
            .find(|h| !leaked_into(&d.secrets, h))
            .cloned()
            .unwrap_or_else(|| format!("导入条目 {n}"))
    };
    let title = clean_line(&d.title);
    if title.is_empty() {
        d.title = fallback();
        notes.push(Adjustment::TitleGenerated);
    } else if leaked_into(&d.secrets, &title) {
        let t = fallback();
        push_custom(d, "原标题", &title);
        d.title = t;
        notes.push(Adjustment::TitleMoved);
    } else if title.chars().count() > policy::MAX_TITLE_CHARS {
        push_custom(d, "原标题", &title);
        d.title = title.chars().take(policy::MAX_TITLE_CHARS).collect();
        notes.push(Adjustment::TitleShortened);
    }
    // 兜底标题仍可能碰巧含密码（例如密码就是“导入条目”），那就用固定文字
    if leaked_into(&d.secrets, &d.title) {
        d.title = "条目".to_owned();
    }
    let tags = std::mem::take(&mut d.tags);
    for t in tags {
        let c = clean_line(&t);
        let bad = leaked_into(&d.secrets, &c)
            || c.chars().count() > policy::MAX_TAG_CHARS
            || d.tags.len() >= policy::MAX_TAGS;
        if bad {
            push_custom(d, "原标签", &t);
            notes.push(Adjustment::TagMoved);
        } else {
            d.tags.push(c);
        }
    }
    let totp_bad = d
        .secrets
        .totp
        .as_ref()
        .is_some_and(|t| crate::totp::Totp::parse(t).is_err());
    if totp_bad && let Some(t) = d.secrets.totp.take() {
        push_custom(d, "TOTP", t.expose());
        notes.push(Adjustment::TotpMoved);
    }
}
