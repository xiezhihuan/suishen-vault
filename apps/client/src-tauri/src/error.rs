//! 返回给界面的错误。文案固定，不含用户输入、路径、底层库文本。
use serde::Serialize;
use vault_core::{Error, InvalidItem, model::MetaField};
use vault_service::ServiceError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiError {
    pub code: &'static str,
    pub message: String,
    /// 需要等待多久才能再试，毫秒。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

pub type Ui<T> = Result<T, UiError>;

pub fn fail<T>(code: &'static str, message: &str) -> Ui<T> {
    Err(UiError::new(code, message))
}

impl UiError {
    pub fn new(code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.to_owned(),
            wait_ms: None,
        }
    }
    pub fn internal() -> Self {
        Self::new("internal", "操作没有完成，请重试")
    }
    pub fn locked() -> Self {
        Error::Locked.into()
    }
}

fn meta_name(f: MetaField) -> &'static str {
    match f {
        MetaField::Title => "标题",
        MetaField::Domain => "域名",
        MetaField::Tag => "标签",
        MetaField::Hint => "检索提示",
    }
}

impl From<Error> for UiError {
    fn from(e: Error) -> Self {
        let (code, text) = match e {
            Error::UnlockFailed => ("unlock_failed", "验证失败，请检查输入是否正确"),
            Error::Backoff(ms) => {
                return Self {
                    code: "backoff",
                    message: format!("失败次数过多，请等待 {} 秒再试", ms.div_ceil(1000)),
                    wait_ms: Some(ms),
                };
            }
            Error::Locked => ("locked", "密库已锁定，请先解锁"),
            Error::ReadOnly => ("read_only", "密库正在迁移，目前只读"),
            Error::Retired => ("retired", "这台设备的密库已停用"),
            Error::InUse => ("in_use", "密库正被另一个程序使用"),
            Error::AlreadyExists => ("exists", "目标文件已存在，请换一个文件名"),
            Error::NotFound => ("not_found", "找不到文件"),
            Error::UnsupportedFormat => ("unsupported", "文件版本不受支持，请更新应用"),
            Error::KdfParamsRejected | Error::Tampered => ("tampered", "文件已损坏或被改动"),
            Error::PasswordTooShort => ("password_short", "主密码至少要 10 个字符"),
            Error::PasswordTooCommon => ("password_common", "这个主密码太常见，请换一个"),
            Error::CodeFormat => ("code_format", "格式不正确，请检查是否抄错"),
            Error::RecoveryConfirmMismatch => {
                ("recovery_mismatch", "核对不一致，请对照抄写的恢复密钥")
            }
            Error::UnknownItem => ("unknown_item", "这条记录已不存在"),
            Error::UnknownField => ("unknown_field", "这条记录没有该字段"),
            Error::NotAllowedForAi => ("not_allowed", "这条记录不允许交给 AI"),
            Error::SecretInMetadata(f) => {
                return Self::new(
                    "secret_in_metadata",
                    &format!(
                        "{}里出现了这条的密码或账号。这部分 AI 可以搜到，请改掉",
                        meta_name(f)
                    ),
                );
            }
            Error::InvalidItem(i) => return invalid_item(i),
            Error::NotInTrash => ("not_in_trash", "这条记录不在回收站"),
            Error::InvalidGenerator => ("generator", "请至少选一种字符，长度 4 到 256"),
            Error::InvalidTotp => ("totp", "动态口令密钥不正确"),
            Error::NotMigrating => ("not_migrating", "没有进行中的迁移"),
            Error::CompletionMismatch => ("completion", "完成码不正确"),
            Error::CsvFormat => (
                "csv_format",
                "无法识别的 CSV，支持 Chrome、Bitwarden、KeePass 导出的文件",
            ),
            Error::CsvEncoding => ("csv_encoding", "CSV 不是 UTF-8 文本"),
            Error::TooLarge => ("too_large", "文件过大"),
            Error::SourceChanged => ("source_changed", "文件内容已变化，没有删除"),
            Error::OutOfMemory => ("memory", "内存不足，请关闭其他程序后重试"),
            Error::Io(_) => ("io", "文件读写失败，请检查磁盘空间和权限"),
            _ => ("internal", "操作没有完成，请重试"),
        };
        Self::new(code, text)
    }
}

fn invalid_item(i: InvalidItem) -> UiError {
    let text = match i {
        InvalidItem::EmptyTitle => "请填写标题".to_owned(),
        InvalidItem::TooLong(f) => format!("{}太长", meta_name(f)),
        InvalidItem::TooManyTags => "标签太多".to_owned(),
        InvalidItem::TooManyDomains => "域名太多".to_owned(),
        InvalidItem::BadDomain => "域名格式不正确，例如 example.com".to_owned(),
        InvalidItem::SecretTooLong => "内容太长".to_owned(),
        InvalidItem::TooManyCustomFields => "自定义字段太多".to_owned(),
        InvalidItem::FieldNotForKind => "这种类型不支持填入的字段".to_owned(),
        InvalidItem::Empty => "请至少填写一项内容".to_owned(),
        _ => "内容不符合要求".to_owned(),
    };
    UiError::new("invalid_item", &text)
}

impl From<ServiceError> for UiError {
    fn from(e: ServiceError) -> Self {
        let text = match e.1 {
            "unlock_failed" => "主密码不正确，或正在等待重试",
            "invalid_fields" => "请至少勾选一个申请中的字段",
            "unknown_request" | "gone" | "not_ready" => "申请已失效",
            "invalid_params" => "请检查名称和标签",
            "port_in_use" => "端口已被占用，可在设置里换一个端口",
            "unauthorized" => "这个客户端已不存在",
            "relay_url" => "跳板地址不正确，例如 https://relay.example.com",
            "relay_ca" => "证书不正确，请粘贴一张 PEM 格式的 CA 证书，不要含私钥",
            "relay_code" => "配对码不正确、已过期或已用过，请在服务器上重新生成",
            "relay_unreachable" => "连不上跳板，请检查地址、网络和证书",
            "relay_refused" => "对方不是跳板，或跳板的主机名设置与这个地址不一致",
            "relay_not_set" => "还没有配对跳板",
            "relay_superseded" => "跳板已由另一台设备接管。要换回这台，请重新生成配对码并配对",
            "pairing_closed" => "这次配对已结束，请重新开始",
            _ => "操作没有完成，请检查密库和服务状态",
        };
        Self::new(e.1, text)
    }
}
