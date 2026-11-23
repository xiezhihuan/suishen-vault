//! 错误类型。错误里不携带任何输入内容，也不转述底层库的错误文本。

use crate::model::MetaField;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 主密码、恢复密钥、设备密钥错误，或包裹密文被改动。刻意不区分。
    #[error("解锁失败")]
    UnlockFailed,
    #[error("失败次数过多，请在 {0} 毫秒后重试")]
    Backoff(u64),
    #[error("密库已锁定")]
    Locked,
    #[error("密库正在迁移，只读")]
    ReadOnly,
    #[error("本设备的密库已停用")]
    Retired,
    #[error("密库正在被使用")]
    InUse,
    #[error("目标文件已存在")]
    AlreadyExists,
    #[error("找不到密库文件")]
    NotFound,
    #[error("不支持的密库格式版本")]
    UnsupportedFormat,
    /// KDF 参数低于下限或高于上限。在运行 KDF 之前就拒绝，不算一次失败尝试。
    #[error("密钥派生参数不被接受")]
    KdfParamsRejected,
    /// 密文、清单或结构校验不通过。
    #[error("数据损坏或被篡改")]
    Tampered,
    #[error("主密码太短")]
    PasswordTooShort,
    #[error("主密码太常见")]
    PasswordTooCommon,
    #[error("恢复密钥或迁移码格式不正确，请检查是否抄错")]
    CodeFormat,
    #[error("核对的恢复密钥不一致")]
    RecoveryConfirmMismatch,
    #[error("没有这条记录")]
    UnknownItem,
    #[error("这条记录没有该字段")]
    UnknownField,
    #[error("这条记录不允许交给 AI")]
    NotAllowedForAi,
    /// 元数据中混入了本条的密码或账号全文。
    #[error("检测到机密内容出现在{0}中")]
    SecretInMetadata(MetaField),
    #[error("内容不符合要求")]
    InvalidItem(InvalidItem),
    #[error("不在回收站中")]
    NotInTrash,
    #[error("密码生成参数不正确")]
    InvalidGenerator,
    #[error("动态口令密钥不正确")]
    InvalidTotp,
    #[error("没有进行中的迁移")]
    NotMigrating,
    #[error("完成码不正确")]
    CompletionMismatch,
    #[error("无法识别的 CSV 格式")]
    CsvFormat,
    #[error("CSV 不是有效的 UTF-8 文本")]
    CsvEncoding,
    #[error("文件过大")]
    TooLarge,
    #[error("文件内容已变化，未删除")]
    SourceChanged,
    #[error("存储出错")]
    Storage,
    #[error("文件读写出错")]
    Io(std::io::ErrorKind),
    #[error("系统随机源不可用")]
    Random,
    #[error("内存不足")]
    OutOfMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidItem {
    EmptyTitle,
    TooLong(MetaField),
    TooManyTags,
    TooManyDomains,
    BadDomain,
    SecretTooLong,
    TooManyCustomFields,
    /// 该类型不支持填入的字段。
    FieldNotForKind,
    /// 没有任何内容。
    Empty,
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode as C;
        match e.sqlite_error_code() {
            Some(C::DatabaseBusy | C::DatabaseLocked) => Self::InUse,
            Some(C::DatabaseCorrupt | C::NotADatabase) => Self::Tampered,
            Some(C::OutOfMemory) => Self::OutOfMemory,
            Some(_) => Self::Storage,
            // 列类型、行数不符：结构被改动
            None => Self::Tampered,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            k => Self::Io(k),
        }
    }
}
