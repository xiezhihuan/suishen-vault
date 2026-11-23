//! 设备端服务：`/mcp`、明文 GET 接口、客户端配对。嵌入 App 进程运行。
//!
//! 目前是骨架，不监听任何端口。接口定义见 `docs/设计.md` 第 6 节。

use vault_core::ExposureScope;

/// 服务的运行状态。
#[derive(Debug, Default)]
pub struct ServiceHandle {
    scope: ExposureScope,
}

impl ServiceHandle {
    /// 新建时一律为关闭；没有任何从磁盘恢复开放范围的途径。
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn scope(&self) -> ExposureScope {
        self.scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed() {
        assert_eq!(ServiceHandle::new().scope(), ExposureScope::Closed);
    }
}
