//! AI 侧桥接程序：对 Claude Code / Codex 提供 stdio MCP，
//! 对设备端走固定公钥的 TLS。
//!
//! 目前是骨架。设计见 `docs/设计.md` 第 6、7 节。

use std::process::ExitCode;

fn main() -> ExitCode {
    // 未实现前以非零码退出，避免 MCP 客户端误以为连接成功。
    ExitCode::from(2)
}
