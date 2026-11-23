//! 公网跳板：部署在用户自己的服务器上，只转发密文，只认一个当前设备身份。
//!
//! 目前是骨架。设计见 `docs/设计.md` 第 7 节。

use std::process::ExitCode;

fn main() -> ExitCode {
    // 未实现前以非零码退出，避免被误当成已在运行。
    ExitCode::from(2)
}
