# 随身密库 suishen-vault

随身保存并搜索账号、密码和要记的内容。Claude、Codex 可以按描述找到条目，但拿不到明文；某一条要由你在 App 上批准，再把一次性授权码交给 AI，AI 才能取到那一条。

Rust 核心已实现本地加密密库、搜索、CSV 导入、备份和迁移。客户端与网络服务仍是骨架。核心接入方式、测试与依赖审计见 [密库核心](docs/密库核心.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/PRD.md](docs/PRD.md) | 需求与验收编号 |
| [docs/设计.md](docs/设计.md) | 架构、密钥、授权、接口、跳板、迁移 |
| [docs/威胁模型.md](docs/威胁模型.md) | 威胁、对策、残余风险 |
| [docs/调研.md](docs/调研.md) | 同类项目与协议现状 |
| [docs/未验证项.md](docs/未验证项.md) | 还没有验证的事项 |

## 目录

| 目录 | 内容 |
|---|---|
| `crates/vault-core` | 加密、存储、检索、授权状态机 |
| `crates/vault-service` | 设备端服务（MCP、GET 明文接口），嵌入 App |
| `crates/vault-relay` | 公网跳板，部署在自己的服务器 |
| `crates/vault-bridge` | AI 侧桥接 |
| `apps/client` | Tauri 2 客户端 |

## 环境

- Rust 1.90 及以上，带 rustfmt 与 clippy（`rustup component add rustfmt clippy`）。
- Node 22.12 及以上。
- macOS：Xcode Command Line Tools 即可，不需要完整 Xcode。
- 全部用户级安装，不需要 sudo。

## 命令

```bash
npm ci                                        # 首次安装前端依赖
npm test                                      # 统一测试：仓库、文档、前端、Rust、桌面壳编译
npm run client:dev                            # 开发运行
npm run client:build -- --debug --no-bundle   # 编译桌面可执行文件
npm run cargo -- test -p vault-core           # 用统一环境运行任意 cargo 命令
```

这些命令会自动补上 `~/.cargo/bin`，并把 Cargo 产物放到 `~/.cache/suishen-vault/target`，各工作树共用，节省磁盘。可用环境变量 `CARGO_TARGET_DIR` 覆盖。直接运行 `cargo` 会在当前目录另建 `target/`，不推荐。

`Cargo.lock` 与 `package-lock.json` 随仓库提交，请勿随意升级，避免重复下载。

## 约定

- 测试只用假密码。不要提交真实数据、密钥、签名文件。
- 新增或修改功能时引用 `docs/PRD.md` 的验收编号；编号有误 `npm test` 会失败。
- 没有实际跑过的结果写进 `docs/未验证项.md`。
- 不抄 GPL/AGPL 项目代码。

## 许可证

未授予开源许可，按私有项目处理，是否公开由项目所有者决定。
