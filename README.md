# 随身密库 suishen-vault

随身保存并搜索账号、密码和要记的内容。Claude、Codex 可以按描述找到条目，但拿不到明文；某一条要由你在 App 上批准，再把一次性授权码交给 AI，AI 才能取到那一条。

Rust 核心已实现本地加密密库、搜索、CSV 导入、备份和迁移。桌面 App 可完成首次设置、存取与搜索、逐条授权、导入备份与设备迁移，用法、打包与验证记录见 [桌面端](docs/桌面端.md)。Claude Code 与 Codex 的配置和联测命令见 [本机服务](docs/本机服务.md)。没有公网 IP 的设备可以经自己的服务器对外提供 MCP，见 [公网跳板](docs/公网跳板.md)。核心接入方式、测试与依赖审计见 [密库核心](docs/密库核心.md)。

打开「智能粘贴」，把一条或多条账号资料粘进来，对照高亮原文检查。未识别的片段可以手动归类，确认后才整批新增。要让 AI 帮忙录入，在「AI 客户端」单独打开该客户端的草稿权限，再到「草稿箱」核对域名、补密码并确认。AI 不应索要密码。用法和实窗截图见 [本机服务](docs/本机服务.md#允许某个-ai-提交草稿)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/PRD.md](docs/PRD.md) | 需求与验收编号 |
| [docs/设计.md](docs/设计.md) | 架构、密钥、授权、接口、跳板、迁移 |
| [docs/威胁模型.md](docs/威胁模型.md) | 威胁、对策、残余风险 |
| [docs/调研.md](docs/调研.md) | 同类项目与协议现状 |
| [docs/桌面端.md](docs/桌面端.md) | 桌面 App 的用法、安全约束、打包、验证记录 |
| [docs/公网跳板.md](docs/公网跳板.md) | 跳板部署、配对、两种访问方式、ssh -R 与 frp、验证记录 |
| [docs/未验证项.md](docs/未验证项.md) | 还没有验证的事项 |

## 目录

| 目录 | 内容 |
|---|---|
| `crates/vault-core` | 加密、存储、检索、授权状态机 |
| `crates/vault-service` | 设备端服务（MCP、GET 明文接口），嵌入 App |
| `crates/vault-relay` | 公网跳板，部署在自己的服务器 |
| `crates/vault-tunnel` | 跳板、设备、桥接共用的隧道协议 |
| `crates/vault-bridge` | AI 侧桥接 |
| `deploy/relay` | 跳板的 Dockerfile、Compose、Caddy、Nginx、systemd 配置 |
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
npm run test:relay                            # 公网端到端测试，需要 Docker
npm run test:deploy                           # 按部署文档在干净容器里跑一遍，需要 Docker
npm run package                               # 打安装包，见 docs/桌面端.md
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

Android arm64 直装包的环境准备、签名和模拟器验收见 [Android 构建](docs/Android构建.md)。本次工作树未产出 APK。
