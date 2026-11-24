# 随身密库 suishen-vault

随身保存并搜索账号、密码和要记的内容。Claude、Codex 可以按描述找到条目，但拿不到明文；某一条要由你在 App 上批准，再把一次性授权码交给 AI，AI 才能取到那一条。

Rust 核心已实现本地加密密库、搜索、CSV 导入、备份和迁移。桌面 App 可完成首次设置、存取与搜索、逐条授权、导入备份与设备迁移，用法、打包与验证记录见 [桌面端](docs/桌面端.md)。Claude Code 与 Codex 的配置和联测命令见 [本机服务](docs/本机服务.md)。没有公网 IP 的设备可以经自己的服务器对外提供 MCP，见 [公网跳板](docs/公网跳板.md)。核心接入方式、测试与依赖审计见 [密库核心](docs/密库核心.md)。

打开「智能粘贴」，把一条或多条账号资料粘进来，对照高亮原文检查。未识别的片段可以手动归类，确认后才整批新增。要让 AI 帮忙录入，在「AI 客户端」单独打开该客户端的草稿权限，再到「草稿箱」核对域名、补密码并确认。AI 不应索要密码。用法和实窗截图见 [本机服务](docs/本机服务.md#允许某个-ai-提交草稿)。

## 下载安装与首次设置

本轮交付在仓库根目录的 `dist/`。Apple 芯片 Mac 打开 `SuishenVault_0.1.0_aarch64.dmg`，把 App 拖进「应用程序」。这是 ad-hoc 签名的验收包，未公证。Windows x64 运行 `SuishenVault_0.1.0_x64-setup.exe`，按向导安装。Windows 包未签名、未在 Windows 实机运行。Android 本轮没有 APK。

在 Mac 终端进入 `dist` 运行 `shasum -a 256 -c SHA256SUMS`，应显示 OK。在 Windows PowerShell 运行 `Get-FileHash .\SuishenVault_0.1.0_x64-setup.exe -Algorithm SHA256`，与同目录 `SHA256SUMS` 中对应行逐字核对。校验只能确认拿到的文件与清单一致。

首次打开选「新建密库」，用至少 10 个字符设主密码。把九组恢复密钥抄到纸上，按要求填回随机两组。丢失主密码后，在解锁页选「忘了主密码，用恢复密钥重设」并抄好新的恢复密钥。如果两者都丢失，就无法找回。初次验收可以先用假数据照着[十五分钟验收指南](docs/验收指南.md)操作。

## 接入 Claude Code 或 Codex

1. 在「开放范围」选「仅本机」。在「AI 客户端」分别为 Claude Code、Codex 签发令牌，起不同名称。可把演示客户端的可见标签限制为「验收」。
2. 找到同页「接入配置」，选要接的客户端和本机 stdio 方式。复制页面给出的 `vault-bridge store-token claude` 或 `store-token codex` 完整命令到终端运行，在隐藏输入提示下粘贴令牌。安装包内置桥接。钥匙串授权由你决定。
3. 把页面生成的不含令牌的配置合并到测试项目。Claude Code 使用项目的 `.mcp.json`，Codex 使用受信任项目的 `.codex/config.toml`。重启相应客户端，在 Claude Code 的 `/mcp` 或 Codex 的 `/mcp` 检查服务器和工具列表。
4. 请 AI 描述要找的条目、申请单个字段，并告诉你理由。你在主设备核对后可选择「仅在本机查看」。要交付给 AI，须重新验证主密码并亲自把短码交给它。授权码只能使用一次，120 秒失效。智能粘贴与待审草稿的示例见[验收指南](docs/验收指南.md)。

HTTP 直连本机服务需专用令牌环境变量。公网默认应使用配对桥接，服务器只能看到端到端密文。在你自己的 Linux 服务器准备域名及反向代理，进入 `deploy/relay`，按文档设置 `RELAY_HOST`，运行 `docker compose up -d --build` 和 `docker compose exec relay vault-relay pair-code`。将服务器地址与配对码输入主设备「开放范围 → 公网跳板」。打开公网后，在「AI 客户端」生成配对串，在 AI 电脑运行页面给出的 `vault-bridge pair` 命令，核对指纹并在 App 确认。公网直连另须主动勾选，那个模式下跳板能看到提交的码和交付的明文。局域网档尚未实现。[完整部署](docs/公网跳板.md) · [本机服务](docs/本机服务.md)

## 备份、恢复与换设备

在「导入与备份」导出加密备份，把它与恢复密钥分开保存。新设备在欢迎页选「从备份恢复」，选择备份文件并输入该备份对应的主密码或恢复密钥。恢复不会覆盖已有密库。使用恢复密钥后按提示重设主密码。恢复不能远程停用旧设备。

正常换设备用「设备迁移」。旧设备生成加密迁移包后关闭服务并变为只读。新设备导入时需要包、迁移码和密库凭据，校验完成后显示完成码。回旧设备输入完成码，核对新库后再清除旧库。公网需新设备用新的服务器配对码接管，AI 客户端也要重新配对。密库不做多端同步，没有中心服务器能阻止手工复制备份后两处同时使用。

本轮的通过项、已知缺口与实测证据见[验收清单](docs/验收清单.md)、[安全复查](docs/安全复查.md)和[未验证项](docs/未验证项.md)。

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
