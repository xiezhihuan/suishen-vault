# Android arm64 APK 构建和验收

本次在 macOS arm64 工作树中检查到 5.0 GiB 可用空间，未找到可用 JDK、SDK、NDK、模拟器和已接受的 SDK 许可。没有产出 APK，也没有 Android 运行截图。以下是给本机准备好空间后使用的步骤。Android 最低 API 29，本次只构建 arm64-v8a。

## 1. 确认空间

在本工作树根目录运行 `df -h . "$HOME"`。以下是冷安装的粗估，随工具版本、镜像和 AVD 使用量变化。

| 内容 | 预计新增占用 |
|---|---:|
| JDK、命令行工具、SDK Platforms 和 Build Tools | 1–3 GiB |
| NDK、arm64 Rust 标准库 | 3–5 GiB |
| Gradle、依赖、Rust Android 编译产物、签名临时文件 | 3–6 GiB |
| 模拟器、arm64 系统镜像和首次启动的 AVD | 4–8 GiB |

建议全流程开始前有约 25 GiB 可用，或把工具链与 AVD 放在空间充足的卷上。低于 3 GiB 时不要继续构建或下载。按项目约定，如需清理，只可运行 `"$HOME/.cargo/bin/cargo" clean --target-dir "$HOME/.cache/suishen-vault/target"`，会清掉本项目各工作树共用的编译结果。清理后重新检查空间。

## 2. 本人安装 JDK 和 Android 命令行工具

在同一终端执行以下命令。第一组将开源 JDK 21 装到用户目录。已有可用的 JDK 17 或 21 时，直接把 `JAVA_HOME` 指向它。

```sh
mkdir -p "$HOME/.local/share/suishen-jdk21"
curl -fL 'https://api.adoptium.net/v3/binary/latest/21/ga/mac/aarch64/jdk/hotspot/normal/eclipse' -o "$TMPDIR/suishen-jdk21.tar.gz"
tar -xzf "$TMPDIR/suishen-jdk21.tar.gz" --strip-components=1 -C "$HOME/.local/share/suishen-jdk21"
export JAVA_HOME="$HOME/.local/share/suishen-jdk21/Contents/Home"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
export PATH="$JAVA_HOME/bin:$HOME/.cargo/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
java -version
```

本人打开 [Android 官方下载页](https://developer.android.com/studio#command-line-tools-only)，选择 **Command line tools only → Mac**，阅读条款，自行决定是否接受并下载。将下载的 ZIP 在“下载”目录中命名为 `suishen-android-cli.zip`。首次安装执行以下命令。如果已有 `cmdline-tools/latest/bin/sdkmanager`，可跳过解压和移动。

```sh
mkdir -p "$ANDROID_HOME/cmdline-tools"
sv_unpack="$(mktemp -d)"
unzip -q "$HOME/Downloads/suishen-android-cli.zip" -d "$sv_unpack"
mv "$sv_unpack/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
sdkmanager --sdk_root="$ANDROID_HOME" --licenses
```

最后一条命令逐项展示 SDK 许可，由本人阅读并逐项回答。安装组件过程中若出现其他许可，也须由本人决定。无人值守构建不会应答这些提示。

## 3. 安装构建组件并签名

锁定的 Tauri CLI 2.12.6 模板使用 compileSdk/targetSdk 37，Rust 侧的 Tauri Android 库和文件插件编译时还需要 36。下面安装这两个平台。使用 NDK r29，以支持 16 KiB 页的 arm64 设备。

```sh
df -h . "$ANDROID_HOME"
sdkmanager --sdk_root="$ANDROID_HOME" "platform-tools" "platforms;android-36" "platforms;android-37" "build-tools;37.0.0" "ndk;29.0.14206865"
rustup target add aarch64-linux-android
node scripts/android-build.mjs --check
npm run android:build
```

在其他新检出目录缺少前端依赖时先执行 `npm ci`。本工作树可以复用已有的 `node_modules` 链接和 `~/.cache/suishen-vault/target`。构建入口在生成的 Gradle 工程中放入本项目的清单、Kotlin 类和资源，再用 Tauri 构建 release APK。修改 Android 源码请改 `apps/client/android/`。

构建成功时会生成 `dist/android/suishen-vault-arm64.apk`。首次成功编译后，脚本才在 `~/.local/share/suishen-vault/android-signing/` 生成签名密钥和随机口令文件。目录权限为 0700。请将这两个文件一起离线保管，覆盖安装更新需要同一把签名密钥。脚本执行 16 KiB zipalign、APK 签名和验签，并检查包内只有 arm64 的本地库。

## 4. 安装和启动

在 Mac 的第一个终端运行专用 AVD。这里采用 API 36 的 ARM 系统镜像，不需要 Google 账号。

```sh
df -h . "$ANDROID_HOME"
sdkmanager --sdk_root="$ANDROID_HOME" "emulator" "system-images;android-36;google_apis;arm64-v8a"
avdmanager create avd --name SuishenVaultQA --package "system-images;android-36;google_apis;arm64-v8a" --device pixel_6
emulator -avd SuishenVaultQA -no-snapshot
```

在另一个终端设置相同的 ANDROID_HOME 和 PATH 后运行。用 `adb devices` 看到的编号替换示例编号。

```sh
adb devices
export ANDROID_SERIAL=emulator-5554
adb -s "$ANDROID_SERIAL" wait-for-device
adb -s "$ANDROID_SERIAL" shell getprop ro.product.cpu.abi
adb -s "$ANDROID_SERIAL" install -r dist/android/suishen-vault-arm64.apk
adb -s "$ANDROID_SERIAL" shell am start -n dev.suishen.vault/.MainActivity
```

自行安装到 arm64 手机时，也可把 APK 拷到手机并从文件管理器打开。系统会向用户确认安装来源权限。

## 5. 用假密库验收

1. 在专用 AVD 建库，仅用假主密码。抄下恢复密钥，按随机抽查的两组完成确认。录入一个假条目，先在密库搜索，再到智能粘贴粘入以下整段。检查分段、遮盖、保存后能搜索；重复保存应提示已有同域名账号。再粘一次，切到桌面，回来解锁，未保存原文应消失。

   ```text
   标题：极光演示
   网址：https://aurora.example.test/login
   账号：fake.aurora
   密码：Fake-Aurora-Only-8237
   ```

2. 在“AI 客户端”新建假客户端，允许它提交草稿，保管本次令牌。在“开放范围”选“仅本机”，保留默认端口 47600，允许通知。专用 AVD 的端口转发只用于此次测试。在仓库根目录运行以下命令，跟随终端提示在手机点按。已有官方 Python MCP SDK 的本机可直接运行最后一条。

   ```sh
   python3 -m venv "$HOME/.cache/suishen-vault/android-qa-venv"
   "$HOME/.cache/suishen-vault/android-qa-venv/bin/pip" install 'mcp>=1.22,<2' httpx
   "$HOME/.cache/suishen-vault/android-qa-venv/bin/python" scripts/android-accept.py
   ```

   验收客户端会提交无机密草稿，检查确认前搜索不到，等用户在 App 补充假密码确认入库。它在 HOME 后台和息屏时各执行一次搜索、申请、查状态。每次由用户点开通知核对字段、重新验证、输入一次性授权码。脚本检查无授权 GET 被拒、带头部的 GET 只返回所选字段、响应不可缓存、重放被拒。最后从通知关闭服务，重开后检查关闭前尚未兑换的码已经失效。截图保存在 `target/android-qa/`，存放息屏和模拟器通知栏证据。不要为截图解除 FLAG_SECURE。

3. 将申请改为“仅在本机查看”，核对本地可见、AI 没有授权码。开放时划掉任务或强停应用，再启动应显示“关闭”。选择 15 分钟自动关闭，等到期后检查通知撤除、服务不可达。公网隧道的验证需要另起**测试跳板**并配对，本次未连接真实服务器。局域网档沿用桌面端现状，尚未实现 TLS 监听。
4. 在 AVD 系统设置里设置一个测试锁屏 PIN 并登记指纹。模拟触摸用 `adb -s "$ANDROID_SERIAL" emu finger touch 1`。在 App 设置用主密码启用生物识别，实际解锁一次、批准一次，再取消一次，取消不得出码。去系统设置新增第二枚指纹，再次尝试应失败；用主密码仍能解锁并重新登记。
5. 手动验证剪贴板敏感提示、到期清除和在计时期间复制另一段不会误删。Android 10 起其他应用有焦点时，系统可能拒绝读取剪贴板标识。App 在到期和重新获得焦点时检查所有权，只清自己写入的那次。检查备份导出、新空库恢复和迁移，确认从系统文件选择器返回后须解锁，原密库的设备槽不会随包迁移。
6. 敏感页执行 `adb -s "$ANDROID_SERIAL" exec-out screencap -p > "$TMPDIR/suishen-secure-check.png"`，截图不得出现应用内容。通知栏和最近任务也不得出现条目、客户端、理由、明文或授权码。模拟器不能代表厂商真机的后台保活策略。

## Android 的后台和密钥边界

开放源于用户在前台的明确操作。同一进程的前台服务承载“等待本地 MCP 访问和授权申请、维持加密反向隧道”的持续任务。Android 14 起采用 `specialUse`，清单声明对应权限、用途和类型。任务没有持续同步一批数据，不适用 `dataSync`。服务使用 `START_NOT_STICKY`，没有开机启动入口。通知不可见或前台服务启动失败时，App 拒绝开放。Android 仍可因资源不足或用户强停而终止进程。[Android 前台服务类型](https://developer.android.com/develop/background-work/services/fgs/service-types#special-use)

切后台会锁住密库。服务开放时按共享核心规则保留元数据密钥。主密码验证后可登记设备槽。应用通过 Android Keystore 中的 AES-GCM 密钥包裹一个随机的 256 位设备密钥，每次使用都要求 BiometricPrompt 的 CryptoObject 完成密码操作。密库用解出的设备密钥打开设备槽，每个批准请求独立验证。应用禁用系统备份与设备搬家，手工备份或迁移沿用核心的加密包。

## 本工作树实际跑过的检查

- 在 macOS arm64 上，改动前和改动后的 `npm test` 均走完十步。改动后 52 项前端测试通过，覆盖智能粘贴、草稿补录、切后台丢弃未提交输入，以及生物识别批准失败后不出码。
- Rust 状态测试实际用设备密钥槽走过锁定时批准、错误密钥拒绝、字段越权拒绝和一键关闭。使用了临时密库，没有调用 Android Keystore。
- `npm run test:mcp` 用官方 Python SDK 通过了本机 MCP 集成测试。
- 在桌面 Chrome 的 360 × 740 CSS 像素视口中，用假状态打开密库、智能粘贴、草稿箱、授权申请、开放范围和设置。六个页面都没有页面级横向溢出，底部导航按钮高度为 48 CSS 像素。
- Android 构建预检在缺少 SDK 许可文件时退出。Kotlin、APK、原生通知、息屏运行与设备指纹仍待模拟器或真机验收。
