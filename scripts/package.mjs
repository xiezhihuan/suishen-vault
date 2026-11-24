// 打安装包：先构建桥接程序并放进包里，再由 Tauri 打包。
// 用法：npm run package                       本机平台（macOS 出 .dmg，Windows 出 NSIS）
//       npm run package -- <target triple>    指定目标
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { buildEnv, root } from "./env.mjs";

const env = buildEnv();
const run = (cmd, args, cwd = root) => {
  const r = spawnSync(cmd, args, { cwd, env, stdio: "inherit", shell: process.platform === "win32" && cmd === "npm" });
  if (r.status !== 0) process.exit(r.status ?? 1);
};
const host = spawnSync("rustc", ["-vV"], { env, encoding: "utf8" }).stdout.match(/^host: (.+)$/m)?.[1];
const target = process.argv[2] ?? host;
if (!target) {
  console.error("找不到 rustc");
  process.exit(1);
}
// 在 macOS 上交叉编译 Windows：用 llvm-mingw（自由许可，不含微软 SDK），放在项目缓存目录
if (target.endsWith("-windows-gnullvm") && process.platform !== "win32") {
  const tools = join(homedir(), ".cache", "suishen-vault", "tools");
  const dir = existsSync(tools) && readdirSync(tools).find((n) => n.startsWith("llvm-mingw-"));
  if (!dir) {
    console.error(`找不到 llvm-mingw，请解压到 ${tools}，见 docs/桌面端.md`);
    process.exit(1);
  }
  const arch = target.split("-")[0];
  env.PATH = `${join(tools, dir, "bin")}${delimiter}${env.PATH}`;
  env[`CARGO_TARGET_${target.toUpperCase().replaceAll("-", "_")}_LINKER`] = `${arch}-w64-mingw32-clang`;
  env[`CC_${target.replaceAll("-", "_")}`] = `${arch}-w64-mingw32-clang`;
  env[`AR_${target.replaceAll("-", "_")}`] = `${arch}-w64-mingw32-ar`;
  // 静态链接 libunwind，安装后不依赖额外的运行库
  env.RUSTFLAGS = `${env.RUSTFLAGS ?? ""} -C target-feature=+crt-static`.trim();
}
const exe = target.includes("windows") ? ".exe" : "";
run("cargo", ["build", "--release", "--locked", "-p", "vault-bridge", "--target", target]);
const tauri = join(root, "apps/client/src-tauri");
mkdirSync(join(tauri, "binaries"), { recursive: true });
copyFileSync(join(env.CARGO_TARGET_DIR, target, "release", `vault-bridge${exe}`), join(tauri, "binaries", `vault-bridge-${target}${exe}`));
// 只在打包时声明，平时编译不要求桥接程序已存在
const config = join(tauri, "binaries", "bundle.json");
const bundle = { externalBin: ["binaries/vault-bridge"] };
if (target.includes("windows-gnu")) {
  // GNU 目标动态链接 WebView2Loader.dll，安装包必须带上，否则启动就失败
  const meta = JSON.parse(spawnSync("cargo", ["metadata", "--format-version", "1", "--locked"], { cwd: root, env, encoding: "utf8", maxBuffer: 1 << 28 }).stdout);
  const sys = meta.packages.find((p) => p.name === "webview2-com-sys");
  const cpu = target.startsWith("aarch64") ? "arm64" : "x64";
  copyFileSync(join(dirname(sys.manifest_path), cpu, "WebView2Loader.dll"), join(tauri, "binaries", "WebView2Loader.dll"));
  bundle.resources = { "binaries/WebView2Loader.dll": "WebView2Loader.dll" };
}
writeFileSync(config, JSON.stringify({ bundle }));
const bundles = target.includes("windows") ? "nsis" : "dmg";
run("npm", ["run", "tauri", "--", "build", "--ci", "--target", target, "--bundles", bundles, "--config", config], join(root, "apps/client"));
