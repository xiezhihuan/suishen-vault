// 统一测试命令：npm test
// 依次运行：仓库卫生检查、文档编号检查、前端类型检查/测试/构建、Rust 格式/静态检查/测试、桌面壳编译。
import { spawnSync } from "node:child_process";
import { buildEnv, root } from "./env.mjs";

const env = buildEnv();
const win = process.platform === "win32";
const node = process.execPath;
const ui = ["run", "-w", "apps/client"];

const steps = [
  ["仓库卫生", node, ["scripts/check-repo.mjs"]],
  ["文档编号", node, ["scripts/check-docs.mjs"]],
  ["前端类型检查", "npm", [...ui, "typecheck"]],
  ["前端测试", "npm", [...ui, "test"]],
  // Tauri 的 generate_context! 需要 dist 存在，所以前端构建排在 Rust 之前
  ["前端构建", "npm", [...ui, "build"]],
  ["Rust 格式", "cargo", ["fmt", "--all", "--check"]],
  ["Rust 静态检查", "cargo", ["clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"]],
  ["Rust 测试", "cargo", ["test", "--workspace", "--locked"]],
  ["万条密库检索", "cargo", ["test", "--release", "-p", "vault-core", "--test", "perf", "--locked", "--", "--nocapture"]],
  ["桌面壳编译", "cargo", ["build", "-p", "suishen-vault-client", "--locked"]],
];

for (const [name, cmd, args] of steps) {
  console.log(`\n=== ${name} ===`);
  const r = spawnSync(cmd, args, { cwd: root, env, stdio: "inherit", shell: win && cmd === "npm" });
  if (r.status !== 0) {
    console.error(`\n失败：${name}${r.error ? `（${r.error.message}）` : ""}`);
    process.exit(1);
  }
}
console.log(`\n全部通过，共 ${steps.length} 步。`);
