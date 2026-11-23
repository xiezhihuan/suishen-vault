// 统一构建环境：补全 ~/.cargo/bin，并让各 worktree 共用一个 Cargo target 目录以节省磁盘。
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = fileURLToPath(new URL("..", import.meta.url));

export function buildEnv() {
  const env = { ...process.env };
  const cargoBin = join(homedir(), ".cargo", "bin");
  if (existsSync(cargoBin)) env.PATH = `${cargoBin}${delimiter}${env.PATH ?? ""}`;
  env.CARGO_TARGET_DIR ??= join(homedir(), ".cache", "suishen-vault", "target");
  return env;
}
