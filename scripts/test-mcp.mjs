import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { buildEnv, root } from "./env.mjs";
const env = buildEnv();
env.SV_TEST_BRIDGE = join(env.CARGO_TARGET_DIR, "debug", process.platform === "win32" ? "vault-bridge.exe" : "vault-bridge");
for (const args of [
  ["build", "--locked", "-p", "vault-bridge"],
  ["test", "--locked", "-p", "vault-service", "official_mcp_clients", "--", "--ignored"],
]) {
  const r = spawnSync("cargo", args, { env, cwd: root, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

