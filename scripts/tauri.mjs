// 用法：npm run client:build -- --debug --no-bundle
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { buildEnv, root } from "./env.mjs";

const r = spawnSync("npm", ["run", "tauri", "--", ...process.argv.slice(2)], {
  cwd: join(root, "apps", "client"),
  env: buildEnv(),
  stdio: "inherit",
  shell: process.platform === "win32",
});
process.exit(r.status ?? 1);
