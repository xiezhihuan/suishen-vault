// 用法：npm run cargo -- test -p vault-core
import { spawnSync } from "node:child_process";
import { buildEnv, root } from "./env.mjs";

const r = spawnSync("cargo", process.argv.slice(2), { cwd: root, env: buildEnv(), stdio: "inherit" });
process.exit(r.status ?? 1);
