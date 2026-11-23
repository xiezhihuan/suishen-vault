// 输出可复制的项目配置，不读取凭据，不写入客户端设置。
import { resolve } from "node:path";
import { buildEnv } from "./env.mjs";
const [client, transport = "stdio"] = process.argv.slice(2);
if (!["claude", "codex"].includes(client) || !["stdio", "http"].includes(transport)) {
  console.error("用法：node scripts/mcp-config.mjs claude|codex [stdio|http]");
  process.exit(2);
}
const command = resolve(buildEnv().CARGO_TARGET_DIR, "debug", process.platform === "win32" ? "vault-bridge.exe" : "vault-bridge");
const url = "http://127.0.0.1:47600/mcp";
if (client === "claude") {
  const config = transport === "stdio" ? { type: "stdio", command, args: ["mcp", "claude"] }
    : { type: "http", url, headers: { Authorization: "Bearer ${SUISHEN_CLAUDE_TOKEN}" } };
  console.log(JSON.stringify({ mcpServers: { "suishen-vault": config } }, null, 2));
} else {
  console.log("[mcp_servers.suishen-vault]");
  console.log(transport === "stdio"
    ? "command = " + JSON.stringify(command) + '\nargs = ["mcp", "codex"]'
    : "url = " + JSON.stringify(url) + '\nbearer_token_env_var = "SUISHEN_CODEX_TOKEN"');
}

