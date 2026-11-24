// 启动真实 Tauri 调试程序，生产前端从 dist 提供。测试驱动仅在独立的回环测试服务器中挂载。
import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from "node:fs";
import { join, resolve } from "node:path";
import { buildEnv, root } from "../env.mjs";

if (process.platform !== "darwin") throw Error("此验收脚本需要 macOS");
const qa = join(root, "target", "window-qa");
mkdirSync(qa, { recursive: true });
const dir = mkdtempSync(join(qa, "vault-"));
const shots = join(root, "docs", "验收截图");
mkdirSync(shots, { recursive: true });
const port = 47381;
writeFileSync(
  join(dir, "settings.json"),
  JSON.stringify({ port, notify: false, shortcut: "", auto_lock_minutes: 60 }),
);
const nonce = randomBytes(24).toString("hex");
const dist = join(root, "apps/client/dist");
const driver = readFileSync(new URL("window-driver.js", import.meta.url), "utf8");
const sdk = new URL("sdk.py", import.meta.url);
const win = new URL("window.swift", import.meta.url);
const env = buildEnv();
let app,
  completed = false,
  finish;
const finished = new Promise((r) => {
  finish = r;
});
const markers = [
  "Fake-Main-Desk-8237",
  "Fake:🔐",
  "Fake-Only-Test-3189",
  "fake.horizon",
  "demo-user",
  "北极星测试站",
];
let output = "";
const server = createServer(async (req, res) => {
  const path = req.url;
  try {
    if (req.headers.host !== "localhost:1420") {
      res.writeHead(403).end();
      return;
    }
    if (req.method === "POST" && path === "/qa/" + nonce && req.headers.origin === "http://localhost:1420") {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const args = JSON.parse(Buffer.concat(chunks));
      let result = true;
      if (["submit", "request", "redeem"].includes(args.step)) {
        if (args.token) markers.push(args.token);
        if (args.code) markers.push(args.code);
        const r = spawnSync("python3", [sdk.pathname], {
          input: JSON.stringify({ ...args, port }),
          encoding: "utf8",
          timeout: 20000,
        });
        if (r.status !== 0) throw Error("SDK 请求失败");
        result = JSON.parse(r.stdout);
      } else if (["paste-shot", "draft-shot", "saved-shot"].includes(args.step)) {
        const id = spawnSync("swift", [win.pathname, String(app.pid)], { encoding: "utf8" });
        if (id.status !== 0 || !/^\d+$/.test(id.stdout.trim())) throw Error("无法定位测试窗口");
        const name = { "paste-shot": "智能粘贴", "draft-shot": "草稿确认", "saved-shot": "确认入库" }[args.step];
        if (spawnSync("screencapture", ["-x", "-o", "-l", id.stdout.trim(), join(shots, name + ".png")]).status !== 0)
          throw Error("窗口截图失败");
      } else if (args.step === "done") {
        completed = true;
        finish();
      } else if (args.step === "error") {
        process.stderr.write("窗口步骤失败 " + String(args.stage).slice(0, 12) + "\n");
        finish();
      } else throw Error("步骤未知");
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(result));
      return;
    }
    if (req.method !== "GET") {
      res.writeHead(405).end();
      return;
    }
    if (path === "/") {
      res.setHeader("content-type", "text/html");
      res.end(
        readFileSync(join(dist, "index.html"), "utf8").replace(
          "</body>",
          '<script type="module" src="/qa-driver.js"></script></body>',
        ),
      );
      return;
    }
    if (path === "/qa-driver.js") {
      res.setHeader("content-type", "application/javascript");
      res.end(driver + "\nexercise(" + JSON.stringify({ dir, nonce }) + ");");
      return;
    }
    if (!/^\/assets\/[\w.-]+\.(js|css)$/.test(path)) {
      res.writeHead(404).end();
      return;
    }
    res.setHeader("content-type", path.endsWith(".css") ? "text/css" : "application/javascript");
    res.end(readFileSync(resolve(dist, "." + path)));
  } catch {
    res.writeHead(500).end();
  }
});
try {
  await new Promise((ok, no) => {
    server.once("error", no);
    server.listen(1420, "localhost", ok);
  });
  app = spawn(join(env.CARGO_TARGET_DIR, "debug/suishen-vault-client"), [], {
    env: { ...env, SUISHEN_DATA_DIR: dir, SUISHEN_ALLOW_CAPTURE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const stream of [app.stdout, app.stderr])
    stream.on("data", (chunk) => {
      output += chunk;
    });
  app.on("exit", () => finish());
  const timer = setTimeout(finish, 90000);
  try {
    await finished;
  } finally {
    clearTimeout(timer);
  }
  if (!completed) throw Error("真实窗口验收未完成");
  const db = readFileSync(join(dir, "vault.svault"));
  if (markers.some((m) => output.includes(m) || db.includes(Buffer.from(m)))) throw Error("发现合成明文");
  process.stdout.write("macOS 窗口两条录入流程、授权取用与重放拒绝通过，数据库和进程输出扫描通过。\n");
} finally {
  if (app && app.exitCode === null) {
    const exited = new Promise((r) => app.once("exit", r));
    app.kill();
    await exited;
  }
  server.close();
}
