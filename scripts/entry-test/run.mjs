// 启动真实 Tauri 调试程序，生产前端从 dist 提供。测试驱动仅在独立的回环测试服务器中挂载。
import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, readdirSync } from "node:fs";
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
const publicTest = process.argv.includes("--relay");
const relayPort = 47382;
const relayUrl = "http://127.0.0.1:" + relayPort;
const relayBin = join(env.CARGO_TARGET_DIR, "debug/vault-relay");
const relayEnv = { ...env, VAULT_RELAY_HOST: relayUrl, VAULT_RELAY_LISTEN: "127.0.0.1:" + relayPort,
  VAULT_RELAY_STATE: join(dir, "relay") };
let relay, claimCode;
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
      if (args.step === "claim" && publicTest) {
        result = { url: relayUrl, code: claimCode };
      } else if (["submit", "request", "redeem", "denied", "code_expired", "closed", "revoked"].includes(args.step)) {
        if (args.token) markers.push(args.token);
        if (args.code) markers.push(args.code);
        const r = spawnSync("python3", [sdk.pathname], {
          input: JSON.stringify({ ...args, port: publicTest ? relayPort : port }),
          encoding: "utf8",
          timeout: 20000,
        });
        if (r.status !== 0) throw Error("SDK 请求失败");
        result = JSON.parse(r.stdout);
        process.stdout.write("SDK 检查通过 " + args.step + "\n");
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
      res.end(driver + "\nexercise(" + JSON.stringify({ dir, nonce, publicTest }) + ");");
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
  if (publicTest) {
    mkdirSync(relayEnv.VAULT_RELAY_STATE, { mode: 0o700 });
    const issued = spawnSync(relayBin, ["pair-code"], { env: relayEnv, encoding: "utf8" });
    claimCode = issued.stdout?.match(/配对码：(\S+)/)?.[1];
    if (!claimCode) throw Error("无法生成本地跳板配对码");
    markers.push(claimCode);
    relay = spawn(relayBin, ["serve"], { env: relayEnv, stdio: ["ignore", "ignore", "pipe"] });
    await new Promise((ok, no) => {
      relay.on("error", no);
      relay.once("exit", () => no(Error("测试跳板未启动")));
      relay.stderr.on("data", chunk => {
        output += chunk;
        if (output.includes("vault-relay started")) ok();
      });
    });
  }
  app = spawn(join(env.CARGO_TARGET_DIR, "debug/suishen-vault-client"), [], {
    env: { ...env, SUISHEN_DATA_DIR: dir, SUISHEN_ALLOW_CAPTURE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const stream of [app.stdout, app.stderr])
    stream.on("data", (chunk) => {
      output += chunk;
    });
  app.on("exit", () => finish());
  const timer = setTimeout(finish, publicTest ? 235000 : 90000);
  try {
    await finished;
  } finally {
    clearTimeout(timer);
  }
  if (!completed) throw Error("真实窗口验收未完成");
  const scan = path => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const file = join(path, entry.name);
      if (entry.isDirectory()) scan(file);
      else if (entry.isFile()) {
        const bytes = readFileSync(file);
        if (markers.some(m => bytes.includes(Buffer.from(m)) || bytes.includes(Buffer.from(m, "utf16le"))))
          throw Error("验收目录发现合成明文");
      }
    }
  };
  scan(dir);
  if (markers.some(m => output.includes(m))) throw Error("进程输出发现合成明文");
  process.stdout.write("macOS 窗口两条录入流程、授权取用与重放拒绝通过，数据库和进程输出扫描通过。\n");
} finally {
  if (app && app.exitCode === null) {
    const exited = new Promise((r) => app.once("exit", r));
    app.kill();
    await exited;
  }
  if (relay && relay.exitCode === null && relay.signalCode === null) {
    const exited = new Promise(r => relay.once("exit", r));
    relay.kill();
    await exited;
  }
  server.close();
}
