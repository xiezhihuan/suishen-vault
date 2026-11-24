// 公网端到端测试：npm run test:relay [caddy|nginx]
// 在本机 Docker 里起跳板与反向代理（用 deploy/relay 里的部署文件），不连接任何真实服务器。
// 设备与桥接跑在本机，tcpdump 抓跳板网卡。只用假数据，测完删除自己建的容器、卷、网络、镜像。
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildEnv, root } from "./env.mjs";

const PORT = "18443";
const HOST = `localhost:${PORT}`;
const tmp = mkdtempSync(join(tmpdir(), "sv-relay-"));
const env = { ...buildEnv(), RELAY_HOST: HOST, RELAY_PER_SOURCE: "100000", SV_PORT: PORT, SV_TMP: tmp };
const project = "sv-relay-test";
const files = ["-f", join(root, "deploy/relay/compose.yaml"), "-f", join(root, "scripts/relay-test/compose.yaml")];

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: root, env, encoding: "utf8", ...opts });
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.slice(0, 8).join(" ")} 失败\n${r.stdout ?? ""}${r.stderr ?? ""}`);
  return `${r.stdout ?? ""}${opts.both ? r.stderr ?? "" : ""}`;
}
const compose = (...args) => run("docker", ["compose", "-p", project, ...files, "--profile", "nginx", "--profile", "capture", ...args]);
const container = (service) => `${project}-${service}-1`;
let capture = "";
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function check(ok, what) {
  if (!ok) throw new Error(`不符合：${what}`);
  console.log(`  ✓ ${what}`);
}

/** 自签 CA 与叶证书，只在临时目录里。 */
function certificates() {
  const dir = join(tmp, "tls");
  mkdirSync(dir, { recursive: true });
  const at = (f) => join(dir, f);
  const key = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  run("openssl", ["req", "-x509", ...key, "-keyout", at("ca.key"), "-out", at("ca.pem"), "-days", "2", "-subj", "/CN=sv fake ca"]);
  run("openssl", ["req", ...key, "-keyout", at("privkey.pem"), "-out", at("leaf.csr"), "-subj", "/CN=localhost"]);
  writeFileSync(at("ext"), "subjectAltName=DNS:localhost\n");
  run("openssl", ["x509", "-req", "-in", at("leaf.csr"), "-CA", at("ca.pem"), "-CAkey", at("ca.key"), "-CAcreateserial", "-days", "2", "-extfile", at("ext"), "-out", at("fullchain.pem")]);
  return at("ca.pem");
}

function prepare(proxy) {
  if (proxy === "caddy") return;
  const conf = readFileSync(join(root, "deploy/relay/nginx.conf"), "utf8")
    .replace("listen 443 ssl", `listen ${PORT} ssl`)
    .replace("server_name relay.example.com", "server_name localhost")
    .replace("http://127.0.0.1:7470", "http://relay:7470");
  writeFileSync(join(tmp, "nginx.conf"), conf);
}

function ca(proxy) {
  if (proxy === "nginx") return certificates();
  const out = join(tmp, "caddy-root.pem");
  for (let i = 0; i < 60; i += 1) {
    const r = run("docker", ["exec", container("caddy"), "cat", "/data/caddy/pki/authorities/local/root.crt"], { mayFail: true });
    if (r.includes("BEGIN CERTIFICATE")) {
      writeFileSync(out, r);
      return out;
    }
    sleep(500);
  }
  throw new Error("Caddy 没有生成根证书");
}

const curl = (caFile, ...args) => run("curl", ["-sS", "--noproxy", "*", "--cacert", caFile, "--max-time", "10", ...args], { mayFail: true });

function ready(caFile) {
  for (let i = 0; i < 60; i += 1) {
    const started = run("docker", ["logs", container("relay")], { both: true }).includes("started");
    if (started && curl(caFile, `https://${HOST}/`).includes("unavailable")) return;
    sleep(500);
  }
  throw new Error("反向代理没有就绪");
}

function capturing() {
  for (let i = 0; i < 60; i += 1) {
    if (existsSync(capture)) return;
    sleep(500);
  }
  throw new Error(`抓包没有开始\n${run("docker", ["logs", container("tcpdump")], { both: true, mayFail: true })}`);
}

function verify(proxy, caFile) {
  const name = container(proxy);
  // 跳板没在运行时，代理自己的错误日志不能带上请求内容
  run("docker", ["stop", "-t", "1", container("relay")]);
  const fake = "FAKE-CODE-7K3MQ9XD";
  curl(caFile, "-H", `X-Auth-Code: ${fake}`, "-H", `Authorization: Bearer ${fake}`, `https://${HOST}/v1/requests/req_${"0".repeat(32)}/secret`);
  const down = curl(caFile, "-w", " %{http_code}", `https://${HOST}/`);
  check(down === '{"error":"unavailable"} 503', "跳板停止时答复与离线相同");
  sleep(500);
  const relayLog = run("docker", ["logs", container("relay")], { both: true });
  const proxyLog = run("docker", ["logs", name], { both: true });
  const strange = relayLog.split("\n").filter((l) => l && !/^vault-relay [a-z_]+$/.test(l));
  check(strange.length === 0, "跳板日志只有固定事件名");
  for (const marker of ["Fake-", "fake-oriole", "Bearer", "FAKE-CODE", "X-Auth-Code", "req_", "/v1/", "/mcp"]) {
    check(!proxyLog.includes(marker), `${proxy} 日志不含 ${marker}`);
  }
  // OrbStack 会给每个容器注入自己的根证书，与跳板无关
  const orb = /^C \/(etc|etc\/ssl|etc\/ssl\/certs|etc\/ssl\/certs\/ca-certificates\.crt|usr|usr\/local|usr\/local\/share)$|ca-certificates$|orbstack-root\.crt$/;
  const written = run("docker", ["diff", container("relay")]).split("\n").filter((l) => l && !orb.test(l));
  check(written.length === 0, "跳板容器没有写任何文件");
  const state = join(tmp, "state");
  rmSync(state, { recursive: true, force: true });
  run("docker", ["cp", `${container("relay")}:/var/lib/vault-relay`, state]);
  const names = run("ls", ["-A", state]).split("\n").filter(Boolean).filter((f) => f !== "pairing.json");
  check(names.join() === "state.json", "跳板状态目录只有登记文件");
  const saved = JSON.parse(readFileSync(join(state, "state.json"), "utf8"));
  check(Object.keys(saved).sort().join() === "current,retired", "登记文件只有公钥");
  check(statSync(capture).size > 10_000, "抓包文件有内容");
}

function cycle(proxy) {
  console.log(`\n=== ${proxy} ===`);
  // 每轮一个文件名，避免共享目录缓存到上一轮已删除的文件
  capture = join(tmp, `capture-${proxy}.pcap`);
  env.SV_CAPTURE_NAME = `capture-${proxy}.pcap`;
  prepare(proxy);
  const early = proxy === "nginx" ? ca(proxy) : null;
  compose("up", "-d", "--no-build", "relay", proxy, "tcpdump");
  const caFile = early ?? ca(proxy);
  capturing();
  ready(caFile);
  const r = spawnSync("cargo", ["test", "--locked", "-p", "vault-bridge", "--test", "relay", "docker_end_to_end", "--", "--ignored", "--exact"], {
    cwd: root, stdio: "inherit",
    env: { ...env, SV_RELAY_URL: `https://${HOST}`, SV_RELAY_CA: caFile, SV_RELAY_CONTAINER: container("relay"), SV_PROXY_CONTAINER: container(proxy), SV_CAPTURE: capture },
  });
  if (r.status !== 0) throw new Error(`${proxy} 端到端测试失败`);
  verify(proxy, caFile);
  compose("down", "-v", "--remove-orphans", "-t", "1");
}

let failed = false;
try {
  run("docker", ["version"]);
  if (process.env.SV_PREBUILT) {
    console.log("使用已有的测试镜像，不构建");
  } else {
    console.log("构建跳板镜像……");
    compose("build", "relay", "tcpdump");
  }
  for (const proxy of process.argv[2] ? [process.argv[2]] : ["caddy", "nginx"]) cycle(proxy);
} catch (e) {
  failed = true;
  console.error(String(e.message ?? e));
} finally {
  try {
    compose("down", "-v", "--remove-orphans", "-t", "1");
    run("docker", ["image", "rm", "sv-relay-test/relay", "sv-relay-test/tcpdump"], { mayFail: true });
  } catch (e) {
    console.error(`清理没有完成：${e.message}`);
  }
  rmSync(tmp, { recursive: true, force: true });
}
if (failed) process.exit(1);
console.log("\n公网端到端测试通过。");
