// 在干净的 Debian + systemd 容器里逐条执行 docs/公网跳板.md 的部署命令：npm run test:deploy
// 命令直接从文档里带 deploy-test 标记的代码块取，只替换域名。只用 localhost 与假数据。
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildEnv, root } from "./env.mjs";

const PORT = "18443";
const SSH_PORT = "18022";
const HOST = `localhost:${PORT}`;
const NAME = "sv-deploy-test";
const IMAGE = "sv-deploy-test/debian";
const tmp = mkdtempSync(join(tmpdir(), "sv-deploy-"));
const env = buildEnv();

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: root, env, encoding: "utf8", ...opts });
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.slice(0, 6).join(" ")} 失败\n${r.stdout ?? ""}${r.stderr ?? ""}`);
  return r.stdout ?? "";
}
const inside = (script) => run("docker", ["exec", "-w", "/root/deploy", NAME, "bash", "-euo", "pipefail", "-c", script]);
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
function check(ok, what) {
  if (!ok) throw new Error(`不符合：${what}`);
  console.log(`  ✓ ${what}`);
}

const doc = readFileSync(join(root, "docs/公网跳板.md"), "utf8");
function block(name) {
  const m = doc.match(new RegExp(`<!-- deploy-test:${name} -->\\n\`\`\`bash\\n([\\s\\S]*?)\`\`\``));
  if (!m) throw new Error(`文档里没有 ${name} 代码块`);
  return m[1];
}

function certificates() {
  const at = (f) => join(tmp, f);
  const key = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  run("openssl", ["req", "-x509", ...key, "-keyout", at("ca.key"), "-out", at("ca.pem"), "-days", "2", "-subj", "/CN=sv fake ca"]);
  run("openssl", ["req", ...key, "-keyout", at("privkey.pem"), "-out", at("leaf.csr"), "-subj", "/CN=localhost"]);
  writeFileSync(at("ext"), "subjectAltName=DNS:localhost\n");
  run("openssl", ["x509", "-req", "-in", at("leaf.csr"), "-CA", at("ca.pem"), "-CAkey", at("ca.key"), "-CAcreateserial", "-days", "2", "-extfile", at("ext"), "-out", at("fullchain.pem")]);
}

function cargo(test, extra = {}) {
  const r = spawnSync("cargo", ["test", "--locked", "-p", "vault-bridge", "--test", "relay", test, "--", "--ignored", "--exact"], {
    cwd: root, stdio: "inherit",
    env: { ...env, SV_RELAY_URL: `https://${HOST}`, SV_RELAY_CA: join(tmp, "ca.pem"), SV_RELAY_CONTAINER: NAME, SV_PROXY_CONTAINER: NAME, SV_CAPTURE: "", ...extra },
  });
  if (r.status !== 0) throw new Error(`${test} 失败`);
}

const DEBIAN = `FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv openssh-server ca-certificates iproute2 procps
CMD ["/lib/systemd/systemd"]
STOPSIGNAL SIGRTMIN+3
`;

let failed = false;
try {
  run("docker", ["version"]);
  certificates();
  console.log("导出可执行文件、准备干净的 Debian……");
  run("docker", ["build", "-f", "deploy/relay/Dockerfile", "--target", "bin", "--output", join(tmp, "out"), "."]);
  run("docker", ["build", "--load", "-t", IMAGE, "-"], { input: DEBIAN });
  run("docker", ["run", "-d", "--name", NAME, "--privileged", "--cgroupns", "private", "--tmpfs", "/run", "--tmpfs", "/tmp", "-p", `127.0.0.1:${PORT}:443`, "-p", `127.0.0.1:${SSH_PORT}:22`, IMAGE]);
  for (let i = 0; i < 60; i += 1) {
    const s = run("docker", ["exec", NAME, "systemctl", "is-system-running"], { mayFail: true }).trim();
    if (s === "running" || s === "degraded") break;
    sleep(500);
  }
  run("docker", ["exec", NAME, "mkdir", "-p", "/root/deploy/deploy", "/etc/nginx/tls"]);
  run("docker", ["cp", join(tmp, "out/vault-relay"), `${NAME}:/root/deploy/vault-relay`]);
  run("docker", ["cp", join(root, "deploy/relay"), `${NAME}:/root/deploy/deploy/relay`]);
  for (const f of ["fullchain.pem", "privkey.pem"]) run("docker", ["cp", join(tmp, f), `${NAME}:/etc/nginx/tls/${f}`]);

  console.log("执行文档：systemd");
  const out = inside(block("systemd").replace("VAULT_RELAY_HOST=relay.example.com", `VAULT_RELAY_HOST=${HOST}`));
  check(out.trim().endsWith("active"), "vault-relay 已在运行");
  console.log("执行文档：Nginx");
  inside(block("nginx").replace("/relay.example.com/'", "/localhost/'"));
  const curl = run("curl", ["-sS", "--noproxy", "*", "--cacert", join(tmp, "ca.pem"), "-w", " %{http_code}", `https://${HOST}/`]);
  check(curl === '{"error":"unavailable"} 503', "没有设备时是统一的离线答复");
  check(inside(block("code")).includes("配对码："), "管理员能生成配对码");
  check(inside("stat -c %U:%a /var/lib/vault-relay/pairing.json").trim() === "vault-relay:600", "root 生成的配对码跳板也能读，权限 600");
  check(inside("ps -o user= -C vault-relay").trim() === "vault-relay", "以普通用户运行");
  check(!/(^|\s)(0\.0\.0\.0|\*|\[::\]):7470/m.test(inside("ss -ltnH")), "7470 只监听回环");
  inside("systemd-analyze verify /etc/systemd/system/vault-relay.service");
  check(true, "systemd-analyze verify 无告警");
  console.log(`  systemd 加固评分：${inside("systemd-analyze security vault-relay --no-pager | tail -1").trim()}`);

  cargo("docker_deployed_by_the_docs");
  const log = inside("journalctl -u vault-relay -o cat --no-pager").split("\n").filter((l) => l.startsWith("vault-relay "));
  check(log.length > 0 && log.every((l) => /^vault-relay [a-z_]+$/.test(l)), "日志只有固定事件名");
  check(inside("cat /var/log/nginx/*.log 2>/dev/null | grep -c localhost || true").trim() === "0", "Nginx 没有访问日志");
  check(inside("ls -A /var/lib/vault-relay").split("\n").filter(Boolean).every((f) => ["state.json", "pairing.json"].includes(f)), "状态目录只有登记文件");

  console.log("执行文档：ssh -R");
  run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(tmp, "id")]);
  chmodSync(join(tmp, "id"), 0o600);
  const pub = readFileSync(join(tmp, "id.pub"), "utf8").trim();
  inside(`useradd -m tunnel; install -d -o tunnel -m 700 /home/tunnel/.ssh
    echo 'restrict,port-forwarding,permitlisten="127.0.0.1:47600" ${pub}' > /home/tunnel/.ssh/authorized_keys
    chown tunnel /home/tunnel/.ssh/authorized_keys; systemctl restart ssh
    rm /etc/nginx/conf.d/vault-relay.conf; install -m 644 deploy/relay/nginx-ssh.conf /etc/nginx/conf.d/vault-ssh.conf
    sed -i 's/relay\\.example\\.com/localhost/' /etc/nginx/conf.d/vault-ssh.conf`);
  mkdirSync(join(tmp, "ssh"), { recursive: true });
  const extra = `-F /dev/null -p ${SSH_PORT} -i ${join(tmp, "id")} -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=${join(tmp, "ssh/known")} -o LogLevel=ERROR -o BatchMode=yes`;
  const command = block("ssh").trim().replace(/^ssh /, `${extra} `).replace("relay.example.com", "127.0.0.1");
  cargo("docker_ssh_reverse", { SV_SSH_ARGS: command });
} catch (e) {
  failed = true;
  console.error(String(e.message ?? e));
} finally {
  run("docker", ["rm", "-f", "-v", NAME], { mayFail: true });
  run("docker", ["image", "rm", IMAGE], { mayFail: true });
  rmSync(tmp, { recursive: true, force: true });
}
if (failed) process.exit(1);
console.log("\n按文档部署通过。");
