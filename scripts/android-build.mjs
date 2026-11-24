// macOS arm64。使用已安装且由用户接受许可的 SDK。构建不调用 sdkmanager。
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, statfsSync, readFileSync, writeFileSync,
  readdirSync, statSync, realpathSync, cpSync, copyFileSync, renameSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname, sep } from "node:path";
import { buildEnv, root } from "./env.mjs";

const env = buildEnv();
const app = join(root, "apps/client");
const native = join(app, "android");
const gen = join(app, "src-tauri/gen/android");
const sdk = env.ANDROID_HOME || join(homedir(), "Library/Android/sdk");
const buildTools = join(sdk, "build-tools/37.0.0");
const ndk = env.NDK_HOME || join(sdk, "ndk/29.0.14206865");
const keydir = join(homedir(), ".local/share/suishen-vault/android-signing");
const output = join(root, "dist/android");
const run = (command, args, extra = {}) => execFileSync(command, args, { cwd: root, env, stdio: "inherit", ...extra });
function space(path, gib) {
  while (!existsSync(path)) path = dirname(path);
  const stat = statfsSync(path);
  const avail = stat.bavail * stat.bsize / 2 ** 30;
  if (avail < gib) throw Error("可用空间 " + avail.toFixed(1) + " GiB，当前步骤预计需预留 " + gib + " GiB。见 docs/Android构建.md");
}
function preflight() {
  run("df", ["-h", root]);
  space(root, 3);
  for (const path of [join(sdk, "licenses/android-sdk-license"), join(sdk, "platforms/android-37/android.jar"),
    join(sdk, "platforms/android-36/android.jar"), join(buildTools, "apksigner"), join(buildTools, "zipalign"),
    join(ndk, "source.properties")]) {
    if (!existsSync(path)) throw Error("缺少 " + path + "。请本人按 docs/Android构建.md 安装并确认许可。");
  }
  if (!env.JAVA_HOME || !existsSync(join(env.JAVA_HOME, "bin/keytool"))) throw Error("请设置 JDK 17 或以上的 JAVA_HOME");
  const targets = run("rustup", ["target", "list", "--installed"], { stdio: "pipe", encoding: "utf8" });
  if (!targets.split(/\s+/).includes("aarch64-linux-android")) throw Error("请先安装 aarch64-linux-android Rust 标准库");
  Object.assign(env, { ANDROID_HOME: sdk, ANDROID_SDK_ROOT: sdk, NDK_HOME: ndk, ANDROID_NDK_HOME: ndk });
}
function prepare() {
  if (!existsSync(join(gen, "gradlew")))
    run(process.execPath, ["scripts/tauri.mjs", "android", "init", "--ci", "--skip-targets-install"]);
  const main = join(gen, "app/src/main");
  const activities = readdirSync(main, { recursive: true }).filter(p => p.endsWith("/MainActivity.kt"));
  if (activities.length !== 1) throw Error("生成工程中 MainActivity 不唯一，请检查 Tauri 模板");
  cpSync(join(native, "kotlin"), dirname(join(main, activities[0])), { recursive: true });
  cpSync(join(native, "res"), join(main, "res"), { recursive: true });
  copyFileSync(join(native, "AndroidManifest.xml"), join(main, "AndroidManifest.xml"));
  copyFileSync(join(native, "proguard-vault.pro"), join(gen, "app/proguard-vault.pro"));
  const props = join(gen, "gradle.properties");
  const previous = readFileSync(props, "utf8");
  if (!previous.includes("android.builder.sdkDownload=false"))
    writeFileSync(props, previous + "\nandroid.builder.sdkDownload=false\n");
}
function sign(unsigned) {
  process.umask(0o077);
  mkdirSync(keydir, { recursive: true, mode: 0o700 });
  if ((realpathSync(keydir) + sep).startsWith(realpathSync(root) + sep) ||
      (statSync(keydir).mode & 0o077)) throw Error("签名目录必须位于仓库外且权限为 0700");
  const store = join(keydir, "release.p12"), pass = join(keydir, "release.pass");
  if (!existsSync(store)) {
    if (!existsSync(pass)) writeFileSync(pass, randomBytes(32).toString("base64") + "\n", { flag: "wx", mode: 0o600 });
    run(join(env.JAVA_HOME, "bin/keytool"), ["-genkeypair", "-alias", "vault", "-keyalg", "RSA", "-keysize", "3072",
      "-validity", "10000", "-storetype", "PKCS12", "-keystore", store, "-storepass:file", pass,
      "-keypass:file", pass, "-dname", "CN=Suishen Vault Android"]);
  }
  mkdirSync(output, { recursive: true });
  const tmp = mkdtempSync(join(output, ".sign-"));
  try {
    const aligned = join(tmp, "aligned.apk"), apk = join(tmp, "signed.apk");
    run(join(buildTools, "zipalign"), ["-P", "16", "-f", "4", unsigned, aligned]);
    run(join(buildTools, "apksigner"), ["sign", "--ks", store, "--ks-key-alias", "vault", "--ks-pass",
      "file:" + pass, "--v4-signing-enabled", "false", "--out", apk, aligned]);
    run(join(buildTools, "apksigner"), ["verify", "--verbose", apk]);
    run(join(buildTools, "zipalign"), ["-c", "-P", "16", "4", apk]);
    const entries = run("unzip", ["-Z1", apk], { encoding: "utf8", stdio: "pipe" }).split("\n");
    if (!entries.includes("lib/arm64-v8a/libsuishen_vault_client_lib.so") ||
        entries.some(p => /^lib\/(?!arm64-v8a\/)/.test(p))) throw Error("APK 架构不符");
    renameSync(apk, join(output, "suishen-vault-arm64.apk"));
    console.log("已生成并校验 dist/android/suishen-vault-arm64.apk");
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
try {
  preflight();
  if (!process.argv.includes("--check")) {
    space(env.CARGO_TARGET_DIR, 5);
    space(root, 5);
    prepare();
    run("df", ["-h", root]);
    run(process.execPath, ["scripts/tauri.mjs", "android", "build", "--target", "aarch64", "--apk", "--ci", "--split-per-abi"]);
    const apkRoot = join(gen, "app/build/outputs/apk");
    const candidates = readdirSync(apkRoot, { recursive: true })
      .filter(p => /(^|\/)arm64\/release\/[^/]+\.apk$/.test(p));
    if (candidates.length !== 1) throw Error("请检查 arm64 release APK 输出目录");
    sign(join(apkRoot, candidates[0]));
  }
} catch (e) { console.error(e.message); process.exitCode = 1; }
