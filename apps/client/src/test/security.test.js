// 前端安全约束：CSP、远程资源、权限、持久化。
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

const root = process.cwd();
const read = (p) => readFileSync(join(root, p), "utf8");
function* files(dir) {
  for (const name of readdirSync(join(root, dir))) {
    const p = `${dir}/${name}`;
    if (statSync(join(root, p)).isDirectory()) { if (name !== "test") yield* files(p); }
    else yield p;
  }
}
const conf = JSON.parse(read("src-tauri/tauri.conf.json"));

test("CSP 只允许应用自身，不含内联、eval、远程地址", () => {
  const csp = conf.app.security.csp;
  expect(csp).toContain("default-src 'none'");
  expect(csp).not.toMatch(/unsafe|\*|https:/);
  expect(csp.match(/http:\/\/[^\s;]+/g)).toEqual(["http://ipc.localhost"]);
  expect(conf.app.security.freezePrototype).toBe(true);
  expect(conf.app.withGlobalTauri).toBe(false);
  expect(conf.app.windows[0].contentProtected).toBe(true);
});

test("权限只有本应用命令，且与后端清单一致", () => {
  const cap = JSON.parse(read("src-tauri/capabilities/main.json"));
  expect(cap.windows).toEqual(["main"]);
  expect(cap.remote).toBeUndefined();
  const listed = [...read("src-tauri/build.rs").matchAll(/^ {4}"(\w+)",/gm)].map((m) => `allow-${m[1]?.replaceAll("_", "-")}`);
  expect(cap.permissions).toEqual(listed);
  const handlers = [...read("src-tauri/src/lib.rs").matchAll(/commands::(\w+),/g)].map((m) => `allow-${m[1]?.replaceAll("_", "-")}`);
  expect(handlers).toEqual(listed);
});

test("源码不注入 HTML、不持久化、不直接联网、不打印", () => {
  const banned = /dangerouslySetInnerHTML|innerHTML|localStorage|sessionStorage|indexedDB|document\.cookie|\beval\(|new Function|\bfetch\(|XMLHttpRequest|WebSocket|console\.|https?:\/\//;
  for (const f of files("src")) if (/\.(tsx?|css)$/.test(f)) expect(banned.exec(read(f))?.[0], f).toBeUndefined();
  expect(read("index.html")).not.toMatch(/https?:|<style|<script(?![^>]*src=)/);
});
