// 假后端：记录调用，按命令返回。只用假数据。
import { mockIPC } from "@tauri-apps/api/mocks";
import type { Request, Status } from "../api";

export const FAKE = { password: "Fake-Violet-Secret-7172", master: "fake-master-鲸鱼-0001", code: "7K3M-Q9XD" };

export function status(part: Partial<Status> = {}): Status {
  return {
    version: "0.0.0", platform: "macos", phase: "unlocked", scope: "closed", remaining: null, tunnel: "off", direct: false, relay: null, pairing: null, requests: [], backoff_ms: 0, migrating: false,
    settings: { auto_lock_minutes: 5, clipboard_seconds: 30, hide_to_tray: true, notify: true, shortcut: "CmdOrCtrl+Alt+K", port: 47600 },
    nav: { seq: 0, target: "" }, data_dir: "/tmp/fake", ...part,
  };
}

export const request = (part: Partial<Request> = {}): Request => ({
  request_id: "req_1", client: "笔记本上的 Claude", access: "local", reason: "要登录测试站", title: "公司邮箱", type: "login", domain: "example.test",
  masked_account: "f***", fields: ["username", "password"], state: "pending", expires_in_seconds: 590, ...part,
});

export const meta = {
  id: "a1", kind: "login", title: "公司邮箱", domains: ["example.test"], tags: ["工作"], hint: "", masked_account: "f***",
  ai_hidden: false, created_ms: 1, updated_ms: 2, deleted_ms: null,
};
export const detail = { ...meta, has: { username: true, password: true, note: false, totp: false, body: false, urls: 1, custom: 0 } };

type Reply = unknown | ((args: Record<string, unknown>) => unknown);

export function backend(replies: Record<string, Reply>) {
  const calls: { cmd: string; args: Record<string, unknown> }[] = [];
  const state = { status: status(), replies };
  mockIPC((cmd, raw) => {
    const args = (raw ?? {}) as Record<string, unknown>;
    if (cmd !== "poll" && cmd !== "touch") calls.push({ cmd, args });
    if (cmd === "poll") return state.status;
    const r = state.replies[cmd];
    return typeof r === "function" ? (r as (a: Record<string, unknown>) => unknown)(args) : r ?? null;
  });
  return { calls, state, of: (cmd: string) => calls.filter((c) => c.cmd === cmd).map((c) => c.args) };
}

export function refuse(code: string, message: string): () => never {
  return () => { throw { code, message }; };
}
