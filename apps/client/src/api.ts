// 与 Rust 命令的唯一通道。机密只在显示时取回，用完即从状态中去掉。
import { invoke } from "@tauri-apps/api/core";
import type { ExposureScope } from "./status";

export type Scope = ExposureScope;
export type Phase = "empty" | "broken" | "locked" | "serving" | "unlocked" | "retired";
export type Kind = "login" | "note" | "custom";
export type AiField = "username" | "password" | "url" | "note" | "body" | "custom";
export type SecretField = "username" | "password" | "url" | "note" | "totp" | "body" | "custom_name" | "custom_value";

export interface Settings {
  auto_lock_minutes: number;
  clipboard_seconds: number;
  hide_to_tray: boolean;
  notify: boolean;
  shortcut: string;
  port: number;
}
export interface Request {
  request_id: string;
  client: string;
  access: "local" | "direct" | "bridge";
  reason: string;
  title: string;
  type: Kind;
  domain: string | null;
  masked_account: string | null;
  fields: AiField[];
  state: "pending" | "code_issued";
  expires_in_seconds: number;
}
export type Tunnel = "off" | "connecting" | "online" | "offline" | "rejected" | "superseded";
export interface Relay {
  url: string;
  custom_ca: boolean;
  superseded: boolean;
}
export interface Pairing {
  name: string;
  state: "open" | "asked" | "ready";
  expires_in_seconds: number;
  label?: string;
  fingerprint?: string;
}
export interface Status {
  version: string;
  platform: string;
  biometric?: boolean;
  documents?: string[];
  package_kind?: string;
  phase: Phase;
  scope: Scope;
  remaining: number | null;
  tunnel: Tunnel;
  direct: boolean;
  relay: Relay | null;
  pairing: Pairing | null;
  requests: Request[];
  backoff_ms: number;
  migrating: boolean;
  settings: Settings;
  nav: { seq: number; target: string };
  data_dir: string;
  open_error?: UiError;
}
export interface Meta {
  id: string;
  kind: Kind;
  title: string;
  domains: string[];
  tags: string[];
  hint: string;
  masked_account: string | null;
  ai_hidden: boolean;
  created_ms: number;
  updated_ms: number;
  deleted_ms: number | null;
}
export interface Detail extends Meta {
  has: { username: boolean; password: boolean; note: boolean; totp: boolean; body: boolean; urls: number; custom: number };
}
/** `null` 表示保持原值，空字符串表示删除。 */
export interface Draft {
  kind: Kind;
  title: string;
  domains: string[];
  auto_domains: boolean;
  tags: string[];
  hint: string;
  ai_hidden: boolean;
  username: string | null;
  password: string | null;
  note: string | null;
  totp: string | null;
  body: string | null;
  urls: string[] | null;
  custom: { name: string; value: string }[] | null;
}
export interface Client {
  id: string;
  name: string;
  tags: string[];
  access: "local" | "direct" | "bridge";
  drafts_enabled?: boolean;
  search_paused: boolean;
  request_paused: boolean;
}
export interface RecoveryOut {
  recovery_key: string;
  challenge: [number, number];
}
export interface ImportReport {
  format: string;
  imported: number;
  blank: number;
  adjusted: [number, string][];
  rejected: [number, string][];
  prompt: string;
  file: string | null;
}
export interface AuditEvent {
  time_ms: number;
  client: string;
  action: string;
  subject: unknown;
  result: string;
}
export interface Audit {
  events: AuditEvent[];
  titles: Record<string, string>;
  clients: Client[];
}
export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}
export interface UiError {
  code: string;
  message: string;
  wait_ms?: number;
}

export function toError(e: unknown): UiError {
  if (typeof e === "object" && e !== null && "message" in e && "code" in e) return e as UiError;
  return { code: "internal", message: "操作没有完成，请重试" };
}

/** 统一把失败变成 `UiError`，不把底层文本带到界面。 */
export async function call<T = void>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    throw toError(e);
  }
}

export const KINDS: Record<Kind, string> = { login: "账号", note: "笔记", custom: "自定义" };
export const FIELDS: Record<AiField, string> = {
  username: "账号", password: "密码", url: "网址", note: "备注", body: "正文", custom: "自定义字段",
};
