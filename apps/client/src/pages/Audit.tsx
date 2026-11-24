import { useEffect, useState } from "react";
import { call, FIELDS, type AiField, type Audit as Data, type AuditEvent } from "../api";
import { useAction, when } from "../hooks";
import { Card, ErrorText, Page, TextField, takeForm, text } from "../ui";

const ACTIONS: Record<string, string> = { search: "搜索", request: "提出申请", decision: "你的决定", redeem: "领取明文", state: "状态变化" };
const RESULTS: Record<string, string> = {
  ok: "成功", pending: "等待处理", code_issued: "交给 AI（已出码）", view_only: "仅在本机查看", denied: "拒绝", revoked: "撤销", redeemed: "已取走",
  invalid_code: "授权码错误", missing_code: "没带授权码", gone: "已失效", not_ready: "还没批准", unknown_request: "申请不存在", rate_limited: "超过频率限制",
  cooldown: "冷却中", too_many_pending: "待处理太多", invalid_fields: "字段不正确", invalid_reason: "理由不正确", query_too_short: "搜索词太短",
  search_paused: "搜索已暂停", unavailable: "服务不可用",
};

export function describe(e: AuditEvent, data: Data): string {
  const s = (typeof e.subject === "object" && e.subject !== null ? e.subject : {}) as { item?: string; matches?: string[]; fields?: AiField[]; state?: string };
  const title = (id: string) => data.titles[id] ?? "已删除的条目";
  const parts: string[] = [];
  if (s.matches) parts.push(s.matches.length ? `命中 ${s.matches.map(title).join("、")}` : "没有命中");
  if (s.item) parts.push(title(s.item));
  if (s.fields?.length) parts.push(s.fields.map((f) => FIELDS[f] ?? f).join("、"));
  return parts.join(" · ");
}

export function Audit() {
  const [data, setData] = useState<Data | null>(null);
  const [filter, setFilter] = useState("");
  const { busy, error, run } = useAction();
  useEffect(() => { void run(async () => setData(await call<Data>("audit", { query: filter }))); }, [filter, run]);
  const names = new Map(data?.clients.map((c) => [c.id, c.name]));
  return (
    <Page title="审计记录" note="最近 100 条。加密保存在本机，不含密码、授权码、搜索词和理由的原文。">
      <Card>
        <form className="inline grow" onSubmit={(e) => setFilter(text(takeForm(e), "query"))}>
          <TextField label="核对搜索词（只保存了指纹，要输入完全相同的词）" name="query" />
          <button disabled={busy}>核对</button>
        </form>
      </Card>
      <ErrorText error={error} />
      {data && data.events.length === 0 && <Card><p className="empty">{filter ? "没有用这个词搜索过的记录。" : "还没有记录。"}</p></Card>}
      {data && data.events.length > 0 && (
        <ul className="audit">
          {data.events.map((e, i) => (
            <li key={i}>
              <time>{when(e.time_ms)}</time>
              <span className="row-main"><strong>{names.get(e.client) ?? "已吊销的客户端"} · {ACTIONS[e.action] ?? e.action}</strong><small>{describe(e, data)}</small></span>
              <span className={`tag ${e.result}`}>{RESULTS[e.result] ?? e.result}</span>
            </li>
          ))}
        </ul>
      )}
    </Page>
  );
}
