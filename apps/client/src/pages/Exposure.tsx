import { useState } from "react";
import { call, type Scope, type Status } from "../api";
import { useAction } from "../hooks";
import { scopeLabel } from "../status";
import { Card, ErrorText, Page } from "../ui";

export function remainingText(status: Status): string {
  if (status.scope === "closed") return "";
  if (status.remaining === null) return "不自动关闭";
  const m = Math.ceil(status.remaining / 60);
  return m >= 60 ? `剩余 ${Math.floor(m / 60)} 小时 ${m % 60} 分` : `剩余 ${m} 分钟`;
}

const TIMES: [number, string][] = [[15, "15 分钟"], [60, "1 小时"], [480, "8 小时"], [0, "不自动关闭"]];
const OPTIONS: { scope: Scope; note: string; ready: boolean }[] = [
  { scope: "closed", note: "不监听任何端口，AI 连不上。重启后总是这个状态。", ready: true },
  { scope: "loopback", note: "只有这台设备上的 AI 能连。", ready: true },
  { scope: "lan", note: "同一网络里已配对的设备能连，全程 TLS 1.3。", ready: false },
  { scope: "public", note: "经你自己的公网服务器转发密文。", ready: false },
];

export function Exposure({ status, refresh }: { status: Status; refresh: () => Promise<void> }) {
  const [minutes, setMinutes] = useState(480);
  const { busy, error, run } = useAction();
  const open = status.scope !== "closed";
  const choose = (s: Scope) => void run(async () => {
    if (s === "closed") await call("close_service");
    else if (s === "loopback" && !open) await call("open_service", { minutes });
    await refresh();
  });
  return (
    <Page title="开放范围" note="决定哪里的 AI 能连到这台设备。能连上也只能搜打码信息和提申请。">
      <Card tone={open ? "good" : undefined}>
        <p className="scope-now">当前：<strong>{scopeLabel(status.scope)}</strong> {remainingText(status)}</p>
        {open && <div className="actions"><button className="danger big" disabled={busy} onClick={() => choose("closed")}>全部关闭并撤销授权</button></div>}
      </Card>
      {!open && (
        <fieldset className="segmented"><legend>自动关闭</legend>
          {TIMES.map(([v, l]) => <label key={v}><input type="radio" name="minutes" checked={minutes === v} onChange={() => setMinutes(v)} />{l}</label>)}
        </fieldset>
      )}
      <div className="choices">
        {OPTIONS.map((o) => (
          <button key={o.scope} className={`choice ${status.scope === o.scope ? "on" : ""}`} aria-pressed={status.scope === o.scope}
            disabled={busy || !o.ready || status.migrating} onClick={() => choose(o.scope)}>
            <strong>{scopeLabel(o.scope)}{!o.ready && " · 这一版还没有"}</strong><span>{o.note}</span>
          </button>
        ))}
      </div>
      <ErrorText error={error} />
      <p className="muted">端口 {status.settings.port}，可在设置里改。关闭或切换时，所有申请、授权码、搜索结果编号立即失效。</p>
    </Page>
  );
}
