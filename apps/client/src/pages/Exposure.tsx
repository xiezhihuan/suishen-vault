import { useState } from "react";
import { call, type Relay, type Scope, type Status } from "../api";
import { useAction } from "../hooks";
import { scopeLabel } from "../status";
import { Card, Check, Confirm, ErrorText, Page, PasswordField, TextField, takeForm, text } from "../ui";

export function remainingText(status: Status): string {
  if (status.scope === "closed") return "";
  if (status.remaining === null) return "不自动关闭";
  const m = Math.ceil(status.remaining / 60);
  return m >= 60 ? `剩余 ${Math.floor(m / 60)} 小时 ${m % 60} 分` : `剩余 ${m} 分钟`;
}

/** 公网档的连接情况。AC-NET-08 */
export function tunnelText(status: Status): string {
  if (status.scope !== "public") return "";
  switch (status.tunnel) {
    case "online": return status.direct ? "已连上跳板，直连已开" : "已连上跳板，只接受桥接";
    case "rejected": return "跳板不认这台设备，请重新配对";
    case "offline": return "连不上跳板，正在重试";
    default: return "正在连接跳板";
  }
}

const TIMES: [number, string][] = [[15, "15 分钟"], [60, "1 小时"], [480, "8 小时"], [0, "不自动关闭"]];
const OPTIONS: { scope: Scope; note: string; ready: boolean }[] = [
  { scope: "closed", note: "不监听任何端口，AI 连不上。重启后总是这个状态。", ready: true },
  { scope: "loopback", note: "只有这台设备上的 AI 能连。", ready: true },
  { scope: "lan", note: "同一网络里已配对的设备能连，全程 TLS 1.3。", ready: false },
  { scope: "public", note: "这台设备主动连到你自己的跳板，别处的 AI 经跳板连进来。不附带开放局域网。", ready: true },
];

function Times({ value, onChange, name }: { value: number; onChange: (v: number) => void; name: string }) {
  return (
    <fieldset className="segmented"><legend>自动关闭</legend>
      {TIMES.map(([v, l]) => <label key={v}><input type="radio" name={name} checked={value === v} onChange={() => onChange(v)} />{l}</label>)}
    </fieldset>
  );
}

export function Exposure({ status, refresh }: { status: Status; refresh: () => Promise<void> }) {
  const [minutes, setMinutes] = useState(480);
  const [asking, setAsking] = useState(false);
  const { busy, error, run } = useAction();
  const open = status.scope !== "closed";
  const usable = status.relay !== null && !status.relay.superseded;
  const start = (scope: Scope, m: number, direct: boolean) => void run(async () => {
    await call("open_service", { scope, minutes: m, direct });
    await refresh();
  });
  const choose = (s: Scope) => {
    if (s === status.scope) return;
    if (s === "closed") void run(async () => { await call("close_service"); await refresh(); });
    else if (s === "loopback") start(s, minutes, false);
    else if (s === "public") setAsking(true);
  };
  const why = (s: Scope) => {
    if (s === "lan") return " · 这一版还没有";
    return s === "public" && !usable ? " · 先在下方配对跳板" : "";
  };
  return (
    <Page title="开放范围" note="决定哪里的 AI 能连到这台设备。能连上也只能搜打码信息和提申请。">
      <Card tone={status.scope === "public" ? "warn" : open ? "good" : undefined}>
        <p className="scope-now">当前：<strong>{scopeLabel(status.scope)}</strong> {remainingText(status)}</p>
        {status.scope === "public" && <p role="status">{tunnelText(status)}</p>}
        {status.tunnel === "superseded" && <p role="alert" className="warn-text">跳板已由另一台设备接管，这台的公网已关闭。如果不是你操作的，请登录服务器检查。密库没有受影响。</p>}
        {open && <div className="actions"><button className="danger big" disabled={busy} onClick={() => choose("closed")}>全部关闭并撤销授权</button></div>}
      </Card>
      {!open && <Times value={minutes} onChange={setMinutes} name="minutes" />}
      <div className="choices">
        {OPTIONS.map((o) => (
          <button key={o.scope} className={`choice ${status.scope === o.scope ? "on" : ""}`} aria-pressed={status.scope === o.scope}
            disabled={busy || !o.ready || status.migrating || (o.scope === "public" && !usable)} onClick={() => choose(o.scope)}>
            <strong>{scopeLabel(o.scope)}{why(o.scope)}</strong><span>{o.note}</span>
          </button>
        ))}
      </div>
      <ErrorText error={error} />
      <p className="muted">端口 {status.settings.port}，可在设置里改。关闭或切换时，所有申请、授权码、搜索结果编号立即失效。</p>
      <RelayCard relay={status.relay} locked={status.scope === "public"} refresh={refresh} />
      {asking && <OpenPublic onCancel={() => setAsking(false)} onOpen={(m, direct) => { setAsking(false); start("public", m, direct); }} />}
    </Page>
  );
}

function OpenPublic({ onCancel, onOpen }: { onCancel: () => void; onOpen: (minutes: number, direct: boolean) => void }) {
  const [minutes, setMinutes] = useState(60);
  const [direct, setDirect] = useState(false);
  return (
    <Confirm title="开放公网？" confirm="开放公网" danger onCancel={onCancel} onConfirm={() => onOpen(minutes, direct)}>
      <Times value={minutes} onChange={setMinutes} name="public-minutes" />
      <p><strong>桥接</strong>（总是可用）：AI 那台电脑装 vault-bridge 并与这台配对。两端互认公钥，跳板和反向代理只看到密文。</p>
      <Check label="同时允许直连 HTTPS" checked={direct} onChange={setDirect}
        hint="不用装桥接，AI 直接连跳板网址。但跳板那台服务器解开了 HTTPS，理论上能看到令牌、授权码，以及交给 AI 的那条明文。" />
      <p className="muted">切换时，现有申请与授权码立即失效。</p>
    </Confirm>
  );
}

function RelayCard({ relay, locked, refresh }: { relay: Relay | null; locked: boolean; refresh: () => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [forget, setForget] = useState(false);
  const { busy, error, run } = useAction();
  const form = !relay || editing;
  return (
    <Card title="公网跳板" tone={relay?.superseded ? "warn" : undefined}>
      {relay && <p>{relay.url}{relay.custom_ca && "（使用你指定的证书）"}</p>}
      {relay?.superseded && <p className="warn-text">已由另一台设备接管。要换回这台，请重新配对。</p>}
      {!relay && <p className="muted">跳板跑在你自己的公网服务器上，部署方法见 docs/公网跳板.md。它同一时间只认一台设备。</p>}
      {form ? (
        <form onSubmit={(e) => {
          const el = e.currentTarget;
          const f = takeForm(e);
          void run(async () => {
            await call("relay_claim", { url: text(f, "url"), ca: text(f, "ca") || null, code: text(f, "code"), password: text(f, "password") });
            el.reset();
            setEditing(false);
            await refresh();
          });
        }}>
          <TextField label="跳板地址" name="url" required maxLength={260} placeholder="relay.example.com" mono />
          <PasswordField label="配对码" name="code" hint="在服务器上运行 vault-relay pair-code 得到，10 分钟有效。配对后，原来登记的设备立即断开并失效。" />
          <details><summary>服务器用自签证书？</summary>
            <TextField label="CA 证书（PEM，可不填）" name="ca" multiline mono hint="填了就只认这张证书。不要粘贴私钥。" />
          </details>
          <PasswordField label="主密码" name="password" />
          <ErrorText error={error} />
          <div className="actions">
            <button className="primary" disabled={busy || locked}>{busy ? "正在配对…" : "配对这台设备"}</button>
            {editing && <button type="button" onClick={() => setEditing(false)}>取消</button>}
          </div>
          {locked && <p className="muted">请先关闭公网。</p>}
        </form>
      ) : (
        <>
          <ErrorText error={error} />
          <div className="actions">
            <button disabled={locked} onClick={() => setEditing(true)}>重新配对或换跳板…</button>
            <button className="danger" disabled={locked} onClick={() => setForget(true)}>忘记跳板…</button>
          </div>
        </>
      )}
      {forget && <Confirm title="忘记跳板？" confirm="忘记" danger onCancel={() => setForget(false)}
        onConfirm={() => { setForget(false); void run(async () => { await call("relay_forget"); await refresh(); }); }}>
        <p>清除这台设备上的跳板地址与设备身份。已配对的桥接要重新配对。</p>
      </Confirm>}
    </Card>
  );
}
