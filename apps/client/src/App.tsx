import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState, type FormEvent } from "react";
import { type AppStatus, scopeLabel } from "./status";

type Grant = { request_id: string; title: string; client: string; reason: string; fields: string[]; state: string };
type Panel = { clients: { id: string; name: string; tags: string[] }[]; requests: Grant[] };
type Display = { label: string; value: string; ms: number };
const fieldNames: Record<string, string> = { username: "账号", password: "密码", note: "备注", url: "网址", body: "正文", custom: "自定义字段" };
const master = () => <label>主密码<input name="password" type="password" autoComplete="off" required /></label>;
function takeForm(event: FormEvent<HTMLFormElement>) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const password = form.elements.namedItem("password") as HTMLInputElement | null;
  if (password) password.value = "";
  return data;
}

function ApprovalButtons({ busy }: { busy: boolean }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const timer = window.setTimeout(() => setReady(true), 2000);
    return () => window.clearTimeout(timer);
  }, []);
  return <><button disabled={busy || !ready} value="view">仅在本机查看</button>{" "}
    <button disabled={busy || !ready} value="issue">交给 AI</button></>;
}

export function App() {
  const [status, setStatus] = useState<(AppStatus & { remaining: number | null }) | null>(null);
  const [panel, setPanel] = useState<Panel | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [display, setDisplay] = useState<Display | null>(null);
  async function refresh() {
    const state = await invoke<AppStatus & { remaining: number | null }>("app_status");
    setStatus(state);
    if (state.scope === "closed") { setPanel(null); setDisplay(null); }
    else setPanel(await invoke<Panel>("service_panel"));
  }
  useEffect(() => {
    const read = () => refresh().catch(() => setError("无法读取服务状态"));
    void read();
    const timer = window.setInterval(read, 1500);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!display) return;
    const hide = () => setDisplay(null);
    const timer = window.setTimeout(hide, display.ms);
    window.addEventListener("blur", hide);
    return () => { window.clearTimeout(timer); window.removeEventListener("blur", hide); };
  }, [display]);
  async function act(command: string, args: Record<string, unknown>, label?: string, ms = 30000) {
    setError(""); setBusy(true); setDisplay(null);
    try {
      const value = await invoke<string | null>(command, args);
      if (label && value) setDisplay({ label, value, ms });
      await refresh();
    } catch { setError("操作未完成，请检查主密码、密库路径、端口或申请状态。"); }
    finally { setBusy(false); }
  }
  const open = status && status.scope !== "closed";
  return <main>
    <h1>随身密库</h1>
    {status && <p>开放范围 · <strong>{scopeLabel(status.scope)}</strong> {open && (status.remaining === null ? " · 手动关闭" : " · 剩余 " + Math.ceil(status.remaining / 60) + " 分钟")}</p>}
    {error && <p role="alert">{error}</p>}
    {status && !open && <form onSubmit={e => { const f = takeForm(e); void act("open_service", { path: f.get("path"), password: f.get("password"), minutes: Number(f.get("minutes")) }); }}>
      <label>已有密库的完整路径<input name="path" placeholder="…/我的密库.svault" required /></label>
      {master()}
      <label>自动关闭<select name="minutes"><option value="15">15 分钟</option><option value="60">1 小时</option><option value="480">8 小时</option><option value="0">手动关闭</option></select></label>
      <button disabled={busy}>开启仅本机服务</button>
    </form>}
    {open && <><button onClick={() => void act("close_service", {})}>全部关闭并撤销授权</button>
      <h2>授权申请</h2>
      {!panel?.requests.length && <p>暂无待处理的申请。</p>}
      {panel?.requests.map(r => <article key={r.request_id}>
        <h3>{r.title}</h3><p>客户端 · {r.client}</p><p>AI 提供的理由 · {r.reason}</p>
        {r.state === "pending" ? <form onSubmit={e => {
          const action = ((e.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null)?.value;
          if (action !== "view" && action !== "issue") { e.preventDefault(); return; }
          const f = takeForm(e);
          void act("decide", { id: r.request_id, action, fields: f.getAll("field"), password: f.get("password") }, action === "view" ? "仅在本机查看" : "一次性授权码 · 请自行交给 AI", action === "view" ? 30000 : 120000);
        }}>
          <fieldset><legend>允许的字段</legend>{r.fields.map(field => <label key={field}><input type="checkbox" name="field" value={field} defaultChecked />{fieldNames[field]}</label>)}</fieldset>
          {master()}<p>选择「交给 AI」后，获批明文会进入 AI 服务商的上下文，也可能保存在聊天记录里。</p>
          <ApprovalButtons busy={busy} />{" "}
          <button type="button" onClick={() => void act("decide", { id: r.request_id, action: "deny", fields: [], password: "" })}>拒绝</button>
        </form> : <><p>已出码 · {r.fields.map(f => fieldNames[f]).join("、")}</p><button onClick={() => void act("decide", { id: r.request_id, action: "revoke", fields: [], password: "" })}>撤销授权码</button></>}
      </article>)}
      {display && <aside><strong>{display.label}</strong><pre>{display.value}</pre><button onClick={() => setDisplay(null)}>隐藏</button></aside>}
      <h2>AI 客户端</h2>
      {panel?.clients.map(c => <article key={c.id}><h3>{c.name}</h3><p>可见标签 · {c.tags.join("、") || "所有对 AI 可见的条目"}</p>
        <button onClick={() => void act("client_action", { id: c.id, resume: false, password: "" })}>吊销令牌</button>
        <details><summary>恢复已暂停的搜索</summary><form onSubmit={e => { const f = takeForm(e); void act("client_action", { id: c.id, resume: true, password: f.get("password") }); }}>{master()}<button disabled={busy}>恢复搜索</button></form></details></article>)}
      <form onSubmit={e => { const f = takeForm(e); void act("add_client", { name: f.get("name"), tags: String(f.get("tags")).split(/[,，]/).map(t => t.trim()).filter(Boolean), password: f.get("password") }, "客户端令牌 · 仅此次显示", 120000); }}>
        <label>客户端名称<input name="name" maxLength={80} required /></label>
        <label>可见标签（逗号分隔，留空表示全部）<input name="tags" /></label>
        {master()}<button disabled={busy}>签发客户端令牌</button>
      </form>
      <details><summary>最近 100 条审计记录</summary>
        <form onSubmit={e => { const f = takeForm(e); void act("audit_history", { password: f.get("password"), query: f.get("query") }, "本机审计记录"); }}>
          <label>核对搜索词（留空查看全部）<input name="query" /></label>
          {master()}<button disabled={busy}>查看审计记录</button>
        </form>
      </details></>}
  </main>;
}
