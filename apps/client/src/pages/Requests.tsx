import { useEffect, useRef, useState } from "react";
import { call, FIELDS, KINDS, type AiField, type Request, type Status } from "../api";
import { useAction, useTemporary } from "../hooks";
import { Card, CopyButton, copyText, ErrorText, Page, PasswordField, useCountdown } from "../ui";

/** 已出码的申请。码只在这里，到期或被取用后立即去掉。 */
export interface Issued { id: string; title: string; client: string; code: string; until: number }
interface Viewed { title: string; rows: { label: string; value: string }[] }

const OUTCOME: Record<string, string> = {
  redeemed: "AI 已凭授权码取走，授权码已失效。", code_expired: "授权码已过期，AI 没有取走。", locked: "授权码输错 5 次，已作废。",
  revoked: "授权已撤销。", denied: "已拒绝。", expired: "申请已过期。", view_only: "仅在本机查看。",
};

export function Requests({ status, refresh, issued, setIssued }: {
  status: Status; refresh: () => Promise<void>; issued: Issued[]; setIssued: (f: (old: Issued[]) => Issued[]) => void;
}) {
  const [viewed, setViewed] = useTemporary<Viewed>(30_000);
  const pending = status.requests.filter((r) => r.state === "pending");
  // 出码后重新打开窗口时没有码可看，但仍可撤销
  const orphan = status.requests.filter((r) => r.state === "code_issued" && !issued.some((i) => i.id === r.request_id));
  return (
    <Page title="授权申请" note="AI 想看某一条时会出现在这里。每次批准都要重新输入主密码。">
      {issued.map((i) => <CodePanel key={i.id} item={i} onClose={() => setIssued((all) => all.filter((x) => x.id !== i.id))} />)}
      {viewed && <ViewPanel data={viewed} onClose={() => setViewed(null)} />}
      {pending.map((r) => (
        <Approval key={r.request_id} request={r} refresh={refresh}
          onCode={(code) => setIssued((all) => [...all, { id: r.request_id, title: r.title, client: r.client, code, until: Date.now() + 120_000 }])}
          onView={(rows) => setViewed({ title: r.title, rows })} />
      ))}
      {orphan.map((r) => <Orphan key={r.request_id} request={r} refresh={refresh} />)}
      {!pending.length && !orphan.length && !issued.length && !viewed && (
        <Card><p className="empty">{status.scope === "closed" ? "服务已关闭，AI 无法提出申请。" : "暂时没有申请。"}</p></Card>
      )}
    </Page>
  );
}

export function Approval({ request: r, refresh, onCode, onView }: {
  request: Request; refresh: () => Promise<void>; onCode: (code: string) => void; onView: (rows: Viewed["rows"]) => void;
}) {
  const [ready, setReady] = useState(false);
  const [fields, setFields] = useState<AiField[]>(r.fields);
  const { busy, error, setError, run } = useAction();
  const password = useRef<HTMLDivElement>(null);
  const deny = useRef<HTMLButtonElement>(null);
  // AC-GRT-17：默认焦点在拒绝，2 秒内不能批准
  useEffect(() => {
    // 不滚动，先让用户看到是谁、要什么
    deny.current?.focus({ preventScroll: true });
    const t = window.setTimeout(() => setReady(true), 2000);
    return () => window.clearTimeout(t);
  }, []);
  const decide = (action: "view" | "issue" | "deny") => {
    const input = password.current?.querySelector("input");
    const pw = action === "deny" ? "" : input?.value ?? "";
    if (input) input.value = "";
    if (action !== "deny" && !pw) { setError({ code: "empty", message: "请先输入主密码" }); input?.focus(); return; }
    if (action !== "deny" && !fields.length) { setError({ code: "fields", message: "请至少勾选一个字段" }); return; }
    void run(async () => {
      const out = await call<string | null>("decide", { id: r.request_id, action, fields: action === "deny" ? [] : fields, password: pw });
      if (action === "issue" && out) onCode(out);
      if (action === "view" && out) onView(parseView(out));
      await refresh();
    });
  };
  return (
    <article className="card approval" aria-label={`${r.client} 的申请`}>
      <p className="eyebrow">等待你处理 · {Math.floor(r.expires_in_seconds / 60)} 分 {r.expires_in_seconds % 60} 秒后过期</p>
      <dl className="facts">
        <div><dt>谁在申请</dt><dd className="strong">{r.client}<small>这是你给客户端起的名字</small></dd></div>
        <div><dt>想看哪一条</dt><dd className="strong">{r.title}<small>{[KINDS[r.type], r.domain, r.masked_account].filter(Boolean).join(" · ")}</small></dd></div>
        <div><dt>理由</dt><dd><q>{r.reason}</q><small>由 AI 填写，未核实</small></dd></div>
      </dl>
      <form onSubmit={(e) => e.preventDefault()}>
        <fieldset><legend>允许的字段</legend>
          <div className="checks">
          {r.fields.map((f) => (
            <label key={f} className="check">
              <input type="checkbox" checked={fields.includes(f)}
                onChange={(e) => setFields((all) => (e.target.checked ? r.fields.filter((x) => x === f || all.includes(x)) : all.filter((x) => x !== f)))} />
              <span>{FIELDS[f]}</span>
            </label>
          ))}
          </div>
        </fieldset>
        <div ref={password}><PasswordField label="主密码（批准时需要）" name="password" /></div>
        <ErrorText error={error} />
        <p className="warn-text">选「交给 AI」后，勾选字段的明文会进入 AI 服务商的上下文，也可能留在聊天记录里。</p>
        {r.access === "direct" && <p className="warn-text">这个客户端允许公网直连：如果它正走直连，跳板那台服务器也能看到授权码和交出的明文。</p>}
        <div className="decision">
          <button type="button" ref={deny} className="danger huge" disabled={busy} onClick={() => decide("deny")}>拒绝</button>
          <button type="button" className="huge" disabled={busy || !ready} onClick={() => decide("view")}>
            仅在本机查看<small>AI 得不到明文</small>
          </button>
          <button type="button" className="primary huge" disabled={busy || !ready} onClick={() => decide("issue")}>
            交给 AI<small>生成一次性授权码</small>
          </button>
        </div>
      </form>
    </article>
  );
}

export function parseView(json: string): Viewed["rows"] {
  try {
    const data = JSON.parse(json) as { fields: { name: AiField; value: string | { name: string; value: string }[] }[] };
    return data.fields.flatMap((f) =>
      typeof f.value === "string" ? [{ label: FIELDS[f.name], value: f.value }] : f.value.map((p) => ({ label: p.name, value: p.value })));
  } catch {
    return [];
  }
}

function ViewPanel({ data, onClose }: { data: Viewed; onClose: () => void }) {
  return (
    <Card tone="good" title={`${data.title} · 仅在本机查看`}>
      {data.rows.length ? data.rows.map((r, i) => (
        <div className="secret-row" key={i}><span className="label">{r.label}</span><code className="value">{r.value}</code><CopyButton copy={copyText(r.value)} /></div>
      )) : <p>这一条没有所选字段的内容。</p>}
      <p className="muted">30 秒后或切换窗口时自动遮住。AI 没有得到内容。</p>
      <div className="actions"><button onClick={onClose}>现在遮住</button></div>
    </Card>
  );
}

export function CodePanel({ item, onClose }: { item: Issued; onClose: () => void }) {
  const left = useCountdown(item.until);
  const [state, setState] = useState("code_issued");
  const { busy, error, run } = useAction();
  useEffect(() => {
    const read = () => call<string | null>("request_state", { id: item.id }).then((s) => setState(s ?? "revoked"), () => setState("revoked"));
    const t = window.setInterval(read, 1000);
    return () => window.clearInterval(t);
  }, [item.id]);
  const live = state === "code_issued" && left > 0;
  if (!live) {
    return (
      <Card title={item.title} tone={state === "redeemed" ? "good" : undefined}>
        <p role="status">{OUTCOME[state === "code_issued" ? "code_expired" : state] ?? "授权已结束。"}</p>
        <div className="actions"><button onClick={onClose}>知道了</button></div>
      </Card>
    );
  }
  return (
    <article className="card code-panel" aria-label="授权码">
      <p>把这个授权码告诉 <strong>{item.client}</strong>，它就能取走「{item.title}」一次：</p>
      <p className="code" aria-label="授权码内容">{item.code}</p>
      <progress max={120} value={left} aria-hidden="true" />
      <p className={left <= 20 ? "warn-text" : "muted"} role="timer">还有 <strong>{left}</strong> 秒失效 · 只能用一次 · 输错 5 次作废</p>
      <ErrorText error={error} />
      <div className="actions">
        <CopyButton copy={copyText(item.code)} label="复制授权码" primary />
        <button className="danger" disabled={busy} onClick={() => void run(async () => {
          await call("decide", { id: item.id, action: "revoke", fields: [], password: "" });
          setState("revoked");
        })}>撤销</button>
      </div>
    </article>
  );
}

function Orphan({ request: r, refresh }: { request: Request; refresh: () => Promise<void> }) {
  const { busy, error, run } = useAction();
  return (
    <Card title={r.title}>
      <p>已给 {r.client} 出过授权码，还有 {r.expires_in_seconds} 秒失效。授权码只显示一次，忘记了可撤销后让 AI 重新申请。</p>
      <ErrorText error={error} />
      <div className="actions"><button className="danger" disabled={busy} onClick={() => void run(async () => {
        await call("decide", { id: r.request_id, action: "revoke", fields: [], password: "" });
        await refresh();
      })}>撤销</button></div>
    </Card>
  );
}
