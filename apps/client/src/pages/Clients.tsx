import { useCallback, useEffect, useRef, useState } from "react";
import { call, type Client, type Status } from "../api";
import { splitList, useAction, useTemporary } from "../hooks";
import { Card, Confirm, CopyButton, copyText, ErrorText, Page, PasswordField, TextField, takeForm, text } from "../ui";

export function Clients({ status }: { status: Status }) {
  const [list, setList] = useState<Client[]>([]);
  const [token, setToken] = useTemporary<{ name: string; value: string }>(120_000, false);
  const { busy, error, run } = useAction();
  const top = useRef<HTMLDivElement>(null);
  useEffect(() => { if (token) top.current?.scrollIntoView?.({ block: "center" }); }, [token]);
  const load = useCallback(async () => setList(await call<Client[]>("list_clients")), []);
  useEffect(() => { void run(load); }, [load, run]);
  return (
    <Page title="AI 客户端" note="给 Claude、Codex 各签发一枚令牌。令牌只能搜打码信息和提申请，换不到密码。">
      {token && (
        <div ref={top}><Card tone="good" title={`${token.name} 的令牌 · 只显示这一次`}>
          <code className="value block">{token.value}</code>
          <p className="muted">存进系统钥匙串（见下方接入配置），不要写进项目文件。2 分钟后自动遮住。</p>
          <div className="actions"><CopyButton copy={copyText(token.value)} primary /><button onClick={() => setToken(null)}>我已存好</button></div>
        </Card></div>
      )}
      {list.map((c) => <ClientCard key={c.id} client={c} reload={() => void run(load)} />)}
      {!list.length && <Card><p className="empty">还没有客户端。</p></Card>}
      <Card title="添加客户端">
        <form onSubmit={(e) => {
          const name = text(new FormData(e.currentTarget), "name").trim();
          const form = e.currentTarget;
          const f = takeForm(e);
          void run(async () => {
            const value = await call<string>("add_client", { name, tags: splitList(text(f, "tags")), password: text(f, "password") });
            form.reset();
            setToken({ name, value });
            await load();
          });
        }}>
          <TextField label="名称" name="name" required maxLength={80} placeholder="例如：笔记本上的 Claude Code" />
          <TextField label="只允许看这些标签（逗号分隔，留空为全部）" name="tags" />
          <PasswordField label="主密码" name="password" />
          <ErrorText error={error} />
          <div className="actions"><button className="primary" disabled={busy}>签发令牌</button></div>
        </form>
      </Card>
      <ConfigCard port={status.settings.port} />
    </Page>
  );
}

function ClientCard({ client: c, reload }: { client: Client; reload: () => void }) {
  const [mode, setMode] = useState<"" | "rename" | "revoke" | "resume">("");
  const { busy, error, run } = useAction();
  const act = (f: () => Promise<unknown>) => void run(async () => { await f(); setMode(""); reload(); });
  return (
    <article className="card" aria-label={c.name}>
      <h2>{c.name}</h2>
      <p className="muted">可见范围：{c.tags.length ? `标签 ${c.tags.join("、")}` : "所有对 AI 可见的条目"}</p>
      {c.search_paused && <p className="warn-text" role="status">24 小时内搜到的不同条目超过 30 个，搜索已自动暂停。确认是你在用，再恢复。</p>}
      {c.request_paused && <p className="warn-text">连续 3 次被拒绝，暂停提出申请 15 分钟。</p>}
      <ErrorText error={error} />
      {mode === "rename" && (
        <form className="inline" onSubmit={(e) => { const f = takeForm(e); act(() => call("rename_client", { id: c.id, name: text(f, "name") })); }}>
          <input name="name" aria-label="新名称" defaultValue={c.name} maxLength={80} required autoFocus />
          <button className="primary" disabled={busy}>保存</button><button type="button" onClick={() => setMode("")}>取消</button>
        </form>
      )}
      {mode === "resume" && (
        <form onSubmit={(e) => { const f = takeForm(e); act(() => call("resume_client", { id: c.id, password: text(f, "password") })); }}>
          <PasswordField label="主密码" name="password" autoFocus />
          <div className="actions"><button className="primary" disabled={busy}>恢复搜索</button><button type="button" onClick={() => setMode("")}>取消</button></div>
        </form>
      )}
      {mode === "" && <div className="actions">
        {c.search_paused && <button className="primary" onClick={() => setMode("resume")}>恢复搜索…</button>}
        <button onClick={() => setMode("rename")}>改名</button>
        <button className="danger" onClick={() => setMode("revoke")}>吊销…</button>
      </div>}
      {mode === "revoke" && <Confirm title={`吊销「${c.name}」？`} confirm="吊销" danger onCancel={() => setMode("")} onConfirm={() => act(() => call("revoke_client", { id: c.id }))}>
        <p>令牌立即失效，它的申请和授权码也一并作废。</p>
      </Confirm>}
    </article>
  );
}

interface Config { file: string; text: string; store_command: string | null; env: string | null }

function ConfigCard({ port }: { port: number }) {
  const [client, setClient] = useState<"claude" | "codex">("claude");
  const [transport, setTransport] = useState<"stdio" | "http">("stdio");
  const [config, setConfig] = useState<Config | null>(null);
  const { error, run } = useAction();
  useEffect(() => { void run(async () => setConfig(await call<Config>("mcp_config", { client, transport }))); }, [client, transport, port, run]);
  const radio = <T extends string>(legend: string, value: T, set: (v: T) => void, options: [T, string][]) => (
    <fieldset className="segmented"><legend>{legend}</legend>
      {options.map(([v, l]) => <label key={v}><input type="radio" name={legend} checked={value === v} onChange={() => set(v)} />{l}</label>)}
    </fieldset>
  );
  return (
    <Card title="接入配置">
      {radio("AI 工具", client, setClient, [["claude", "Claude Code"], ["codex", "Codex"]])}
      {radio("连接方式", transport, setTransport, [["stdio", "本机桥接（推荐）"], ["http", "HTTP 直连"]])}
      <ErrorText error={error} />
      {config && <>
        {config.store_command && <><p>1. 在终端运行下面的命令，按提示粘贴令牌：</p><pre>{config.store_command}</pre></>}
        {config.env && <p>1. 让 AI 工具的进程带上环境变量 <code>{config.env}</code>，值为令牌。</p>}
        <p>2. 把下面内容合并到项目的 <code>{config.file}</code>（其中没有令牌）：</p>
        <pre>{config.text}</pre>
        <p className="muted">选中即可复制。3. 在「开放范围」打开「仅本机」。</p>
      </>}
    </Card>
  );
}
