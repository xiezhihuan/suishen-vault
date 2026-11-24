import { useCallback, useEffect, useRef, useState } from "react";
import { call, KINDS, type Detail, type Meta, type SecretField } from "../api";
import { useAction, useTemporary, when } from "../hooks";
import { Card, Check, Confirm, CopyButton, ErrorText } from "../ui";
import { ItemEditor } from "./ItemEditor";

type View = { mode: "none" } | { mode: "detail"; id: string } | { mode: "edit"; id: string | null };

export function Items({ focusSeq }: { focusSeq: number }) {
  const [query, setQuery] = useState("");
  const [trash, setTrash] = useState(false);
  const [list, setList] = useState<Meta[] | null>(null);
  const [view, setView] = useState<View>({ mode: "none" });
  const [emptying, setEmptying] = useState(false);
  const { error, run } = useAction();
  const box = useRef<HTMLInputElement>(null);
  const latest = useRef(0);

  const load = useCallback(async () => {
    const n = ++latest.current;
    const rows = await call<Meta[]>("list_items", { trash, query });
    // 慢的旧结果不覆盖新结果
    if (n === latest.current) setList(rows);
  }, [trash, query]);
  useEffect(() => {
    const t = window.setTimeout(() => void run(load), 120);
    return () => window.clearTimeout(t);
  }, [load, run]);
  // 全局快捷键呼出：回到搜索框
  useEffect(() => {
    if (!focusSeq) return;
    setTrash(false);
    // 正在编辑时不关掉表单，免得丢掉没保存的内容
    setView((v) => (v.mode === "edit" ? v : { mode: "none" }));
    box.current?.focus();
    box.current?.select();
  }, [focusSeq]);

  const done = (next: View) => { setView(next); void run(load); };
  return (
    <section className={`page items ${view.mode === "none" ? "" : "has-detail"}`}>
      <div className="list-pane">
        <div className="toolbar">
          <input ref={box} type="search" value={query} placeholder="搜索标题、标签、账号…" aria-label="搜索" autoFocus
            spellCheck={false} autoComplete="off" disabled={trash} onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              const first = list?.[0];
              if (e.key === "Enter" && first && !e.nativeEvent.isComposing) setView({ mode: "detail", id: first.id });
              if (e.key === "Escape") setQuery("");
            }} />
          <button className="primary" onClick={() => setView({ mode: "edit", id: null })}>新增</button>
        </div>
        <div className="subbar">
          <button className="link" aria-pressed={trash} onClick={() => { setTrash(!trash); setView({ mode: "none" }); }}>{trash ? "← 返回密库" : "回收站"}</button>
          {list && <span className="muted">{list.length} 条</span>}
          {trash && !!list?.length && <button className="link danger-text" onClick={() => setEmptying(true)}>清空回收站…</button>}
        </div>
        <ErrorText error={error} />
        <ul className="list">
          {list?.map((m) => (
            <li key={m.id}>
              <button className={`row ${view.mode !== "none" && view.id === m.id ? "on" : ""}`} onClick={() => setView({ mode: "detail", id: m.id })}>
                <span className={`kind ${m.kind}`}>{KINDS[m.kind]}</span>
                <span className="row-main"><strong>{m.title}</strong>
                  <small>{[m.domains[0], m.masked_account, m.tags.join(" ")].filter(Boolean).join(" · ") || when(m.updated_ms)}</small></span>
                {m.ai_hidden && <span className="tag">AI 不可见</span>}
              </button>
            </li>
          ))}
        </ul>
        {list?.length === 0 && <p className="empty">{trash ? "回收站是空的。" : query ? "没有找到。换个说法，或用标签、网址试试。" : "还没有内容。点「新增」存第一条，或从浏览器导入。"}</p>}
      </div>
      {view.mode !== "none" && (
        <div className="detail-pane">
          {view.mode === "detail"
            ? <ItemDetail key={view.id} id={view.id} onEdit={() => setView({ mode: "edit", id: view.id })} onClose={() => setView({ mode: "none" })} onChanged={(gone) => done(gone ? { mode: "none" } : view)} />
            : <ItemEditor key={view.id ?? "new"} id={view.id} onSaved={(id) => done({ mode: "detail", id })} onCancel={() => setView(view.id ? { mode: "detail", id: view.id } : { mode: "none" })} />}
        </div>
      )}
      {emptying && <Confirm title="清空回收站？" confirm="永久删除" danger onCancel={() => setEmptying(false)}
        onConfirm={() => { setEmptying(false); setView({ mode: "none" }); void run(async () => { await call("empty_trash"); await load(); }); }}>
        <p>其中的内容会永久删除，无法找回。</p>
      </Confirm>}
    </section>
  );
}

/** 默认遮住，点开后 30 秒或失去焦点时遮回。复制不经过界面。AC-VLT-09 */
export function SecretRow({ id, label, field, index = 0, multiline, copyable = true }: { id: string; label: string; field: SecretField; index?: number; multiline?: boolean; copyable?: boolean }) {
  const [value, setValue] = useTemporary<string>(30_000);
  const { busy, error, run } = useAction();
  const args = { id, field, index };
  return (
    <div className="secret-row">
      <span className="label">{label}</span>
      {value === null ? <span className="value dots" aria-label="已遮住">••••••••</span>
        : <code className={`value ${multiline ? "block" : ""}`}>{value}</code>}
      <span className="row-actions">
        <button className="ghost" disabled={busy} onClick={() => value === null
          ? void run(async () => setValue(await call<string>("reveal_field", args))) : setValue(null)}>{value === null ? "显示" : "遮住"}</button>
        {copyable && <CopyButton copy={() => call<number>("copy_field", args)} />}
      </span>
      <ErrorText error={error} />
    </div>
  );
}

function Totp({ id }: { id: string }) {
  const [on, setOn] = useTemporary<true>(60_000);
  const [code, setCode] = useState<{ code: string; remaining: number } | null>(null);
  useEffect(() => {
    if (!on) { setCode(null); return; }
    const read = () => call<{ code: string; remaining: number }>("totp_code", { id }).then(setCode, () => setOn(null));
    void read();
    const t = window.setInterval(read, 1000);
    return () => window.clearInterval(t);
  }, [on, id, setOn]);
  return (
    <div className="secret-row">
      <span className="label">动态口令</span>
      <code className="value">{code ? `${code.code}（${code.remaining} 秒）` : "••••••"}</code>
      <span className="row-actions">
        <button className="ghost" onClick={() => setOn(on ? null : true)}>{on ? "遮住" : "显示"}</button>
        {code && <CopyButton copy={() => call<number>("copy_text", { text: code.code })} />}
      </span>
    </div>
  );
}

function ItemDetail({ id, onEdit, onClose, onChanged }: { id: string; onEdit: () => void; onClose: () => void; onChanged: (gone: boolean) => void }) {
  const [item, setItem] = useState<Detail | null>(null);
  const [ask, setAsk] = useState<"trash" | "purge" | null>(null);
  const { busy, error, run } = useAction();
  const load = useCallback(async () => setItem(await call<Detail>("get_item", { id })), [id]);
  useEffect(() => { void run(load); }, [load, run]);
  const act = (action: string, gone: boolean) => void run(async () => {
    await call("item_action", { id, action });
    if (!gone) await load();
    onChanged(gone);
  });
  if (!item) return <><ErrorText error={error} /><button className="link back" onClick={onClose}>← 返回列表</button></>;
  const trashed = item.deleted_ms !== null;
  const { has } = item;
  return (
    <article aria-label={item.title}>
      <button className="link back" onClick={onClose}>← 返回列表</button>
      <header className="detail-head">
        <div><p className="eyebrow">{KINDS[item.kind]}{item.domains.length > 0 && ` · ${item.domains.join("、")}`}</p><h1>{item.title}</h1></div>
        {!trashed && <button onClick={onEdit}>编辑</button>}
      </header>
      <ErrorText error={error} />
      <Card>
        {has.username && <SecretRow id={id} label="账号" field="username" />}
        {has.password && <SecretRow id={id} label="密码" field="password" />}
        {has.totp && !trashed && <Totp id={id} />}
        {Array.from({ length: has.urls }, (_, i) => <SecretRow key={i} id={id} label={has.urls > 1 ? `网址 ${i + 1}` : "网址"} field="url" index={i} />)}
        {has.body && <SecretRow id={id} label="正文" field="body" multiline />}
        {has.note && <SecretRow id={id} label="备注" field="note" multiline />}
        {Array.from({ length: has.custom }, (_, i) => <CustomRow key={i} id={id} index={i} />)}
      </Card>
      <Card title="AI 能搜到的信息">
        {item.ai_hidden ? <p>AI 搜不到这一条。</p> : <p className="muted">标题、域名、标签、检索提示和打码账号。账号全文、密码、正文搜不到。</p>}
        <dl className="facts small">
          <div><dt>标签</dt><dd>{item.tags.join("、") || "无"}</dd></div>
          <div><dt>检索提示</dt><dd>{item.hint || "无"}</dd></div>
          {item.masked_account && <div><dt>打码账号</dt><dd>{item.masked_account}</dd></div>}
        </dl>
        {!trashed && <Check label="对 AI 不可见" hint="打开后，已有的申请和授权码立即失效" checked={item.ai_hidden} disabled={busy} onChange={(v) => act(v ? "hide_from_ai" : "show_to_ai", false)} />}
      </Card>
      <p className="muted">修改于 {when(item.updated_ms)}，创建于 {when(item.created_ms)}</p>
      <div className="actions">
        {trashed ? <>
          <button className="primary" disabled={busy} onClick={() => act("restore", true)}>还原</button>
          <button className="danger" disabled={busy} onClick={() => setAsk("purge")}>永久删除…</button>
        </> : <button className="danger" disabled={busy} onClick={() => setAsk("trash")}>移入回收站…</button>}
      </div>
      {ask && <Confirm title={ask === "trash" ? "移入回收站？" : "永久删除？"} confirm={ask === "trash" ? "移入回收站" : "永久删除"} danger
        onCancel={() => setAsk(null)} onConfirm={() => { const a = ask; setAsk(null); act(a, true); }}>
        <p>{ask === "trash" ? "30 天内可以从回收站还原。" : "删除后无法找回。"}</p>
      </Confirm>}
    </article>
  );
}

/** 自定义字段的名称也是机密，点开才取。 */
function CustomRow({ id, index }: { id: string; index: number }) {
  const [name, setName] = useTemporary<string>(30_000);
  const { error, run } = useAction();
  return (
    <>
      {name === null
        ? <div className="secret-row"><span className="label">自定义字段 {index + 1}</span><span className="value dots">••••••••</span>
          <span className="row-actions"><button className="ghost" onClick={() => void run(async () => setName(await call<string>("reveal_field", { id, field: "custom_name", index })))}>显示名称</button>
            <CopyButton copy={() => call<number>("copy_field", { id, field: "custom_value", index })} label="复制内容" /></span></div>
        : <SecretRow id={id} label={name || `自定义字段 ${index + 1}`} field="custom_value" index={index} multiline />}
      <ErrorText error={error} />
    </>
  );
}
