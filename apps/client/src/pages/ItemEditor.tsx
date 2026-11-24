import { useEffect, useId, useState } from "react";
import { call, KINDS, type Detail, type Draft, type Kind, type SecretField } from "../api";
import { splitList, useAction } from "../hooks";
import { Card, Check, ErrorText, TextField } from "../ui";
import { GeneratorPanel } from "./Generator";

/** 编辑已有条目时默认保持原值，不把机密取到界面；`null` 即保持。 */
function SecretInput({ label, value, onChange, load, multiline, rows = 5, children }: {
  label: string; value: string | null; onChange: (v: string | null) => void; load?: () => Promise<string>; multiline?: boolean; rows?: number; children?: React.ReactNode;
}) {
  const id = useId();
  const { busy, error, run } = useAction();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {value === null ? (
        <div className="inline">
          <span id={id} className="filename dots">已保存，不改动</span>
          <button type="button" disabled={busy} onClick={() => void run(async () => onChange(load ? await load() : ""))}>显示并修改</button>
          <button type="button" className="ghost" onClick={() => onChange("")}>重新填写</button>
        </div>
      ) : (
        <div className="inline">
          {multiline ? <textarea id={id} rows={rows} value={value} spellCheck={false} onChange={(e) => onChange(e.target.value)} />
            : <input id={id} type="text" className="mono" value={value} spellCheck={false} autoComplete="off" autoCapitalize="off" autoCorrect="off" onChange={(e) => onChange(e.target.value)} />}
          {children}
          {load && <button type="button" className="ghost" onClick={() => onChange(null)}>不改了</button>}
        </div>
      )}
      <ErrorText error={error} />
    </div>
  );
}

interface Form {
  kind: Kind; title: string; domains: string; tags: string; hint: string; ai_hidden: boolean; auto_domains: boolean;
  username: string | null; password: string | null; note: string | null; totp: string | null; body: string | null; urls: string | null;
  custom: { name: string; value: string }[] | null;
}

const EMPTY: Form = {
  kind: "login", title: "", domains: "", tags: "", hint: "", ai_hidden: false, auto_domains: true,
  username: "", password: "", note: "", totp: "", body: "", urls: "", custom: [],
};

function fromDetail(d: Detail): Form {
  const keep = (on: boolean) => (on ? null : "");
  return {
    kind: d.kind, title: d.title, domains: d.domains.join("，"), tags: d.tags.join("，"), hint: d.hint, ai_hidden: d.ai_hidden, auto_domains: true,
    username: keep(d.has.username), password: keep(d.has.password), note: keep(d.has.note), totp: keep(d.has.totp), body: keep(d.has.body),
    urls: keep(d.has.urls > 0), custom: d.has.custom ? null : [],
  };
}

/** 只交出该类型用得到的字段。 */
export function toDraft(f: Form): Draft {
  const login = f.kind === "login";
  return {
    kind: f.kind, title: f.title, domains: splitList(f.domains), tags: splitList(f.tags), hint: f.hint, ai_hidden: f.ai_hidden,
    // 网址没改就不再自动加域名，免得把用户删掉的加回来
    auto_domains: f.auto_domains && f.urls !== null,
    username: login ? f.username : null, password: login ? f.password : null, note: login ? f.note : null, totp: login ? f.totp : null,
    body: f.kind === "note" ? f.body : null,
    urls: login ? (f.urls === null ? null : f.urls.split("\n").map((s) => s.trim()).filter(Boolean)) : null,
    custom: f.custom === null ? null : f.custom.filter((c) => c.name.trim() || c.value),
  };
}

export function ItemEditor({ id, onSaved, onCancel }: { id: string | null; onSaved: (id: string) => void; onCancel: () => void }) {
  const [form, setForm] = useState<Form | null>(id ? null : EMPTY);
  const [old, setOld] = useState<Detail | null>(null);
  const [generating, setGenerating] = useState(false);
  const { busy, error, run } = useAction();
  useEffect(() => {
    if (!id) return;
    void run(async () => {
      const d = await call<Detail>("get_item", { id });
      setOld(d);
      setForm(fromDetail(d));
    });
  }, [id, run]);
  if (!form) return <ErrorText error={error} />;
  const set = <K extends keyof Form>(k: K) => (v: Form[K]) => setForm((f) => f && { ...f, [k]: v });
  const loader = (field: SecretField, has: boolean | undefined) =>
    id && has ? () => call<string>("reveal_field", { id, field, index: 0 }) : undefined;
  const has = old?.has;
  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      void run(async () => onSaved(await call<string>("save_item", { id, draft: toDraft(form) })));
    }}>
      <button type="button" className="link back" onClick={onCancel}>← 返回</button>
      <h1>{id ? "编辑" : "新增"}</h1>
      {!id && (
        <fieldset className="segmented"><legend>类型</legend>
          {(Object.keys(KINDS) as Kind[]).map((k) => <label key={k}><input type="radio" name="kind" checked={form.kind === k} onChange={() => set("kind")(k)} />{KINDS[k]}</label>)}
        </fieldset>
      )}
      <TextField label="标题" value={form.title} onChange={set("title")} required maxLength={200} placeholder="例如：公司 GitHub" autoFocus={!id} />
      {form.kind === "login" && <>
        <SecretInput label="账号" value={form.username} onChange={set("username")} load={loader("username", has?.username)} />
        <SecretInput label="密码" value={form.password} onChange={set("password")} load={loader("password", has?.password)}>
          <button type="button" onClick={() => setGenerating(!generating)}>生成</button>
        </SecretInput>
        {form.password === null && <button type="button" className="link" onClick={() => setGenerating(!generating)}>换一个新密码…</button>}
        {generating && <Card title="生成密码"><GeneratorPanel onUse={(p) => { set("password")(p); setGenerating(false); }} /></Card>}
        <SecretInput label="网址（每行一个）" value={form.urls} onChange={set("urls")} multiline rows={2}
          load={id && has?.urls ? async () => (await Promise.all(Array.from({ length: has.urls }, (_, index) => call<string>("reveal_field", { id, field: "url", index })))).join("\n") : undefined} />
        <SecretInput label="备注" value={form.note} onChange={set("note")} load={loader("note", has?.note)} multiline />
        <SecretInput label="动态口令密钥（可选，Base32 或 otpauth 链接）" value={form.totp} onChange={set("totp")} load={loader("totp", has?.totp)} />
      </>}
      {form.kind === "note" && <SecretInput label="正文" value={form.body} onChange={set("body")} load={loader("body", has?.body)} multiline />}
      <CustomFields id={id} count={has?.custom ?? 0} value={form.custom} onChange={set("custom")} />

      <Card title="方便以后找到" tone="warn">
        <p><strong>下面这些 AI 也能搜到，不要在里面写密码、账号或其他机密。</strong></p>
        <TextField label="检索提示" value={form.hint} onChange={set("hint")} maxLength={1000} placeholder="例如：报销用的那个系统、老板让注册的" />
        <TextField label="标签（逗号分隔）" value={form.tags} onChange={set("tags")} placeholder="工作，常用" />
        {form.kind !== "note" && <TextField label="域名（逗号分隔）" value={form.domains} onChange={set("domains")} placeholder="example.com" />}
        {form.kind === "login" && form.urls !== null && <Check label="自动从网址取域名" checked={form.auto_domains} onChange={set("auto_domains")} />}
        <Check label="对 AI 不可见" hint="AI 搜不到，也不能申请" checked={form.ai_hidden} onChange={set("ai_hidden")} />
      </Card>
      <ErrorText error={error} />
      <div className="actions sticky">
        <button className="primary big" disabled={busy}>{busy ? "正在保存…" : "保存"}</button>
        <button type="button" onClick={onCancel}>取消</button>
      </div>
    </form>
  );
}

function CustomFields({ id, count, value, onChange }: { id: string | null; count: number; value: Form["custom"]; onChange: (v: Form["custom"]) => void }) {
  const { busy, error, run } = useAction();
  if (value === null) {
    return (
      <div className="field"><span className="label">自定义字段</span>
        <div className="inline"><span className="filename dots">{count} 个，不改动</span>
          <button type="button" disabled={busy} onClick={() => void run(async () => onChange(await Promise.all(Array.from({ length: count }, async (_, index) => ({
            name: await call<string>("reveal_field", { id, field: "custom_name", index }),
            value: await call<string>("reveal_field", { id, field: "custom_value", index }),
          })))))}>显示并修改</button></div>
        <ErrorText error={error} />
      </div>
    );
  }
  const edit = (i: number, part: Partial<{ name: string; value: string }>) => onChange(value.map((c, n) => (n === i ? { ...c, ...part } : c)));
  return (
    <fieldset className="field"><legend>自定义字段</legend>
      {value.map((c, i) => (
        <div className="inline pair" key={i}>
          <input aria-label={`字段 ${i + 1} 名称`} placeholder="名称" value={c.name} autoComplete="off" spellCheck={false} onChange={(e) => edit(i, { name: e.target.value })} />
          <input aria-label={`字段 ${i + 1} 内容`} placeholder="内容" value={c.value} autoComplete="off" spellCheck={false} onChange={(e) => edit(i, { value: e.target.value })} />
          <button type="button" className="ghost" aria-label={`删除字段 ${i + 1}`} onClick={() => onChange(value.filter((_, n) => n !== i))}>删除</button>
        </div>
      ))}
      <button type="button" onClick={() => onChange([...value, { name: "", value: "" }])}>添加字段</button>
    </fieldset>
  );
}
