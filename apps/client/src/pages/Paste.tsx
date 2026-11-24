import { useRef, useState } from "react";
import { call, type Draft } from "../api";
import { useAction } from "../hooks";
import { Card, ErrorText, Page } from "../ui";

const labels = {
  title: "标题",
  url: "网址或域名",
  username: "账号",
  password: "密码",
  totp: "TOTP 密钥",
  note: "备注",
};
type Field = keyof typeof labels;
type Span = { entry: number; start: number; end: number; kind: Field | "unknown" | "syntax" };
type Values = Record<Field, string>;
const blank = (): Values => ({ title: "", url: "", username: "", password: "", totp: "", note: "" });
export const makePassword = () =>
  call<string>("generate", {
    options: { length: 24, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true },
  });
function draft(v: Values): Draft {
  return {
    kind: "login",
    domains: [],
    tags: [],
    hint: "",
    ai_hidden: false,
    auto_domains: true,
    title: v.title,
    urls: v.url ? [v.url] : [],
    username: v.username,
    password: v.password,
    totp: v.totp,
    note: v.note,
    custom: [],
    body: null,
  };
}

export function Paste() {
  const [source, setSource] = useState("");
  const [spans, setSpans] = useState<Span[] | null>(null);
  const [rows, setRows] = useState<Values[]>([]);
  const [assigned, setAssigned] = useState<Record<number, Field | "skip">>({});
  const [focus, setFocus] = useState<[number, Field] | null>(null);
  const [show, setShow] = useState(false);
  const pasteVersion = useRef(0);
  const [stamp, setStamp] = useState<string | null>(null);
  const [clear, setClear] = useState(false);
  const [saved, setSaved] = useState(0);
  const { run, error, busy, setError } = useAction();
  const reset = () => {
    pasteVersion.current++;
    setStamp(null);
    setSpans(null);
    setSource("");
    setRows([]);
    setAssigned({});
    setShow(false);
    setClear(false);
    setFocus(null);
    setError(null);
  };
  const parse = () =>
    void run(async () => {
      const parts = await call<Span[]>("parse_paste", { source });
      const entries: Values[] = [];
      for (const p of parts.filter((p) => p.kind !== "syntax")) {
        const v = (entries[p.entry] ??= blank());
        if (p.kind !== "unknown" && p.kind !== "syntax") v[p.kind] = source.slice(p.start, p.end);
      }
      setRows(entries);
      setSpans(parts);
      setSaved(0);
    });
  const update = (i: number, k: Field, value: string) => {
    setError(null);
    setRows((old) => old.map((r, n) => (n === i ? { ...r, [k]: value } : r)));
  };
  const save = () =>
    void run(async () => {
      const n = await call<number>("save_paste", {
        drafts: rows.map(draft),
        allowDuplicates: error?.code === "duplicate",
        clipboard: clear && stamp ? source : null,
        stamp: clear ? stamp : null,
      });
      reset();
      setSaved(n);
    });
  const unknown = spans?.filter((s) => s.kind === "unknown") ?? [];
  return (
    <Page title="智能粘贴" note="在本机识别账号资料，核对后一起保存。">
      {!spans ? (
        <Card>
          {saved > 0 && <p role="status">已新增 {saved} 条记录。</p>}
          <label className="field">
            粘贴原文
            <textarea
              rows={7}
              spellCheck={false}
              autoCorrect="off"
              autoComplete="off"
              disabled={busy}
              value={source}
              onPaste={(e) => {
                const raw = e.clipboardData.getData("text/plain");
                const t = e.currentTarget;
                if (raw && t.selectionStart === 0 && t.selectionEnd === t.value.length) {
                  e.preventDefault();
                  setSource(raw);
                  setSaved(0);
                  setStamp(null);
                  const version = ++pasteVersion.current;
                  void call<string | null>("pasteboard_stamp").then(
                    (mark) => {
                      if (version === pasteVersion.current) setStamp(mark);
                    },
                    () => {},
                  );
                }
              }}
              onChange={(e) => {
                pasteVersion.current++;
                setStamp(null);
                setSource(e.target.value);
                setSaved(0);
              }}
            />
          </label>
          <div className="actions">
            <button className="primary" disabled={!source || busy} onClick={parse}>
              识别并核对
            </button>
            <button
              disabled={busy}
              onClick={() => {
                reset();
                setSaved(0);
              }}
            >
              取消
            </button>
          </div>
        </Card>
      ) : (
        <>
          <label>
            <input type="checkbox" checked={show} onChange={(e) => setShow(e.target.checked)} />
            显示原文中的机密与未识别片段
          </label>
          <div className="paste-columns">
            <Card title="对应原文">
              <pre className="paste-source">
                {spans.map((s) => {
                  const k = assigned[s.start] ?? s.kind;
                  const value =
                    !show && ["unknown", "password", "totp"].some((x) => x === k || x === s.kind)
                      ? "••••••"
                      : source.slice(s.start, s.end);
                  return k === "syntax" ? (
                    value
                  ) : (
                    <mark key={s.start} className={focus?.[0] === s.entry && focus?.[1] === k ? "selected" : ""}>
                      {value}
                    </mark>
                  );
                })}
              </pre>
            </Card>
            <div>
              {rows.map((r, i) => (
                <Card key={i} title={`第 ${i + 1} 条`}>
                  {unknown
                    .filter((s) => s.entry === i)
                    .map((s) => (
                      <div className="field" key={s.start}>
                        <label>
                          未识别片段 · {show ? source.slice(s.start, s.end) : "••••••"}
                          <select
                            aria-label="片段归属"
                            value={assigned[s.start] ?? ""}
                            disabled={!!assigned[s.start]}
                            onChange={(e) => {
                              const field = e.target.value as Field | "skip";
                              if (field !== "skip")
                                update(
                                  i,
                                  field,
                                  r[field]
                                    ? r[field] + "\n" + source.slice(s.start, s.end)
                                    : source.slice(s.start, s.end),
                                );
                              setAssigned((old) => ({ ...old, [s.start]: field }));
                            }}
                          >
                            <option value="" disabled>
                              选择归属
                            </option>
                            {Object.entries(labels).map(([k, l]) => (
                              <option key={k} value={k} disabled={!!r[k as Field] && k !== "note"}>
                                {l}
                              </option>
                            ))}
                            <option value="skip">不保存此段</option>
                          </select>
                        </label>
                      </div>
                    ))}
                  {(Object.keys(labels) as Field[]).map((k) => (
                    <label className="field" key={k}>
                      {labels[k]}
                      {k === "note" ? (
                        <textarea
                          value={r[k]}
                          spellCheck={false}
                          onFocus={() => setFocus([i, k])}
                          onChange={(e) => update(i, k, e.target.value)}
                        />
                      ) : (
                        <input
                          type={!show && (k === "password" || k === "totp") ? "password" : "text"}
                          autoComplete="off"
                          spellCheck={false}
                          value={r[k]}
                          onChange={(e) => update(i, k, e.target.value)}
                          onFocus={() => setFocus([i, k])}
                        />
                      )}
                    </label>
                  ))}
                  <button
                    disabled={busy}
                    onClick={() => void run(async () => update(i, "password", await makePassword()))}
                  >
                    自动生成密码
                  </button>
                </Card>
              ))}
            </div>
          </div>
          {stamp && (
            <label>
              <input type="checkbox" checked={clear} onChange={(e) => setClear(e.target.checked)} />
              保存后清空剪贴板（内容未变时）
            </label>
          )}
          <div className="actions">
            <button
              className="primary"
              disabled={busy || !rows.length || unknown.some((s) => !assigned[s.start])}
              onClick={save}
            >
              {error?.code === "duplicate" ? "仍然新增，不覆盖" : "确认入库"}
            </button>
            <button disabled={busy} onClick={reset}>
              取消
            </button>
          </div>
        </>
      )}
      <ErrorText error={error} />
    </Page>
  );
}
