import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { call, type UiError } from "./api";

export function Page({ title, note, children, action }: { title: string; note?: ReactNode; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          {note && <p className="muted">{note}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

export function Card({ title, children, tone }: { title?: ReactNode; children: ReactNode; tone?: "warn" | "danger" | "good" }) {
  return (
    <div className={`card ${tone ?? ""}`}>
      {title && <h2>{title}</h2>}
      {children}
    </div>
  );
}

export function ErrorText({ error }: { error: UiError | null }) {
  return error ? <p role="alert" className="error">{error.message}</p> : null;
}

/** 密码框不进 React 状态，提交时读取并立即清空。 */
export function PasswordField({ label, name, hint, autoFocus }: { label: string; name: string; hint?: string; autoFocus?: boolean }) {
  const id = useId();
  const [shown, setShown] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="inline">
        <input id={id} name={name} data-secret="" type={shown ? "text" : "password"} autoComplete="off" autoCapitalize="off"
          autoCorrect="off" spellCheck={false} required autoFocus={autoFocus} />
        <button type="button" className="ghost" aria-label={shown ? "遮住" : "显示输入"} aria-pressed={shown} onClick={() => setShown(!shown)}>
          {shown ? "遮住" : "显示"}
        </button>
      </div>
      {hint && <p className="muted">{hint}</p>}
    </div>
  );
}

export function TextField(props: {
  label: string; name?: string; value?: string; onChange?: (v: string) => void; hint?: ReactNode; placeholder?: string;
  required?: boolean; maxLength?: number; autoFocus?: boolean; mono?: boolean; multiline?: boolean;
}) {
  const id = useId();
  const common = {
    id, name: props.name, placeholder: props.placeholder, required: props.required, maxLength: props.maxLength,
    autoFocus: props.autoFocus, autoComplete: "off", spellCheck: false, autoCapitalize: "off", autoCorrect: "off",
    className: props.mono ? "mono" : undefined,
    ...(props.onChange ? { value: props.value ?? "", onChange: (e: { target: { value: string } }) => props.onChange?.(e.target.value) } : {}),
  };
  return (
    <div className="field">
      <label htmlFor={id}>{props.label}</label>
      {props.multiline ? <textarea rows={5} {...common} /> : <input type="text" {...common} />}
      {props.hint && <p className="muted">{props.hint}</p>}
    </div>
  );
}

export function Check({ label, checked, onChange, hint, disabled }: { label: ReactNode; checked: boolean; onChange: (v: boolean) => void; hint?: string; disabled?: boolean }) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}{hint && <small className="muted">{hint}</small>}</span>
    </label>
  );
}

/** 读取表单并清空其中的密码框。 */
export function takeForm(event: FormEvent<HTMLFormElement>): FormData {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  for (const el of Array.from(form.querySelectorAll<HTMLInputElement>("[data-secret]"))) el.value = "";
  return data;
}

export const text = (f: FormData, k: string) => String(f.get(k) ?? "");

/** 复制后告诉用户多久清除。`copy` 返回秒数。 */
export function CopyButton({ copy, label = "复制", primary }: { copy: () => Promise<number>; label?: string; primary?: boolean }) {
  const [note, setNote] = useState("");
  useEffect(() => {
    if (!note) return;
    const t = window.setTimeout(() => setNote(""), 3000);
    return () => window.clearTimeout(t);
  }, [note]);
  return (
    <button type="button" className={primary ? "primary" : "ghost"} aria-live="polite"
      onClick={() => copy().then((s) => setNote(`已复制，${s} 秒后清除`), () => setNote("复制失败"))}>
      {note || label}
    </button>
  );
}

export const copyText = (value: string) => () => call<number>("copy_text", { text: value });

export function Confirm({ title, children, confirm, danger, onConfirm, onCancel }: {
  title: string; children: ReactNode; confirm: string; danger?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const id = useId();
  const cancel = useRef<HTMLButtonElement>(null);
  const latest = useRef(onCancel);
  latest.current = onCancel;
  // 只在打开时聚焦一次，之后的刷新不抢焦点
  useEffect(() => {
    cancel.current?.focus();
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") latest.current(); };
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, []);
  return (
    <div className="overlay">
      <div role="alertdialog" aria-modal="true" aria-labelledby={id} className="card dialog">
        <h2 id={id}>{title}</h2>
        {children}
        <div className="actions end">
          <button type="button" ref={cancel} onClick={onCancel}>取消</button>
          <button type="button" className={danger ? "danger" : "primary"} onClick={onConfirm}>{confirm}</button>
        </div>
      </div>
    </div>
  );
}

/** 距离某一时刻的剩余秒数。 */
export function useCountdown(until: number): number {
  const left = () => Math.max(0, Math.ceil((until - Date.now()) / 1000));
  const [n, setN] = useState(left);
  useEffect(() => {
    const tick = () => setN(left());
    tick();
    const t = window.setInterval(tick, 250);
    return () => window.clearInterval(t);
  }, [until]);
  return n;
}

/** 恢复密钥抄写与核对。只显示到核对完成。 */
export function RecoveryCheck({ data, command, busyText, onDone, onCancel }: {
  data: { recovery_key: string; challenge: [number, number] }; command: string; busyText: string; onDone: () => void; onCancel: () => void;
}) {
  const [step, setStep] = useState<"write" | "check">("write");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const groups = data.recovery_key.split("-");
  if (step === "write") {
    return (
      <div>
        <p>请用纸笔抄下这 {groups.length} 组字符，和电脑分开放。忘记主密码时，只有它能找回数据。</p>
        <ol className="recovery" aria-label="恢复密钥">
          {groups.map((g, i) => <li key={i}><span>{i + 1}</span><code>{g}</code></li>)}
        </ol>
        <Card tone="warn">
          <p>只显示这一次，不会保存在电脑里。<strong>主密码和恢复密钥都丢失，数据就再也找不回来。</strong></p>
          <p>不要截图、不要发到聊天软件，也不要交给 AI。</p>
        </Card>
        <div className="actions">
          <button type="button" className="primary big" onClick={() => setStep("check")}>我已抄好，去核对</button>
          <button type="button" onClick={onCancel}>取消</button>
        </div>
      </div>
    );
  }
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      setBusy(true);
      setError(null);
      call(command, { answers: [text(f, "a"), text(f, "b")] }).then(onDone, (err: UiError) => { setError(err); setBusy(false); });
    }}>
      <p>对照你抄写的纸，填入下面两组。</p>
      <TextField label={`第 ${data.challenge[0] + 1} 组`} name="a" required maxLength={9} mono autoFocus />
      <TextField label={`第 ${data.challenge[1] + 1} 组`} name="b" required maxLength={9} mono />
      <ErrorText error={error} />
      <div className="actions">
        <button className="primary big" disabled={busy}>{busy ? busyText : "核对并完成"}</button>
        <button type="button" onClick={() => { setError(null); setStep("write"); }}>返回再看一遍</button>
      </div>
    </form>
  );
}
