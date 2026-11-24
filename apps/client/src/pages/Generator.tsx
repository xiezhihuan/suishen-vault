import { useCallback, useEffect, useId, useState } from "react";
import { call, type GeneratorOptions } from "../api";
import { useAction } from "../hooks";
import { Card, Check, CopyButton, copyText, ErrorText, Page } from "../ui";

const DEFAULTS: GeneratorOptions = { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true };

/** 随机数由 Rust 侧系统随机源产生。 */
export function GeneratorPanel({ onUse }: { onUse?: (password: string) => void }) {
  const [options, setOptions] = useState(DEFAULTS);
  const [value, setValue] = useState("");
  const { error, run } = useAction();
  const id = useId();
  const make = useCallback(() => run(async () => setValue(await call<string>("generate", { options }))), [options, run]);
  useEffect(() => { void make(); }, [make]);
  const set = (k: keyof GeneratorOptions) => (v: boolean) => setOptions((o) => ({ ...o, [k]: v }));
  return (
    <div>
      <output className="generated" aria-label="生成的密码">{value}</output>
      <div className="field">
        <label htmlFor={id}>长度 · {options.length}</label>
        <input id={id} type="range" min={8} max={64} value={options.length} onChange={(e) => setOptions((o) => ({ ...o, length: Number(e.target.value) }))} />
      </div>
      <div className="checks">
        <Check label="小写字母" checked={options.lowercase} onChange={set("lowercase")} />
        <Check label="大写字母" checked={options.uppercase} onChange={set("uppercase")} />
        <Check label="数字" checked={options.digits} onChange={set("digits")} />
        <Check label="符号" checked={options.symbols} onChange={set("symbols")} />
        <Check label="避开易混字符（0 O 1 l I）" checked={options.avoid_ambiguous} onChange={set("avoid_ambiguous")} />
      </div>
      <ErrorText error={error} />
      <div className="actions">
        {onUse && <button type="button" className="primary" disabled={!value} onClick={() => onUse(value)}>使用这个密码</button>}
        {!onUse && <CopyButton copy={copyText(value)} primary />}
        <button type="button" onClick={() => void make()}>换一个</button>
      </div>
    </div>
  );
}

export function Generator() {
  return (
    <Page title="密码生成" note="在这台设备上用系统随机源生成，不会保存。">
      <Card><GeneratorPanel /></Card>
    </Page>
  );
}
