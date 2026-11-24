import { useState } from "react";
import { call, type RecoveryOut, type Settings as S, type Status } from "../api";
import { useAction } from "../hooks";
import { Card, Check, ErrorText, Page, PasswordField, RecoveryCheck, TextField, takeForm, text } from "../ui";

export function Settings({ status, refresh }: { status: Status; refresh: () => Promise<void> }) {
  return (
    <Page title="设置">
      <General status={status} refresh={refresh} />
      <ChangePassword disabled={status.migrating} />
      <Reissue disabled={status.migrating} />
      <Card title="生物识别">
        <p>没有启用。只有系统能用 Touch ID 或 Windows Hello 真正保护解锁密钥时，才会提供这个选项；当前是未签名的应用，macOS 不允许它使用这种存储。</p>
        <p className="muted">不提供只在界面上判断一下的假保护。请用主密码解锁。</p>
      </Card>
      <Card title="关于">
        <p>随身密库 {status.version}。密库只保存在这台设备：</p>
        <pre>{status.data_dir}</pre>
      </Card>
    </Page>
  );
}

function General({ status, refresh }: { status: Status; refresh: () => Promise<void> }) {
  const [draft, setDraft] = useState<S>(status.settings);
  const [saved, setSaved] = useState(false);
  const { busy, error, run } = useAction();
  const set = (part: Partial<S>) => { setSaved(false); setDraft((d) => ({ ...d, ...part })); };
  const select = (label: string, value: number, options: number[], unit: string, on: (n: number) => void) => (
    <div className="field"><label>{label}
      <select value={value} onChange={(e) => on(Number(e.target.value))}>
        {[...new Set([...options, value])].sort((a, b) => a - b).map((n) => <option key={n} value={n}>{n} {unit}</option>)}
      </select></label></div>
  );
  return (
    <Card title="常规">
      <form onSubmit={(e) => {
        e.preventDefault();
        void run(async () => { await call("set_settings", { settings: draft }); setSaved(true); await refresh(); });
      }}>
        {select("多久没有操作就锁定", draft.auto_lock_minutes, [1, 2, 5, 10, 15, 30, 60], "分钟", (n) => set({ auto_lock_minutes: n }))}
        {select("复制后多久清除剪贴板", draft.clipboard_seconds, [15, 30, 60, 120], "秒", (n) => set({ clipboard_seconds: n }))}
        <TextField label="呼出搜索的全局快捷键" value={draft.shortcut} onChange={(v) => set({ shortcut: v })} maxLength={64}
          hint="例如 CmdOrCtrl+Alt+K。留空则不使用。" mono />
        <TextField label="服务端口" value={String(draft.port)} onChange={(v) => set({ port: Number(v.replace(/\D/g, "").slice(0, 5)) })} mono
          hint={status.scope === "closed" ? undefined : "先关闭服务才能修改。"} />
        <Check label="关闭窗口后留在托盘" hint="关掉后，关窗口即退出并关闭服务" checked={draft.hide_to_tray} onChange={(v) => set({ hide_to_tray: v })} />
        <Check label="有申请时系统通知" hint="通知里不含条目、客户端和理由" checked={draft.notify} onChange={(v) => set({ notify: v })} />
        <p className="muted">系统锁屏或休眠时总会锁定。</p>
        <ErrorText error={error} />
        {saved && <p role="status" className="good-text">已保存。</p>}
        <div className="actions"><button className="primary" disabled={busy}>保存设置</button></div>
      </form>
    </Card>
  );
}

function ChangePassword({ disabled }: { disabled: boolean }) {
  const [done, setDone] = useState(false);
  const { busy, error, setError, run } = useAction();
  return (
    <Card title="修改主密码">
      <form onSubmit={(e) => {
        const f = takeForm(e);
        setDone(false);
        if (text(f, "password") !== text(f, "again")) { setError({ code: "mismatch", message: "两次输入的新密码不一致" }); return; }
        void run(async () => { await call("change_password", { old: text(f, "old"), password: text(f, "password") }); setDone(true); });
      }}>
        <PasswordField label="现在的主密码" name="old" />
        <PasswordField label="新主密码" name="password" hint="至少 10 个字符。之前的备份仍用旧主密码打开。" />
        <PasswordField label="再输一遍新主密码" name="again" />
        <ErrorText error={error} />
        {done && <p role="status" className="good-text">主密码已修改。</p>}
        <div className="actions"><button disabled={busy || disabled}>{busy ? "正在修改…" : "修改主密码"}</button></div>
      </form>
    </Card>
  );
}

function Reissue({ disabled }: { disabled: boolean }) {
  const [data, setData] = useState<RecoveryOut | null>(null);
  const [done, setDone] = useState(false);
  const { busy, error, run } = useAction();
  return (
    <Card title="更换恢复密钥">
      {data ? <RecoveryCheck data={data} command="recovery_confirm" busyText="正在更换…" onDone={() => { setData(null); setDone(true); }}
        onCancel={() => { setData(null); void call("cancel_flow").catch(() => {}); }} /> : (
        <form onSubmit={(e) => {
          const f = takeForm(e);
          setDone(false);
          void run(async () => setData(await call<RecoveryOut>("recovery_reissue", { password: text(f, "password") })));
        }}>
          <p>抄写的恢复密钥丢了或被人看到时，换一把新的。旧的随即失效。</p>
          <PasswordField label="主密码" name="password" />
          <ErrorText error={error} />
          {done && <p role="status" className="good-text">恢复密钥已更换，旧的已失效。</p>}
          <div className="actions"><button disabled={busy || disabled}>{busy ? "正在生成…" : "更换恢复密钥"}</button></div>
        </form>
      )}
    </Card>
  );
}
