// 没有密库、已锁定、打不开、已停用时的页面。
import { useEffect, useState, type ReactNode } from "react";
import { call, type RecoveryOut, type Status, type UiError } from "../api";
import { useAction } from "../hooks";
import { Card, Confirm, ErrorText, PasswordField, RecoveryCheck, takeForm, text } from "../ui";

type Refresh = () => Promise<void>;

export function Brand({ children }: { children: ReactNode }) {
  return (
    <main className="start">
      <div className="brand"><svg viewBox="0 0 44 44" aria-hidden="true"><path d="M13 20v-5a9 9 0 0 1 18 0v5" fill="none" stroke="currentColor" strokeWidth="4" /><rect x="8" y="19" width="28" height="21" rx="4" fill="currentColor" /></svg><span>随身密库</span></div>
      {children}
    </main>
  );
}

export function Welcome({ refresh }: { refresh: Refresh }) {
  const [mode, setMode] = useState<"menu" | "new" | "restore" | "migrate">("menu");
  const back = () => { void call("cancel_flow").catch(() => {}); setMode("menu"); };
  return (
    <Brand>
      {mode === "menu" && (
        <>
          <h1>把账号、密码和要记的事存在自己手里</h1>
          <p className="muted">内容只加密保存在这台设备上。同一时间只用一台设备作主设备。</p>
          <div className="choices">
            <button className="choice" onClick={() => setMode("new")}><strong>新建密库</strong><span>第一次使用，设置主密码和恢复密钥</span></button>
            <button className="choice" onClick={() => setMode("migrate")}><strong>从旧设备迁移过来</strong><span>需要迁移包、迁移码，以及主密码或恢复密钥</span></button>
            <button className="choice" onClick={() => setMode("restore")}><strong>从备份恢复</strong><span>旧设备丢失或损坏时使用</span></button>
          </div>
        </>
      )}
      {mode === "new" && <Setup refresh={refresh} onBack={back} />}
      {mode === "restore" && <Restore refresh={refresh} onBack={back} />}
      {mode === "migrate" && <MigrateIn refresh={refresh} onBack={back} />}
    </Brand>
  );
}

function Setup({ refresh, onBack }: { refresh: Refresh; onBack: () => void }) {
  const [data, setData] = useState<RecoveryOut | null>(null);
  const { busy, error, setError, run } = useAction();
  if (data) {
    return (
      <>
        <h1>抄写恢复密钥</h1>
        <RecoveryCheck data={data} command="setup_confirm" busyText="正在创建…" onDone={() => void refresh()} onCancel={onBack} />
      </>
    );
  }
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      if (text(f, "password") !== text(f, "again")) { setError({ code: "mismatch", message: "两次输入不一致，请重新输入" }); return; }
      void run(async () => setData(await call<RecoveryOut>("setup_begin", { password: text(f, "password") })));
    }}>
      <h1>设置主密码</h1>
      <PasswordField label="主密码" name="password" hint="至少 10 个字符。建议用几个不相关的词连起来，容易记又难猜。" autoFocus />
      <PasswordField label="再输一遍" name="again" />
      <ErrorText error={error} />
      <div className="actions">
        <button className="primary big" disabled={busy}>{busy ? "正在生成密钥…" : "下一步"}</button>
        <button type="button" onClick={onBack}>返回</button>
      </div>
    </form>
  );
}

function PickPackage({ kind, label, onPicked, name }: { kind: "backup" | "migration"; label: string; name: string; onPicked: (n: string) => void }) {
  const { busy, error, run } = useAction();
  return (
    <div className="field">
      <span className="label">{label}</span>
      <div className="inline">
        <span className="filename">{name || "还没有选择文件"}</span>
        <button type="button" disabled={busy} onClick={() => void run(async () => {
          const n = await call<string | null>("pick_package", { kind });
          if (n) onPicked(n);
        })}>选择文件…</button>
      </div>
      <ErrorText error={error} />
    </div>
  );
}

function CredentialFields({ kind, setKind }: { kind: "password" | "recovery"; setKind: (k: "password" | "recovery") => void }) {
  return (
    <>
      <fieldset className="segmented"><legend>用什么打开</legend>
        {([["password", "主密码"], ["recovery", "恢复密钥"]] as const).map(([v, l]) => (
          <label key={v}><input type="radio" name="kind" value={v} checked={kind === v} onChange={() => setKind(v)} />{l}</label>
        ))}
      </fieldset>
      <PasswordField key={kind} label={kind === "password" ? "主密码" : "恢复密钥"} name="secret"
        hint={kind === "recovery" ? "之后还要用这把恢复密钥设置新的主密码。" : undefined} />
    </>
  );
}

function Restore({ refresh, onBack }: { refresh: Refresh; onBack: () => void }) {
  const [file, setFile] = useState("");
  const [kind, setKind] = useState<"password" | "recovery">("password");
  const { busy, error, run } = useAction();
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      void run(async () => { await call("restore_backup", { kind, secret: text(f, "secret") }); await refresh(); });
    }}>
      <h1>从备份恢复</h1>
      <Card tone="warn">
        <p>恢复后，原来的设备上可能还有一份能用的密库。请在原设备上停用它，不要两边同时改。应用无法阻止有人手工复制备份文件在别处打开。</p>
      </Card>
      <PickPackage kind="backup" label="备份文件（.svbak）" name={file} onPicked={setFile} />
      <CredentialFields kind={kind} setKind={setKind} />
      <ErrorText error={error} />
      <div className="actions">
        <button className="primary big" disabled={busy || !file}>{busy ? "正在校验并恢复…" : "恢复到这台设备"}</button>
        <button type="button" onClick={onBack}>返回</button>
      </div>
    </form>
  );
}

// 完成码要在刷新后继续显示，所以放在模块外层由 App 保管
export interface Completion { items: number; completion_code: string }

function MigrateIn({ refresh, onBack }: { refresh: Refresh; onBack: () => void }) {
  const [file, setFile] = useState("");
  const [kind, setKind] = useState<"password" | "recovery">("password");
  const { busy, error, run } = useAction();
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      void run(async () => {
        const done = await call<Completion>("migration_import", { code: text(f, "code"), kind, secret: text(f, "secret") });
        window.dispatchEvent(new CustomEvent<Completion>("suishen:imported", { detail: done }));
        await refresh();
      });
    }}>
      <h1>从旧设备迁移过来</h1>
      <p className="muted">先在旧设备的「设备迁移」里生成迁移包，用 U 盘等方式拷到这台设备。</p>
      <PickPackage kind="migration" label="迁移包（.svmig）" name={file} onPicked={setFile} />
      <PasswordField label="迁移码（旧设备上显示的 7 组）" name="code" />
      <CredentialFields kind={kind} setKind={setKind} />
      <ErrorText error={error} />
      <div className="actions">
        <button className="primary big" disabled={busy || !file}>{busy ? "正在逐条校验…" : "导入到这台设备"}</button>
        <button type="button" onClick={onBack}>返回</button>
      </div>
    </form>
  );
}

export function ImportDone({ done, onClose }: { done: Completion; onClose: () => void }) {
  return (
    <Brand>
      <h1>已导入 {done.items} 条，还差最后一步</h1>
      <p>在<strong>旧设备</strong>的「设备迁移」里输入这个完成码，旧设备就会停用：</p>
      <p className="code" aria-label="完成码">{done.completion_code}</p>
      <p className="muted">AI 客户端的令牌不会跟着搬过来，需要在这台设备上重新签发。</p>
      <div className="actions"><button className="primary big" onClick={onClose}>我已在旧设备输入</button></div>
    </Brand>
  );
}

export function UnlockForm({ status, refresh, autoFocus = true }: { status: Status; refresh: Refresh; autoFocus?: boolean }) {
  const { busy, error, run } = useAction();
  const wait = Math.ceil(status.backoff_ms / 1000);
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      void run(async () => { await call("unlock", { password: text(f, "password") }); await refresh(); });
    }}>
      <PasswordField label="主密码" name="password" autoFocus={autoFocus} />
      <ErrorText error={error} />
      {wait > 0 && <p className="muted" role="status">请等待 {wait} 秒再试</p>}
      <div className="actions"><button className="primary big" disabled={busy || wait > 0}>{busy ? "正在验证…" : "解锁"}</button></div>
    </form>
  );
}

export function Locked({ status, refresh }: { status: Status; refresh: Refresh }) {
  const [forgot, setForgot] = useState(false);
  if (forgot) return <Brand><Recover refresh={refresh} onBack={() => setForgot(false)} /></Brand>;
  return (
    <Brand>
      <h1>密库已锁定</h1>
      <UnlockForm status={status} refresh={refresh} />
      <p className="muted">生物识别在这台设备上没有启用，原因见「设置」。</p>
      <button className="link" onClick={() => setForgot(true)}>忘了主密码，用恢复密钥重设</button>
    </Brand>
  );
}

export function Recover({ refresh, onBack }: { refresh: Refresh; onBack: () => void }) {
  const [data, setData] = useState<RecoveryOut | null>(null);
  const { busy, error, setError, run } = useAction();
  const back = () => { void call("cancel_flow").catch(() => {}); onBack(); };
  if (data) {
    return (
      <>
        <h1>抄写新的恢复密钥</h1>
        <p className="muted">核对完成后，旧的主密码和旧的恢复密钥都会失效。</p>
        <RecoveryCheck data={data} command="recovery_confirm" busyText="正在更换…" onDone={() => void refresh()} onCancel={back} />
      </>
    );
  }
  return (
    <form onSubmit={(e) => {
      const f = takeForm(e);
      if (text(f, "password") !== text(f, "again")) { setError({ code: "mismatch", message: "两次输入不一致，请重新输入" }); return; }
      void run(async () => setData(await call<RecoveryOut>("recovery_begin", { key: text(f, "key"), password: text(f, "password") })));
    }}>
      <h1>用恢复密钥重设主密码</h1>
      <PasswordField label="恢复密钥（9 组）" name="key" autoFocus />
      <PasswordField label="新主密码" name="password" hint="至少 10 个字符。" />
      <PasswordField label="再输一遍" name="again" />
      <ErrorText error={error} />
      <div className="actions">
        <button className="primary big" disabled={busy}>{busy ? "正在验证…" : "下一步"}</button>
        <button type="button" onClick={back}>返回</button>
      </div>
    </form>
  );
}

export function Broken({ error: why, refresh }: { error?: UiError; refresh: Refresh }) {
  const [ask, setAsk] = useState(false);
  const { error, run } = useAction();
  return (
    <Brand>
      <h1>密库打不开</h1>
      <p role="alert" className="error">{why?.message ?? "原因不明"}</p>
      {why?.code === "in_use"
        ? <p>请先退出另一个正在使用密库的程序，再重新启动应用。</p>
        : <><p>可以把这个文件改名保留，然后从备份恢复。文件不会被删除。</p>
          <div className="actions"><button onClick={() => setAsk(true)}>改名保留，重新开始…</button></div></>}
      <ErrorText error={error} />
      {ask && <Confirm title="把打不开的密库改名？" confirm="改名保留" onCancel={() => setAsk(false)}
        onConfirm={() => { setAsk(false); void run(async () => { await call("set_aside"); await refresh(); }); }}>
        <p>原文件会留在同一个文件夹里，之后可以新建密库或从备份恢复。</p>
      </Confirm>}
    </Brand>
  );
}

export function Retired({ refresh }: { refresh: Refresh }) {
  const [ask, setAsk] = useState(false);
  const { busy, error, run } = useAction();
  useEffect(() => { void call("cancel_flow").catch(() => {}); }, []);
  return (
    <Brand>
      <h1>这台设备已停用</h1>
      <p>密库已迁移到新设备。请清除这台设备上的密库文件。</p>
      <p className="muted">闪存上无法保证物理擦除，但文件本身是密文。之前复制出去的备份或迁移包不会因此失效。</p>
      <ErrorText error={error} />
      <div className="actions"><button className="danger big" disabled={busy} onClick={() => setAsk(true)}>清除这台设备上的密库…</button></div>
      {ask && <Confirm title="确认清除？" confirm="清除" danger onCancel={() => setAsk(false)}
        onConfirm={() => { setAsk(false); void run(async () => { await call("wipe_retired"); await refresh(); }); }}>
        <p>请先确认新设备能解锁并看到全部内容。清除后这台设备上无法恢复。</p>
      </Confirm>}
    </Brand>
  );
}
