import { useState } from "react";
import { call, type Status } from "../api";
import { stamp, useAction } from "../hooks";
import { Card, Confirm, ErrorText, Page, PasswordField, takeForm, text } from "../ui";

export function Migration({ status, refresh, code, setCode }: { status: Status; refresh: () => Promise<void>; code: string; setCode: (c: string) => void }) {
  return (
    <Page title="设备迁移" note="同一时间只用一台主设备。换设备时把整个密库搬过去，这台随后停用。">
      {status.migrating ? <InProgress refresh={refresh} code={code} setCode={setCode} /> : <Begin refresh={refresh} setCode={setCode} />}
      <Card title="做不到的事">
        <p>没有中心服务器，应用无法阻止有人手工复制备份、迁移包（连同迁移码）或密库文件到另一台设备同时使用，也无法让已复制出去的副本失效。</p>
      </Card>
    </Page>
  );
}

function Begin({ refresh, setCode }: { refresh: () => Promise<void>; setCode: (c: string) => void }) {
  const { busy, error, run } = useAction();
  return (
    <Card title="迁移到新设备">
      <ol className="steps">
        <li>在这里生成迁移包，抄下迁移码。生成后这台变成只读，服务关闭，所有申请失效。</li>
        <li>用 U 盘等方式把迁移包拷到新设备，在新设备上选「从旧设备迁移过来」。</li>
        <li>新设备会显示完成码，回到这里输入，这台就停用。</li>
      </ol>
      <form onSubmit={(e) => {
        const f = takeForm(e);
        void run(async () => {
          const c = await call<string | null>("migration_begin", { password: text(f, "password"), label: stamp() });
          if (c) setCode(c);
          await refresh();
        });
      }}>
        <PasswordField label="主密码" name="password" />
        <ErrorText error={error} />
        <div className="actions"><button className="primary" disabled={busy}>{busy ? "正在生成…" : "生成迁移包…"}</button></div>
      </form>
    </Card>
  );
}

function InProgress({ refresh, code, setCode }: { refresh: () => Promise<void>; code: string; setCode: (c: string) => void }) {
  const [ask, setAsk] = useState<"" | "cancel">("");
  const { busy, error, run } = useAction();
  return (
    <>
      {code && (
        <Card tone="good" title="迁移码 · 只显示这一次">
          <p className="code small">{code}</p>
          <p className="muted">抄在纸上，不要和迁移包放在一起传。丢了就取消迁移，重新生成。</p>
          <div className="actions"><button onClick={() => setCode("")}>我已抄好</button></div>
        </Card>
      )}
      <Card title="等待新设备" tone="warn">
        <p>这台设备目前只读。新设备导入成功后会显示 8 位完成码，在这里输入：</p>
        <form onSubmit={(e) => { const f = takeForm(e); void run(async () => { await call("migration_confirm", { completion: text(f, "completion") }); setCode(""); await refresh(); }); }}>
          <PasswordField label="完成码" name="completion" />
          <ErrorText error={error} />
          <div className="actions">
            <button className="danger" disabled={busy}>确认并停用这台设备</button>
            <button type="button" disabled={busy} onClick={() => setAsk("cancel")}>取消迁移…</button>
          </div>
        </form>
      </Card>
      {ask === "cancel" && <Confirm title="取消迁移？" confirm="取消迁移，恢复使用" danger onCancel={() => setAsk("")}
        onConfirm={() => { setAsk(""); void run(async () => { await call("migration_cancel"); setCode(""); await refresh(); }); }}>
        <p>如果新设备其实已经导入成功，就会出现两份都能用的密库。请先确认新设备没有导入，并删掉迁移包。</p>
      </Confirm>}
    </>
  );
}
