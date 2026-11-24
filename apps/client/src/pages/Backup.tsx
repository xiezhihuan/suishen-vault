import { useState } from "react";
import { call, type ImportReport } from "../api";
import { stamp, useAction } from "../hooks";
import { Card, Confirm, ErrorText, Page } from "../ui";

export function Backup({ migrating }: { migrating: boolean }) {
  return (
    <Page title="导入与备份">
      <Export />
      <ImportCsv disabled={migrating} />
      <Card title="从备份恢复">
        <p>恢复只能在还没有密库的设备上进行：在新设备打开应用，选「从备份恢复」。</p>
        <p className="muted">应用无法阻止有人手工复制备份文件，在两处同时使用，也不能让已复制出去的旧备份失效。改主密码后，旧备份仍用旧主密码打开。</p>
      </Card>
    </Page>
  );
}

function Export() {
  const [done, setDone] = useState(false);
  const { busy, error, run } = useAction();
  return (
    <Card title="加密备份">
      <p>备份和密库同等加密，只能用主密码或恢复密钥打开。建议存到 U 盘等另一处。</p>
      <ErrorText error={error} />
      {done && <p role="status" className="good-text">已写出备份。</p>}
      <div className="actions"><button className="primary" disabled={busy} onClick={() => {
        setDone(false);
        void run(async () => setDone(await call<boolean>("export_backup", { label: stamp() })));
      }}>{busy ? "正在校验并写出…" : "导出备份…"}</button></div>
    </Card>
  );
}

function ImportCsv({ disabled }: { disabled: boolean }) {
  const [report, setReport] = useState<ImportReport | null>(null);
  const [deleted, setDeleted] = useState(false);
  const [ask, setAsk] = useState(false);
  const { busy, error, run } = useAction();
  return (
    <Card title="从其他密码工具导入">
      <p>支持 Chrome、Bitwarden、KeePass、KeePassXC 导出的 CSV。</p>
      <ErrorText error={error} />
      <div className="actions"><button disabled={busy || disabled} onClick={() => void run(async () => {
        const r = await call<ImportReport | null>("import_csv");
        if (r) { setReport(r); setDeleted(false); }
      })}>{busy ? "正在导入…" : "选择 CSV…"}</button></div>
      {report && (
        <div role="status">
          <p><strong>已从 {report.format} 导入 {report.imported} 条</strong>{report.blank > 0 && `，跳过 ${report.blank} 个空行`}。</p>
          <Rows title="没有导入的行" rows={report.rejected} />
          <Rows title="自动调整的行" rows={report.adjusted} />
          {deleted ? <p className="good-text">已删除 CSV 文件。固态硬盘和网盘可能仍有副本。</p> : <>
            <p className="warn-text">{report.prompt}</p>
            <div className="actions"><button className="danger" onClick={() => setAsk(true)}>删除 {report.file}…</button></div>
          </>}
        </div>
      )}
      {ask && <Confirm title="删除明文 CSV？" confirm="删除文件" danger onCancel={() => setAsk(false)}
        onConfirm={() => { setAsk(false); void run(async () => { await call("delete_csv"); setDeleted(true); }); }}>
        <p>会先核对文件没有变化，再覆写并删除。请确认内容已正确导入。</p>
      </Confirm>}
    </Card>
  );
}

function Rows({ title, rows }: { title: string; rows: [number, string][] }) {
  if (!rows.length) return null;
  return <details><summary>{title}（{rows.length}）</summary><ul>{rows.map(([n, why], i) => <li key={i}>第 {n} 行：{why}</li>)}</ul></details>;
}
