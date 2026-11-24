import { useEffect, useState } from "react";
import { call, type Status } from "./api";
import { useActivity, useStatus } from "./hooks";
import { Audit } from "./pages/Audit";
import { Backup } from "./pages/Backup";
import { Clients } from "./pages/Clients";
import { Exposure, remainingText, tunnelText } from "./pages/Exposure";
import { Generator } from "./pages/Generator";
import { Items } from "./pages/Items";
import { Migration } from "./pages/Migration";
import { Requests, type Issued } from "./pages/Requests";
import { Settings } from "./pages/Settings";
import { Broken, ImportDone, Locked, Recover, Retired, UnlockForm, Welcome, type Completion } from "./pages/Start";
import { scopeLabel } from "./status";
import { Card } from "./ui";

import { Paste } from "./pages/Paste";
import { Inbox } from "./pages/Inbox";

const PAGES = {
  items: "密库", paste: "智能粘贴", inbox: "草稿箱", requests: "授权申请", clients: "AI 客户端", exposure: "开放范围", audit: "审计记录",
  generator: "密码生成", backup: "导入与备份", migration: "设备迁移", settings: "设置",
} as const;
type PageId = keyof typeof PAGES;

export function App() {
  const { status, failed, refresh } = useStatus();
  useActivity();
  const [page, setPage] = useState<PageId>("items");
  const [focusSeq, setFocusSeq] = useState(0);
  const [issued, setIssued] = useState<Issued[]>([]);
  const [imported, setImported] = useState<Completion | null>(null);
  // 迁移码只显示一次，切换页面不能丢
  const [migrationCode, setMigrationCode] = useState("");

  useEffect(() => {
    const clear = () => { setPage(p => p === "paste" || p === "inbox" ? "items" : p); void refresh(); };
    window.addEventListener("suishen:locked", clear);
    return () => window.removeEventListener("suishen:locked", clear);
  }, [refresh]);
  const nav = status?.nav;
  useEffect(() => {
    if (!nav?.seq) return;
    if (nav.target === "requests") setPage("requests");
    if (nav.target === "search") { setPage("items"); setFocusSeq(nav.seq); }
  }, [nav?.seq, nav?.target]);
  useEffect(() => {
    const on = (e: Event) => setImported((e as CustomEvent<Completion>).detail);
    window.addEventListener("suishen:imported", on);
    return () => window.removeEventListener("suishen:imported", on);
  }, []);
  // 服务关闭后授权码已失效；锁定后回到首页
  useEffect(() => { if (status?.scope === "closed") setIssued([]); }, [status?.scope]);
  useEffect(() => { if (status?.phase === "locked") { setMigrationCode(""); setPage("items"); } }, [status?.phase]);

  if (!status) return <main className="start"><p role="status">{failed ? "无法读取应用状态，请重新启动。" : "正在打开…"}</p></main>;
  if (imported) return <ImportDone done={imported} onClose={() => setImported(null)} />;
  switch (status.phase) {
    case "empty": return <Welcome refresh={refresh} />;
    case "broken": return <Broken error={status.open_error} refresh={refresh} />;
    case "retired": return <Retired refresh={refresh} />;
    case "locked": return <Locked status={status} refresh={refresh} />;
    case "serving": return <Serving status={status} refresh={refresh} issued={issued} setIssued={setIssued} />;
    case "unlocked": break;
  }
  const waiting = status.requests.filter((r) => r.state === "pending").length;
  return (
    <div className="shell">
      <nav aria-label="主导航">
        {(Object.keys(PAGES) as PageId[]).map((id) => (
          <button key={id} className={page === id ? "on" : ""} aria-current={page === id ? "page" : undefined} onClick={() => setPage(id)}>
            {PAGES[id]}{id === "requests" && waiting > 0 && <span className="badge" aria-label={`${waiting} 个待处理`}>{waiting}</span>}
          </button>
        ))}
      </nav>
      <div className="body">
        <TopBar status={status} refresh={refresh} />
        {status.migrating && page !== "migration" && <button className="banner" onClick={() => setPage("migration")}>正在迁移，密库只读。点这里完成或取消。</button>}
        {waiting > 0 && page !== "requests" && <button className="banner urgent" onClick={() => setPage("requests")}>有 {waiting} 个授权申请等你处理</button>}
        <main>
          {page === "paste" && <Paste />}
          {page === "inbox" && <Inbox />}
          {page === "items" && <Items focusSeq={focusSeq} />}
          {page === "requests" && <Requests status={status} refresh={refresh} issued={issued} setIssued={setIssued} />}
          {page === "clients" && <Clients status={status} />}
          {page === "exposure" && <Exposure status={status} refresh={refresh} />}
          {page === "audit" && <Audit />}
          {page === "generator" && <Generator />}
          {page === "backup" && <Backup migrating={status.migrating} />}
          {page === "migration" && <Migration status={status} refresh={refresh} code={migrationCode} setCode={setMigrationCode} />}
          {page === "settings" && <Settings status={status} refresh={refresh} />}
        </main>
      </div>
    </div>
  );
}

/** 始终显示开放范围与剩余时间。AC-NET-08 */
function TopBar({ status, refresh }: { status: Status; refresh: () => Promise<void> }) {
  const open = status.scope !== "closed";
  const act = (command: string) => void call(command).then(refresh, () => {});
  return (
    <header className={`topbar ${status.scope}`}>
      <span className="scope"><i className="dot" aria-hidden="true" />开放范围：<strong>{scopeLabel(status.scope)}</strong> <span className="muted">{remainingText(status)}</span> {status.scope === "public" && <span className="muted">{tunnelText(status)}</span>}</span>
      <span className="row-actions">
        {open && <button className="danger" onClick={() => act("close_service")}>全部关闭</button>}
        {status.phase === "unlocked" && <button onClick={() => act("lock")}>锁定</button>}
      </span>
    </header>
  );
}

/** 界面已锁、服务在运行：只能处理申请，不能浏览密库。AC-VLT-05 */
function Serving({ status, refresh, issued, setIssued }: {
  status: Status; refresh: () => Promise<void>; issued: Issued[]; setIssued: (f: (old: Issued[]) => Issued[]) => void;
}) {
  const [forgot, setForgot] = useState(false);
  return (
    <div className="body solo">
      <TopBar status={status} refresh={refresh} />
      <main>
        <Requests status={status} refresh={refresh} issued={issued} setIssued={setIssued} />
        <section className="page"><Card title="密库已锁定">
          {forgot ? <Recover refresh={refresh} onBack={() => setForgot(false)} /> : <>
            <p className="muted">服务仍在运行，可以在上面处理申请。查看和编辑要先解锁。</p>
            <UnlockForm status={status} refresh={refresh} autoFocus={!status.requests.length} />
            <button className="link" onClick={() => setForgot(true)}>忘了主密码，用恢复密钥重设</button>
          </>}
        </Card></section>
      </main>
    </div>
  );
}
