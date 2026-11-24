import { useEffect, useState } from "react";
import { call, KINDS, type Kind } from "../api";
import { useAction, when } from "../hooks";
import { Card, ErrorText, Page } from "../ui";
import { makePassword } from "./Paste";

interface Row {
  id: string;
  client: string;
  created: number;
  domain: string | null;
  proposal: { type: Kind; title: string; url: string | null; tags: string[]; hint: string; username: string | null };
}
export function Inbox() {
  const [rows, setRows] = useState<Row[]>([]);
  const { busy, error, run } = useAction();
  const load = async () => setRows(await call<Row[]>("draft_inbox"));
  useEffect(() => {
    void run(load);
  }, [run]);
  useEffect(() => {
    if (!rows.length) return;
    const expiry = Math.min(...rows.map((row) => row.created + 86400000));
    const timer = window.setTimeout(
      () => {
        setRows((old) => old.filter((row) => row.created + 86400000 > Date.now()));
      },
      Math.max(0, expiry - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [rows]);
  return (
    <Page title="草稿箱" note="这是 AI 写的，请核对网址。只有确认后才会成为密库条目。">
      <div className="actions">
        <button disabled={busy} onClick={() => void run(load)}>
          刷新草稿箱
        </button>
        {!!rows.length && (
          <button
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await call("reject_drafts", { id: null });
                await load();
              })
            }
          >
            全部拒绝
          </button>
        )}
      </div>
      {!rows.length && (
        <Card>
          <p>没有待核对的草稿。</p>
        </Card>
      )}
      {rows.map((row) => (
        <Entry key={row.id} row={row} reload={load} />
      ))}
      <ErrorText error={error} />
    </Page>
  );
}
function Entry({ row, reload }: { row: Row; reload: () => Promise<void> }) {
  const [secret, setSecret] = useState("");
  const { busy, error, run } = useAction();
  const p = row.proposal;
  return (
    <Card title={p.title} tone="warn">
      <p>
        {row.client} · {when(row.created)} · {KINDS[p.type]}
      </p>
      {row.domain && (
        <>
          <strong className="full-domain" dir="ltr">
            {row.domain}
          </strong>
          {row.domain.split(".").some((x) => x.startsWith("xn--")) && <p>国际化域名，以上是完整的 Punycode 域名。</p>}
        </>
      )}
      <dl className="draft-data">
        {[
          ["网址", p.url],
          ["账号", p.username],
          ["标签", p.tags.join("、")],
          ["检索提示", p.hint],
        ].map(
          ([label, value]) =>
            value && (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ),
        )}
      </dl>
      <label className="field">
        {p.type === "login" ? "补充密码" : "补充内容"}
        <input type="password" value={secret} autoComplete="off" onChange={(e) => setSecret(e.target.value)} />
      </label>
      <div className="actions">
        {p.type === "login" && (
          <button disabled={busy} onClick={() => void run(async () => setSecret(await makePassword()))}>
            自动生成密码
          </button>
        )}
        <button
          disabled={busy || !secret}
          className="primary"
          onClick={() =>
            void run(async () => {
              await call("accept_draft", { id: row.id, secret });
              setSecret("");
              await reload();
            })
          }
        >
          确认入库
        </button>
        <button
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await call("reject_drafts", { id: row.id });
              setSecret("");
              await reload();
            })
          }
        >
          拒绝草稿
        </button>
      </div>
      <ErrorText error={error} />
    </Card>
  );
}
