import { call, type Status } from "../api";
import { stamp, useAction } from "../hooks";
import { ErrorText } from "../ui";

export function DocumentPicker({ status, kind }: { status: Status; kind: string }) {
  const { busy, error, run } = useAction();
  if (status.platform !== "android") return null;
  const picked = status.documents?.includes(kind);
  return <div className="field">
    <button type="button" disabled={busy} onClick={() => void run(() => call("select_document", { kind, label: stamp() }))}>
      {picked ? "重新选择文件…" : kind === "csv" ? "选择 CSV 文件…" : "选择保存位置…"}
    </button>
    <p className="muted">{picked ? "已选好文件，可继续。" : "从系统文件选择器返回后，请解锁并回到本页继续。"}</p>
    <ErrorText error={error} />
  </div>;
}
