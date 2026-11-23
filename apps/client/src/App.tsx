import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { type AppStatus, scopeLabel } from "./status";

export function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    invoke<AppStatus>("app_status")
      .then(setStatus)
      // 不展示底层错误文本，避免将来把敏感内容带到界面
      .catch(() => setFailed(true));
  }, []);

  return (
    <main>
      <h1>随身密库</h1>
      <p>骨架版本，尚未实现密库功能。</p>
      {failed && <p role="alert">无法读取应用状态</p>}
      {status && (
        <p>
          版本 {status.version} · 开放范围：{scopeLabel(status.scope)}
        </p>
      )}
    </main>
  );
}
