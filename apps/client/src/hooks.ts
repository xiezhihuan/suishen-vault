import { useCallback, useEffect, useRef, useState } from "react";
import { call, toError, type Status, type UiError } from "./api";

/** 每秒取一次状态；窗口重新获得焦点时立刻取。 */
export function useStatus(): { status: Status | null; failed: boolean; refresh: () => Promise<void> } {
  const [status, setStatus] = useState<Status | null>(null);
  const [failed, setFailed] = useState(false);
  const refresh = useCallback(async () => {
    try {
      setStatus(await call<Status>("poll"));
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, []);
  useEffect(() => {
    const read = () => void refresh();
    read();
    const timer = window.setInterval(read, 1000);
    window.addEventListener("focus", read);
    document.addEventListener("visibilitychange", read);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", read);
      document.removeEventListener("visibilitychange", read);
    };
  }, [refresh]);
  return { status, failed, refresh };
}

/** 用户有操作时告诉后端，供闲置锁定计时。最多每 3 秒一次。 */
export function useActivity() {
  useEffect(() => {
    let last = 0;
    const touch = () => {
      const now = Date.now();
      if (now - last < 3000) return;
      last = now;
      call("touch").catch(() => {});
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
    for (const e of events) window.addEventListener(e, touch, { passive: true });
    return () => {
      for (const e of events) window.removeEventListener(e, touch);
    };
  }, []);
}

/** 执行一次操作，记录进行中与失败信息。卸载后不再更新。 */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const run = useCallback(async <T,>(f: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await f();
    } catch (e) {
      if (alive.current) setError(toError(e));
      return undefined;
    } finally {
      if (alive.current) setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** 到时自动清空的值；窗口失去焦点时也清空（可关闭）。 */
export function useTemporary<T>(ms: number, hideOnBlur = true) {
  const [value, setValue] = useState<T | null>(null);
  useEffect(() => {
    if (value === null) return;
    const hide = () => setValue(null);
    const timer = window.setTimeout(hide, ms);
    if (hideOnBlur) window.addEventListener("blur", hide);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("blur", hide);
    };
  }, [value, ms, hideOnBlur]);
  return [value, setValue] as const;
}

export function splitList(text: string): string[] {
  return text.split(/[,，、\n]/).map((t) => t.trim()).filter(Boolean);
}

export function when(ms: number): string {
  return new Date(ms).toLocaleString("zh-CN", { dateStyle: "medium", timeStyle: "short" });
}

/** 文件名用的时间标记，例如 20261123-2031。 */
export function stamp(d = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}
