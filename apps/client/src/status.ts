/** 与 Rust 侧 `ExposureScope` 的序列化名称一一对应。 */
export type ExposureScope = "closed" | "loopback" | "lan" | "public";

export interface AppStatus {
  version: string;
  scope: ExposureScope;
}

const LABELS: Record<ExposureScope, string> = {
  closed: "关闭",
  loopback: "仅本机",
  lan: "局域网",
  public: "公网",
};

export function scopeLabel(scope: ExposureScope): string {
  return LABELS[scope];
}
