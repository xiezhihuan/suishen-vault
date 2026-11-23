import { expect, test } from "vitest";
import { scopeLabel } from "./status";

test("开放范围使用中文名称", () => {
  expect(scopeLabel("closed")).toBe("关闭");
  expect(scopeLabel("loopback")).toBe("仅本机");
  expect(scopeLabel("lan")).toBe("局域网");
  expect(scopeLabel("public")).toBe("公网");
});
