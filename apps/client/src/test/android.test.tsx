import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { App } from "../App";
import { backend, FAKE, request } from "./backend";

test("Android 密库在服务中重新验证，失败不显示授权码，重试按选中字段出码", async () => {
  const user = userEvent.setup();
  const b = backend({ biometric: () => { throw { code: "biometric", message: "验证已取消" }; } });
  Object.assign(b.state.status, { platform: "android", phase: "serving", scope: "loopback", biometric: true, requests: [request()] });
  render(<App />);
  await user.click(await screen.findByLabelText("用生物识别批准这一次"));
  await user.click(screen.getByLabelText("账号"));
  const issue = screen.getByRole<HTMLButtonElement>("button", { name: /交给 AI/ });
  await waitFor(() => expect(issue.disabled).toBe(false), { timeout: 3500 });
  await user.click(issue);
  await screen.findByText("验证已取消");
  expect(screen.queryByLabelText("授权码内容")).toBeNull();
  b.state.replies.biometric = FAKE.code;
  await user.click(issue);
  expect((await screen.findByLabelText("授权码内容")).textContent).toBe(FAKE.code);
  expect(b.of("biometric")).toEqual(Array(2).fill({ operation: {
    use: "approve", id: "req_1", fields: ["password"], for_ai: true,
  }}));
  expect(b.of("decide")).toHaveLength(0);
  act(() => { window.dispatchEvent(new Event("suishen:background")); });
  await waitFor(() => expect(screen.queryByLabelText("授权码内容")).toBeNull());
});

test("Android 智能粘贴和草稿补录切后台后清空未提交输入", async () => {
  const user = userEvent.setup();
  const b = backend({ list_items: [], draft_inbox: [{ id: "demo", client: "假客户端", created: 1,
    domain: "demo.test", proposal: { type: "login", title: "演示草稿", url: "", tags: [], username: "fake", hint: "" } }] });
  b.state.status.platform = "android";
  render(<App />);
  await user.click(await screen.findByRole("button", { name: "智能粘贴" }));
  fireEvent.change(screen.getByLabelText("粘贴原文"), { target: { value: FAKE.password } });
  act(() => { window.dispatchEvent(new Event("suishen:background")); });
  await user.click(await screen.findByRole("button", { name: "智能粘贴" }));
  expect(screen.getByLabelText<HTMLTextAreaElement>("粘贴原文").value).toBe("");
  await user.click(screen.getByRole("button", { name: "草稿箱" }));
  const field = await screen.findByLabelText<HTMLInputElement>(/密码/);
  fireEvent.change(field, { target: { value: FAKE.password } });
  act(() => { window.dispatchEvent(new Event("suishen:background")); });
  await user.click(await screen.findByRole("button", { name: "草稿箱" }));
  expect((await screen.findByLabelText<HTMLInputElement>(/密码/)).value).toBe("");
  expect(b.of("accept_draft")).toHaveLength(0);
});
