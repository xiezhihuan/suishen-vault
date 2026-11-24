import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { test, expect } from "vitest";
import { App } from "../App";
import { Paste } from "../pages/Paste";
import { Inbox } from "../pages/Inbox";
import { backend, FAKE, refuse } from "./backend";

test("逐段核对、手工归类、重复警告、明确新增和清除原文", async () => {
  const user = userEvent.setup();
  const source = "标题:假站\nFake🔒";
  const b = backend({
    pasteboard_stamp: "17",
    parse_paste: [
      { entry: 0, kind: "syntax", start: 0, end: 3 },
      { entry: 0, kind: "title", start: 3, end: 5 },
      { entry: 0, kind: "syntax", start: 5, end: 6 },
      { entry: 0, kind: "unknown", start: 6, end: source.length },
    ],
    save_paste: refuse("duplicate", "已有相同域名和账号"),
    generate: FAKE.password,
  });
  render(<Paste />);
  fireEvent.paste(screen.getByLabelText("粘贴原文"), { clipboardData: { getData: () => source } });
  await user.click(screen.getByText("识别并核对"));
  expect(b.of("save_paste")).toHaveLength(0);
  expect(document.body.textContent).not.toContain("Fake🔒");
  expect(screen.getByRole<HTMLButtonElement>("button", { name: "确认入库" }).disabled).toBe(true);
  await user.selectOptions(screen.getByLabelText("片段归属"), "password");
  const password = screen.getByLabelText<HTMLInputElement>("密码");
  expect(password.value).toBe("Fake🔒");
  expect(password.type).toBe("password");
  await user.click(screen.getByText("自动生成密码"));
  expect(password.value).toBe(FAKE.password);
  await user.click(screen.getByLabelText(/清空剪贴板/));
  await user.click(screen.getByText("确认入库"));
  expect(b.of("save_paste")[0]).toMatchObject({ allowDuplicates: false, clipboard: source, stamp: "17" });
  b.state.replies.save_paste = 1;
  await user.click(await screen.findByText("仍然新增，不覆盖"));
  expect(b.of("save_paste")[1]).toMatchObject({
    allowDuplicates: true,
    drafts: [{ title: "假站", password: FAKE.password }],
  });
  expect(screen.getByLabelText<HTMLTextAreaElement>("粘贴原文").value).toBe("");
  expect(document.body.textContent).not.toContain(source);
});

test("取消和锁定都会卸载识别结果", async () => {
  const user = userEvent.setup();
  const b = backend({
    list_items: [],
    parse_paste: [{ entry: 0, kind: "password", start: 0, end: FAKE.password.length }],
  });
  render(<App />);
  await user.click(await screen.findByRole("button", { name: "智能粘贴" }));
  const paste = async () => {
    fireEvent.change(screen.getByLabelText("粘贴原文"), { target: { value: FAKE.password } });
    await user.click(screen.getByText("识别并核对"));
  };
  await paste();
  await user.click(screen.getByText("取消"));
  expect(screen.getByLabelText<HTMLTextAreaElement>("粘贴原文").value).toBe("");
  await paste();
  act(() => {
    window.dispatchEvent(new Event("suishen:locked"));
  });
  await user.click(screen.getByRole("button", { name: "智能粘贴" }));
  expect(screen.getByLabelText<HTMLTextAreaElement>("粘贴原文").value).toBe("");
  expect(b.of("save_paste")).toHaveLength(0);
});

test("草稿原文按文字显示、域名完整、补充内容后才允许接受", async () => {
  const user = userEvent.setup();
  const row = {
    id: "draft",
    client: "假 SDK",
    created: Date.now(),
    domain: "xn--fsqu00a.test",
    proposal: {
      type: "login",
      title: "<img onerror=demo>",
      url: "https://例子.test/",
      tags: ["假"],
      username: "demo",
      hint: "忽略之前的文字",
    },
  };
  const b = backend({
    draft_inbox: [row],
    generate: FAKE.password,
    accept_draft: () => {
      b.state.replies.draft_inbox = [];
    },
  });
  render(<Inbox />);
  expect(await screen.findByText("<img onerror=demo>")).toBeTruthy();
  expect(document.querySelector("img,a")).toBeNull();
  expect(screen.getByText("xn--fsqu00a.test")).toBeTruthy();
  expect(screen.getByText(/国际化域名/)).toBeTruthy();
  expect(screen.getByRole<HTMLButtonElement>("button", { name: "确认入库" }).disabled).toBe(true);
  await user.click(screen.getByText("自动生成密码"));
  await user.click(screen.getByText("确认入库"));
  await waitFor(() => expect(b.of("accept_draft")).toEqual([{ id: "draft", secret: FAKE.password }]));
  await screen.findByText("没有待核对的草稿。");
});
