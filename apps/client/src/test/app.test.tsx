import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, test, vi } from "vitest";
import { App } from "../App";
import { describe as describeAudit } from "../pages/Audit";
import { toDraft } from "../pages/ItemEditor";
import { Approval, CodePanel, parseView } from "../pages/Requests";
import { FAKE, backend, detail, meta, refuse, request, status } from "./backend";

afterEach(() => vi.useRealTimers());
const html = () => document.body.innerHTML;

describe("首次设置与解锁", () => {
  test("主密码两次不一致时不提交；核对恢复密钥后才完成（AC-VLT-01）", async () => {
    const user = userEvent.setup();
    const key = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ";
    let tries = 0;
    const b = backend({
      setup_begin: { recovery_key: key, challenge: [1, 8] },
      setup_confirm: () => {
        tries += 1;
        if (tries === 1) throw { code: "recovery_mismatch", message: "核对不一致，请对照抄写的恢复密钥" };
        b.state.status = status();
        return null;
      },
      list_items: [],
    });
    b.state.status = status({ phase: "empty" });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /新建密库/ }));
    await user.type(screen.getByLabelText("主密码"), FAKE.master);
    await user.type(screen.getByLabelText("再输一遍"), "不一样的内容123");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("不一致");
    expect(b.of("setup_begin")).toHaveLength(0);

    await user.type(screen.getByLabelText("主密码"), FAKE.master);
    await user.type(screen.getByLabelText("再输一遍"), FAKE.master);
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect((await screen.findAllByRole("listitem")).map((l) => l.textContent?.slice(1))).toEqual(key.split("-"));
    // 核对时不再显示恢复密钥
    await user.click(screen.getByRole("button", { name: "我已抄好，去核对" }));
    expect(html()).not.toContain("BBBB");
    await user.type(screen.getByLabelText("第 2 组"), "XXXX");
    await user.type(screen.getByLabelText("第 9 组"), "JJJJ");
    await user.click(screen.getByRole("button", { name: "核对并完成" }));
    expect((await screen.findByRole("alert")).textContent).toContain("核对不一致");
    await user.clear(screen.getByLabelText("第 2 组"));
    await user.type(screen.getByLabelText("第 2 组"), "BBBB");
    await user.click(screen.getByRole("button", { name: "核对并完成" }));
    await screen.findByRole("navigation", { name: "主导航" });
    expect(b.of("setup_confirm").at(-1)).toEqual({ answers: ["BBBB", "JJJJ"] });
  });

  test("解锁失败显示原因，密码框随即清空", async () => {
    const user = userEvent.setup();
    const b = backend({ unlock: refuse("unlock_failed", "验证失败，请检查输入是否正确") });
    b.state.status = status({ phase: "locked" });
    render(<App />);
    const box = await screen.findByLabelText<HTMLInputElement>("主密码");
    await user.type(box, "fake-wrong-000");
    // 显示输入后提交，也要清空
    await user.click(screen.getByRole("button", { name: "显示输入" }));
    await user.click(screen.getByRole("button", { name: "解锁" }));
    expect((await screen.findByRole("alert")).textContent).toContain("验证失败");
    expect(box.value).toBe("");
  });

  test("连续失败时要等待", async () => {
    const b = backend({});
    b.state.status = status({ phase: "locked", backoff_ms: 4200 });
    render(<App />);
    expect(await screen.findByText(/请等待 5 秒/)).toBeTruthy();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "解锁" }).disabled).toBe(true);
  });

  test.each([
    ["retired", "这台设备已停用"],
    ["broken", "密库打不开"],
  ] as const)("%s 状态有明确说明", async (phase, text) => {
    backend({}).state.status = status({ phase, open_error: { code: "tampered", message: "文件已损坏或被改动" } });
    render(<App />);
    expect(await screen.findByRole("heading", { name: text })).toBeTruthy();
  });
});

describe("密库", () => {
  test("机密默认遮住，点开才取回，失去焦点就遮回（AC-VLT-09）", async () => {
    const user = userEvent.setup();
    const b = backend({ list_items: [meta], get_item: detail, reveal_field: FAKE.password, copy_field: 30 });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /公司邮箱/ }));
    const row = (await screen.findByText("密码", { selector: ".label" })).closest<HTMLElement>(".secret-row")!;
    expect(b.of("reveal_field")).toHaveLength(0);
    expect(html()).not.toContain(FAKE.password);
    await user.click(within(row).getByRole("button", { name: "显示" }));
    await within(row).findByText(FAKE.password);
    act(() => { window.dispatchEvent(new Event("blur")); });
    expect(html()).not.toContain(FAKE.password);
    // 复制不取回明文
    await user.click(within(row).getByRole("button", { name: "复制" }));
    await within(row).findByText(/30 秒后清除/);
    expect(b.of("copy_field")).toEqual([{ id: "a1", field: "password", index: 0 }]);
    expect(b.of("reveal_field")).toHaveLength(1);
  });

  test("显示 30 秒后自动遮回", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    backend({ list_items: [meta], get_item: detail, reveal_field: FAKE.password });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /公司邮箱/ }));
    const row = (await screen.findByText("密码", { selector: ".label" })).closest<HTMLElement>(".secret-row")!;
    await user.click(within(row).getByRole("button", { name: "显示" }));
    await within(row).findByText(FAKE.password);
    await act(() => vi.advanceTimersByTimeAsync(29_000));
    expect(html()).toContain(FAKE.password);
    await act(() => vi.advanceTimersByTimeAsync(1_500));
    expect(html()).not.toContain(FAKE.password);
  });

  test("锁定后界面上不留任何内容（AC-VLT-05）", async () => {
    const user = userEvent.setup();
    const b = backend({ list_items: [meta], get_item: detail, reveal_field: FAKE.password, lock: () => { b.state.status = status({ phase: "locked" }); return null; } });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /公司邮箱/ }));
    const row = (await screen.findByText("密码", { selector: ".label" })).closest<HTMLElement>(".secret-row")!;
    await user.click(within(row).getByRole("button", { name: "显示" }));
    await within(row).findByText(FAKE.password);
    await user.click(screen.getByRole("button", { name: "锁定" }));
    await screen.findByRole("heading", { name: "密库已锁定" });
    expect(html()).not.toContain(FAKE.password);
    expect(html()).not.toContain("公司邮箱");
  });

  test("编辑时默认保持原有机密，不取回也不清空", async () => {
    const user = userEvent.setup();
    const b = backend({ list_items: [meta], get_item: detail, save_item: "a1" });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /公司邮箱/ }));
    await user.click(await screen.findByRole("button", { name: "编辑" }));
    const title = await screen.findByLabelText("标题");
    await user.clear(title);
    await user.type(title, "新标题");
    expect(screen.getByText(/不要在里面写密码/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(b.of("save_item")).toHaveLength(1));
    expect(b.of("reveal_field")).toHaveLength(0);
    const { draft } = b.of("save_item")[0] as { draft: Record<string, unknown> };
    expect(draft).toMatchObject({ title: "新标题", username: null, password: null, urls: null, note: "", auto_domains: false, tags: ["工作"] });
  });

  test("新增条目可用生成的密码", async () => {
    const user = userEvent.setup();
    const b = backend({ list_items: [], generate: FAKE.password, save_item: "a1", get_item: detail });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "新增" }));
    await user.type(screen.getByLabelText("标题"), "甲");
    await user.click(screen.getByRole("button", { name: "生成" }));
    await user.click(await screen.findByRole("button", { name: "使用这个密码" }));
    await user.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(b.of("save_item")[0]).toMatchObject({ id: null, draft: { kind: "login", password: FAKE.password } }));
  });

  test("只提交该类型用得到的字段", () => {
    const form = {
      kind: "note" as const, title: "甲", domains: "", tags: "a，b", hint: "", ai_hidden: false, auto_domains: true,
      username: "u", password: "p", note: "n", totp: "t", body: "正文", urls: "x", custom: [{ name: "", value: "" }],
    };
    expect(toDraft(form)).toMatchObject({ username: null, password: null, note: null, totp: null, urls: null, body: "正文", tags: ["a", "b"], custom: [] });
  });

  test("快捷键呼出搜索时聚焦搜索框", async () => {
    const b = backend({ list_items: [], list_clients: [] });
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "密码生成" }));
    b.state.status = status({ nav: { seq: 1, target: "search" } });
    act(() => { window.dispatchEvent(new Event("focus")); });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("searchbox")));
  });
});

describe("授权申请", () => {
  const setup = (replies: Record<string, unknown> = {}) => {
    const b = backend({ list_items: [], ...replies });
    b.state.status = status({ phase: "serving", scope: "loopback", remaining: 600, requests: [request()] });
    return b;
  };

  test("显示客户端、条目、字段、理由，并注明理由未核实、明文去向（AC-GRT-03 AC-GRT-06）", async () => {
    setup();
    render(<App />);
    const card = await screen.findByRole("article");
    for (const t of ["笔记本上的 Claude", "公司邮箱", "要登录测试站", "由 AI 填写，未核实", /example\.test/]) expect(within(card).getByText(t)).toBeTruthy();
    expect(within(card).getAllByRole<HTMLInputElement>("checkbox").every((c) => c.checked)).toBe(true);
    expect(card.textContent).toContain("明文会进入 AI 服务商的上下文");
  });

  test("默认焦点在拒绝，2 秒内不能批准（AC-GRT-17）", async () => {
    vi.useFakeTimers();
    backend({});
    render(<Approval request={request()} refresh={async () => {}} onCode={() => {}} onView={() => {}} />);
    const button = (name: RegExp) => screen.getByRole<HTMLButtonElement>("button", { name });
    expect(document.activeElement).toBe(button(/^拒绝/));
    expect([button(/仅在本机查看/).disabled, button(/交给 AI/).disabled, button(/^拒绝/).disabled]).toEqual([true, true, false]);
    act(() => { vi.advanceTimersByTime(1_900); });
    expect(button(/交给 AI/).disabled).toBe(true);
    act(() => { vi.advanceTimersByTime(200); });
    expect([button(/仅在本机查看/).disabled, button(/交给 AI/).disabled]).toEqual([false, false]);
  });

  test("没有主密码不能批准，按回车也不会批准（AC-GRT-04）", async () => {
    const user = userEvent.setup();
    const b = setup();
    render(<App />);
    const issue = await screen.findByRole<HTMLButtonElement>("button", { name: /交给 AI/ });
    await waitFor(() => expect(issue.disabled).toBe(false), { timeout: 3000 });
    await user.click(issue);
    expect(screen.getByRole("alert").textContent).toContain("请先输入主密码");
    await user.type(screen.getByLabelText("主密码（批准时需要）"), `${FAKE.master}{Enter}`);
    expect(b.of("decide")).toHaveLength(0);
  });

  test("去掉字段后只交付剩下的；授权码只出现在界面上并有倒计时（AC-GRT-13）", async () => {
    const user = userEvent.setup();
    const b = setup({ decide: FAKE.code, request_state: "code_issued" });
    render(<App />);
    const issue = await screen.findByRole<HTMLButtonElement>("button", { name: /交给 AI/ });
    await waitFor(() => expect(issue.disabled).toBe(false), { timeout: 3000 });
    await user.click(screen.getByRole("checkbox", { name: "账号" }));
    await user.type(screen.getByLabelText("主密码（批准时需要）"), FAKE.master);
    b.state.status = { ...b.state.status, requests: [request({ state: "code_issued", fields: ["password"] })] };
    await user.click(issue);
    await screen.findByText(FAKE.code);
    expect(b.of("decide")).toEqual([{ id: "req_1", action: "issue", fields: ["password"], password: FAKE.master }]);
    expect(screen.getByRole("timer").textContent).toMatch(/1(20|19|18) 秒失效/);
    expect(html()).not.toContain(FAKE.master);
    // 切换窗口时授权码仍在，用户要拿去交给 AI
    act(() => { window.dispatchEvent(new Event("blur")); });
    expect(screen.getByText(FAKE.code)).toBeTruthy();
  });

  test("拒绝不需要主密码", async () => {
    const user = userEvent.setup();
    const b = setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "拒绝" }));
    await waitFor(() => expect(b.of("decide")).toEqual([{ id: "req_1", action: "deny", fields: [], password: "" }]));
  });

  test("仅在本机查看：显示明文，失去焦点就遮住，不产生授权码（AC-GRT-05）", async () => {
    const user = userEvent.setup();
    const b = setup({ decide: JSON.stringify({ fields: [{ name: "password", value: FAKE.password }] }) });
    render(<App />);
    const view = await screen.findByRole<HTMLButtonElement>("button", { name: /仅在本机查看/ });
    await waitFor(() => expect(view.disabled).toBe(false), { timeout: 3000 });
    await user.type(screen.getByLabelText("主密码（批准时需要）"), FAKE.master);
    b.state.status = { ...b.state.status, requests: [] };
    await user.click(view);
    await screen.findByText(FAKE.password);
    expect(b.of("decide")[0]).toMatchObject({ action: "view" });
    expect(screen.queryByLabelText("授权码")).toBeNull();
    act(() => { window.dispatchEvent(new Event("blur")); });
    expect(html()).not.toContain(FAKE.password);
  });

  test.each([["redeemed", "已凭授权码取走"], ["locked", "输错 5 次"], ["revoked", "已撤销"]])("授权码 %s 后立即从界面消失", async (state, text) => {
    vi.useFakeTimers();
    backend({ request_state: state });
    render(<CodePanel item={{ id: "req_1", title: "甲", client: "乙", code: FAKE.code, until: Date.now() + 120_000 }} onClose={() => {}} />);
    expect(html()).toContain(FAKE.code);
    await act(() => vi.advanceTimersByTimeAsync(1_100));
    expect(html()).not.toContain(FAKE.code);
    expect(screen.getByRole("status").textContent).toContain(text);
  });

  test("到 120 秒授权码消失", async () => {
    vi.useFakeTimers();
    backend({ request_state: "code_issued" });
    render(<CodePanel item={{ id: "req_1", title: "甲", client: "乙", code: FAKE.code, until: Date.now() + 120_000 }} onClose={() => {}} />);
    await act(() => vi.advanceTimersByTimeAsync(119_000));
    expect(html()).toContain(FAKE.code);
    await act(() => vi.advanceTimersByTimeAsync(1_300));
    expect(html()).not.toContain(FAKE.code);
    expect(screen.getByRole("status").textContent).toContain("已过期");
  });

  test("界面锁定时只能处理申请，不能浏览（AC-VLT-05）", async () => {
    const b = setup();
    render(<App />);
    await screen.findByRole("article");
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(b.of("list_items")).toHaveLength(0);
  });

  test("一键关闭后授权码立即从界面消失（AC-NET-04）", async () => {
    const user = userEvent.setup();
    const b = setup({ decide: FAKE.code, request_state: "code_issued", close_service: () => { b.state.status = status(); return null; } });
    render(<App />);
    const issue = await screen.findByRole<HTMLButtonElement>("button", { name: /交给 AI/ });
    await waitFor(() => expect(issue.disabled).toBe(false), { timeout: 3000 });
    await user.type(screen.getByLabelText("主密码（批准时需要）"), FAKE.master);
    b.state.status = { ...b.state.status, requests: [request({ state: "code_issued" })] };
    await user.click(issue);
    await screen.findByText(FAKE.code);
    await user.click(screen.getByRole("button", { name: "全部关闭" }));
    await waitFor(() => expect(html()).not.toContain(FAKE.code));
  });

  test("AI 的理由按纯文本显示", async () => {
    const b = setup();
    b.state.status.requests = [request({ reason: "<img src=x onerror=alert(1)>" })];
    render(<App />);
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  test("自定义字段逐项展开，坏数据不崩溃", () => {
    expect(parseView('{"fields":[{"name":"custom","value":[{"name":"甲","value":"1"}]},{"name":"note","value":"2"}]}'))
      .toEqual([{ label: "甲", value: "1" }, { label: "备注", value: "2" }]);
    expect(parseView("x")).toEqual([]);
  });
});

describe("开放范围、客户端、审计、设置", () => {
  const go = async (name: RegExp | string) => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(within(await screen.findByRole("navigation")).getByRole("button", { name }));
    return user;
  };

  test("默认关闭；未实现的范围不能点；开启时带上自动关闭时间", async () => {
    const b = backend({ list_items: [], open_service: () => { b.state.status = status({ scope: "loopback", remaining: 900 }); return null; } });
    const user = await go("开放范围");
    const choice = (name: RegExp) => screen.getByRole<HTMLButtonElement>("button", { name });
    expect(choice(/^关闭/).getAttribute("aria-pressed")).toBe("true");
    expect([choice(/^局域网/).disabled, choice(/^公网/).disabled]).toEqual([true, true]);
    await user.click(screen.getByRole("radio", { name: "15 分钟" }));
    await user.click(choice(/^仅本机/));
    await screen.findByRole("button", { name: "全部关闭并撤销授权" });
    expect(b.of("open_service")).toEqual([{ minutes: 15 }]);
    expect(document.querySelector(".topbar")?.textContent).toContain("剩余 15 分钟");
  });

  test("签发的令牌只显示一次", async () => {
    const token = "f".repeat(64);
    const b = backend({ list_items: [], list_clients: [], add_client: token, mcp_config: { file: ".mcp.json", text: "{}", store_command: "x", env: null } });
    const user = await go("AI 客户端");
    await user.type(screen.getByLabelText("名称"), "笔记本");
    await user.type(screen.getByLabelText(/只允许看这些标签/), "工作，常用");
    await user.type(screen.getByLabelText("主密码"), FAKE.master);
    await user.click(screen.getByRole("button", { name: "签发令牌" }));
    await screen.findByText(token);
    expect(b.of("add_client")).toEqual([{ name: "笔记本", tags: ["工作", "常用"], password: FAKE.master }]);
    await user.click(screen.getByRole("button", { name: "我已存好" }));
    expect(html()).not.toContain(token);
  });

  test("搜索被暂停时提醒并可恢复（AC-SRC-08）", async () => {
    const b = backend({ list_items: [], list_clients: [{ id: "c1", name: "甲", tags: [], search_paused: true, request_paused: false }], mcp_config: null });
    const user = await go("AI 客户端");
    expect((await screen.findByRole("status")).textContent).toContain("自动暂停");
    await user.click(screen.getByRole("button", { name: "恢复搜索…" }));
    const card = screen.getByRole("article", { name: "甲" });
    await user.type(within(card).getByLabelText("主密码"), FAKE.master);
    await user.click(within(card).getByRole("button", { name: "恢复搜索" }));
    await waitFor(() => expect(b.of("resume_client")).toEqual([{ id: "c1", password: FAKE.master }]));
  });

  test("吊销要先确认，默认焦点在取消", async () => {
    const b = backend({ list_items: [], list_clients: [{ id: "c1", name: "甲", tags: [], search_paused: false, request_paused: false }], mcp_config: null });
    const user = await go("AI 客户端");
    await user.click(await screen.findByRole("button", { name: "吊销…" }));
    const dialog = screen.getByRole("alertdialog");
    expect(document.activeElement?.textContent).toBe("取消");
    expect(b.of("revoke_client")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "吊销" }));
    await waitFor(() => expect(b.of("revoke_client")).toEqual([{ id: "c1" }]));
  });

  test("审计把编号换成标题", () => {
    const data = { events: [], clients: [], titles: { x: "公司邮箱" } };
    const e = (subject: unknown) => ({ time_ms: 0, client: "", action: "search", subject, result: "ok" });
    expect(describeAudit(e({ matches: ["x", "y"] }), data)).toBe("命中 公司邮箱、已删除的条目");
    expect(describeAudit(e({ item: "x", fields: ["password"] }), data)).toBe("公司邮箱 · 密码");
    expect(describeAudit(e("req_1"), data)).toBe("");
  });

  test("设置失败时说明原因", async () => {
    const b = backend({ list_items: [], set_settings: refuse("shortcut", "快捷键已被其他程序占用，请换一个") });
    const user = await go("设置");
    await user.selectOptions(screen.getByLabelText(/没有操作就锁定/), "10");
    await user.click(screen.getByRole("button", { name: "保存设置" }));
    expect((await screen.findByRole("alert")).textContent).toContain("已被其他程序占用");
    expect(b.of("set_settings")[0]).toMatchObject({ settings: { auto_lock_minutes: 10, port: 47600 } });
    expect(screen.getByText(/没有启用/)).toBeTruthy();
  });

  test("迁移中显示只读提示，取消迁移要确认后果", async () => {
    const b = backend({ list_items: [], migration_cancel: () => { b.state.status = status(); return null; } });
    b.state.status = status({ migrating: true });
    const user = await go("设备迁移");
    await user.click(screen.getByRole("button", { name: "取消迁移…" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.textContent).toContain("两份都能用的密库");
    await user.click(within(dialog).getByRole("button", { name: "取消迁移，恢复使用" }));
    await screen.findByRole("button", { name: "生成迁移包…" });
  });

  test("迁移导入后持续显示完成码", async () => {
    const user = userEvent.setup();
    const b = backend({
      pick_package: "a.svmig",
      migration_import: () => { b.state.status = status({ phase: "locked" }); return { items: 3, completion_code: "ABCD-1234" }; },
    });
    b.state.status = status({ phase: "empty" });
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /从旧设备迁移/ }));
    await user.click(screen.getByRole("button", { name: "选择文件…" }));
    await screen.findByText("a.svmig");
    await user.type(screen.getByLabelText(/迁移码/), "FAKE");
    await user.type(screen.getByLabelText("主密码", { selector: "input[name=secret]" }), FAKE.master);
    await user.click(screen.getByRole("button", { name: "导入到这台设备" }));
    await screen.findByText("ABCD-1234");
    await user.click(screen.getByRole("button", { name: "我已在旧设备输入" }));
    await screen.findByRole("heading", { name: "密库已锁定" });
  });

  test("导入报告列出失败行，删除 CSV 要确认", async () => {
    const b = backend({ list_items: [], import_csv: { format: "Chrome", imported: 2, blank: 0, adjusted: [], rejected: [[3, "列数与表头不符"]], prompt: "请先核对", file: "a.csv" } });
    const user = await go("导入与备份");
    await user.click(screen.getByRole("button", { name: "选择 CSV…" }));
    await screen.findByText(/第 3 行：列数与表头不符/);
    await user.click(screen.getByRole("button", { name: "删除 a.csv…" }));
    expect(b.of("delete_csv")).toHaveLength(0);
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "删除文件" }));
    await waitFor(() => expect(b.of("delete_csv")).toHaveLength(1));
  });
});
