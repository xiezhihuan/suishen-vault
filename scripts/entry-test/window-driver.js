// 仅由验收服务器加载，绝不进入 App 构建。仅在本次新建的测试目录中运行。
async function exercise(config) {
  const invoke = (cmd, args) => window.__TAURI_INTERNALS__.invoke(cmd, args);
  const status = await invoke("poll");
  if (status.data_dir !== config.dir || status.phase !== "empty") return;
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const control = async (step, data = {}) => {
    const res = await fetch("/qa/" + config.nonce, { method: "POST", body: JSON.stringify({ step, ...data }) });
    if (!res.ok) throw Error("验收步骤失败");
    return res.json();
  };
  let stage = "初始化";
  try {
    const until = async (fn) => {
      for (let i = 0; i < 120; i++) {
        const v = fn();
        if (v) return v;
        await wait(100);
      }
      throw Error("等待超时");
    };
    const buttons = () => [...document.querySelectorAll("button")];
    const click = async (name) =>
      (await until(() => buttons().find((b) => !b.disabled && b.textContent.startsWith(name)))).click();
    const input = async (selector, value) => {
      const el = await until(() => document.querySelector(selector));
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value").set.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      await wait(100);
    };
    const pw = "Fake-Main-Desk-8237";
    const setup = await invoke("setup_begin", { password: pw });
    await invoke("setup_confirm", { answers: setup.challenge.map((i) => setup.recovery_key.split("-")[i]) });
    stage = "粘贴";
    await click("智能粘贴");
    const transfer = new DataTransfer();
    transfer.setData(
      "text/plain",
      "标题：地平线测试站\n网址：https://demo.test\n账号：fake.horizon\n密码：  Fake:🔐 =  ",
    );
    (await until(() => document.querySelector("textarea"))).dispatchEvent(
      new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: transfer }),
    );
    await click("识别并核对");
    await until(() => document.querySelector("input[type=password]")?.value === "  Fake:🔐 =  ");
    await control("paste-shot");
    await click("确认入库");
    await until(() => document.body.textContent.includes("已新增 1 条记录"));
    const items = await invoke("list_items", { trash: false, query: "地平线测试站" });
    if (
      items.length !== 1 ||
      (await invoke("reveal_field", { id: items[0].id, field: "password", index: 0 })) !== "  Fake:🔐 =  "
    )
      throw Error("切片不匹配");
    stage = "提交草稿";
    const token = await invoke("add_client", { name: "本机 SDK 演示", tags: [], direct: config.publicTest, password: pw });
    await click("AI 客户端");
    await click("允许提交草稿");
    await until(() => buttons().some((b) => b.textContent === "关闭草稿提交"));
    await click("开放范围");
    const openPublic = async () => {
      await invoke("open_service", { scope: "public", minutes: 15, direct: true });
      await until(() => document.body.textContent.includes("已连上跳板"));
    };
    if (config.publicTest) {
      const { url, code } = await control("claim");
      await invoke("relay_claim", { url, code, ca: null, password: pw });
      await openPublic();
    } else {
      await click("仅本机");
      await until(() => document.querySelector(".topbar.loopback"));
    }
    await control("submit", { token });
    stage = "确认草稿";
    await click("草稿箱");
    await until(() => document.querySelector(".full-domain")?.textContent === "xn--fsqu00a.test");
    await input("main input[type=password]", "Fake-Only-Test-3189");
    await control("draft-shot");
    await click("确认入库");
    await until(() => document.body.textContent.includes("没有待核对的草稿"));
    stage = "批准并取用";
    const rid = await control("request", { token });
    await click("授权申请");
    await input("main input[name=password]", pw);
    await click("交给 AI");
    const code = await until(() => document.querySelector('[aria-label="授权码内容"]')?.textContent);
    await control("redeem", { token, rid, code });
    await click("密库");
    await until(() => document.body.textContent.includes("北极星测试站"));
    await control("saved-shot");
    if (config.publicTest) {
      const request = async query => {
        const id = await control("request", { token, query });
        await click("授权申请");
        await until(() => document.querySelector(".approval"));
        return id;
      };
      const approve = async () => {
        await input("main input[name=password]", pw);
        await click("交给 AI");
        return until(() => document.querySelector('[aria-label="授权码内容"]')?.textContent);
      };
      stage = "到期";
      const expiring = await request("北极星");
      const expiringCode = await approve();
      await wait(122000);
      await control("code_expired", { token, rid: expiring, code: expiringCode });
      stage = "拒绝";
      const denied = await request("地平线");
      await click("拒绝");
      await until(() => !document.querySelector(".approval"));
      await control("denied", { token, rid: denied });
      stage = "关闭公网";
      const pending = await request("北极星");
      const pendingCode = await approve();
      await click("开放范围");
      await click("全部关闭并撤销授权");
      await until(() => document.querySelector(".topbar.closed"));
      await control("closed", { token, rid: pending, code: pendingCode });
      await openPublic();
      await control("revoked", { token, rid: pending, code: pendingCode });
    }
    await invoke("close_service");
    await control("done");
  } catch {
    await control("error", { stage });
  }
}
