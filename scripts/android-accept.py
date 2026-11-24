"""在专用 AVD 上操作正式 APK。凭据仅从终端无回显读取。"""
import asyncio
import getpass
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
PORT = 47600
BASE = f"http://127.0.0.1:{PORT}"
TITLE = "北极星测试站"
FAKE = "Fake-Only-Test-3189"
logging.disable(logging.CRITICAL)


class CheckFailure(Exception):
    pass


def check(condition, why):
    if not condition:
        raise CheckFailure(why)


def adb(*args):
    return subprocess.check_output(["adb", "-s", os.environ["ANDROID_SERIAL"], *args], timeout=30)


def shot(name):
    data = adb("exec-out", "screencap", "-p")
    check(data.startswith(b"\x89PNG\r\n\x1a\n"), "截图失败")
    path = ROOT / "target" / "android-qa"
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{name}.png").write_bytes(data)


async def scenario(token):
    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, trust_env=False) as client:
        async def tool(name, **args):
            async with streamable_http_client(BASE + "/mcp", http_client=client) as (r, w, _):
                async with ClientSession(r, w) as sdk:
                    await sdk.initialize()
                    result = await sdk.call_tool(name, args)
                    check(not result.isError, "MCP 调用失败")
                    return json.loads(result.content[0].text)

        async def search():
            return (await tool("search_entries", query=TITLE))["results"]

        async def request():
            hits = await search()
            check(len(hits) == 1 and FAKE not in str(hits), "检索结果不符")
            return (await tool("request_access", item_ref=hits[0]["item_ref"],
                               fields=["password"], reason="核对模拟器假条目"))["request_id"]

        check(not await search(), "请使用新的测试密库")
        await tool("propose_entry", title=TITLE, type="login", url="https://example.test/login",
                   username="fake-user", hint="模拟器验收", tags=[])
        check(not await search(), "未确认的草稿可被检索")
        input("在草稿箱给北极星测试站补充假密码 Fake-Only-Test-3189 并确认入库，完成后回车。")
        for asleep in [False, True]:
            if asleep:
                adb("shell", "input", "keyevent", "KEYCODE_SLEEP")
                await asyncio.sleep(2)
                power = adb("shell", "dumpsys", "power").decode()
                check(re.search(r"mWakefulness=(Asleep|Dozing)", power), "未进入息屏状态")
                shot("息屏")
            else:
                adb("shell", "input", "keyevent", "KEYCODE_HOME")
                await asyncio.sleep(2)
            rid = await request()
            check((await tool("get_request_status", request_id=rid))["state"] == "pending", "申请状态不符")
            url = BASE + "/v1/requests/" + rid + "/secret"
            unauthorized = await client.get(url)
            check(unauthorized.status_code >= 400 and FAKE not in unauthorized.text, "无授权请求未被拒绝")
            if asleep:
                adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
                input("解锁系统屏幕，保持密库在后台，回车。")
            adb("shell", "cmd", "statusbar", "expand-notifications")
            input("在专用模拟器通知栏核对常驻通知和申请通知，回车截图。")
            shot("唤醒通知" if asleep else "后台通知")
            print("点击申请通知，核对客户端、条目、理由和字段，选择交给 AI 并重新验证。")
            code = getpass.getpass("本次授权码（隐藏输入）：").strip()
            response = await client.get(url, headers={"X-Auth-Code": code})
            check(response.status_code == 200 and response.headers.get("cache-control") == "no-store",
                  "授权 GET 没有成功或缓存头错误")
            check(response.json()["fields"] == [{"name": "password", "value": FAKE}], "返回字段不符")
            replay = await client.get(url, headers={"X-Auth-Code": code})
            check(replay.status_code == 410 and FAKE not in replay.text, "授权码可被重放")
            print("本轮 GET 与重放检查通过。")
        rid = await request()
        print("再批准一次，先保留尚未兑换的假条目授权码。")
        code = getpass.getpass("授权码（隐藏输入）：").strip()
        input("从常驻通知点「全部关闭」，完成后回车。")
        url = BASE + "/v1/requests/" + rid + "/secret"
        try:
            await client.get(url, headers={"X-Auth-Code": code}, timeout=3)
        except httpx.TransportError:
            pass
        else:
            raise CheckFailure("一键关闭后监听仍在响应")
        input("重新在 App 开放「仅本机」，回车验证旧码失效。")
        old = await client.get(url, headers={"X-Auth-Code": code})
        check(old.status_code >= 400 and FAKE not in old.text, "旧授权仍有效")


def main():
    serial = os.environ.get("ANDROID_SERIAL", "")
    check(re.fullmatch(r"emulator-\d+", serial), "请指定专用 Android 模拟器")
    check(adb("emu", "avd", "name").splitlines()[0] == b"SuishenVaultQA", "请使用 SuishenVaultQA")
    adb("forward", "--no-rebind", f"tcp:{PORT}", f"tcp:{PORT}")
    try:
        token = getpass.getpass("模拟器中假客户端的令牌（隐藏输入）：").strip()
        asyncio.run(scenario(token))
        print("后台、息屏、草稿和授权流程通过。截图在 target/android-qa。请关闭测试开放范围。")
    finally:
        adb("forward", "--remove", f"tcp:{PORT}")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # 网络或 SDK 异常可能带请求信息。仅列脚本自己的固定失败原因。
        sys.exit(str(exc) if isinstance(exc, CheckFailure)
                 else "Android 验收未完成，请检查当前步骤、模拟器、端口与设置。")
