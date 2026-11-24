"""只由本地验收进程启动。所有凭据从 stdin 读取，不记录请求体。"""
import asyncio
import json
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main(req):
    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + req["token"]}, trust_env=False) as client:
        base = "http://127.0.0.1:" + str(req["port"])
        if req["step"] in ("denied", "code_expired", "closed", "revoked"):
            res = await client.get(base + "/v1/requests/" + req["rid"] + "/secret",
                                   headers={"X-Auth-Code": req.get("code", "00000000")})
            assert "fields" not in res.json() and "Fake-" not in res.text
            if req["step"] == "closed":
                assert res.status_code == 503
            elif req["step"] == "revoked":
                assert res.status_code in (404, 410)
            else:
                assert res.status_code == 410 and res.json()["state"] == req["step"]
            return True
        async with streamable_http_client(base + "/mcp", http_client=client) as (read, write, _):
            async with ClientSession(read, write) as sdk:
                await sdk.initialize()

                async def call(name, **args):
                    res = await sdk.call_tool(name, args)
                    if res.isError:
                        raise ValueError("请求被拒绝")
                    return json.loads(res.content[0].text)

                if req["step"] == "submit":
                    result = await call("propose_entry", title="北极星测试站", type="login", url="https://例子.test/login",
                                        username="demo-user", tags=["演示"], hint="仅用于本机验收")
                    assert result == {"submitted": True}
                    assert not (await call("search_entries", query="北极星测试站"))["results"]
                elif req["step"] == "request":
                    hits = (await call("search_entries", query=req.get("query", "北极星测试站")))["results"]
                    assert len(hits) == 1
                    return (await call("request_access", item_ref=hits[0]["item_ref"], fields=["password"],
                                       reason="核对本机测试流程"))["request_id"]
                elif req["step"] == "redeem":
                    headers = {"X-Auth-Code": req["code"]}
                    url = base + "/v1/requests/" + req["rid"] + "/secret"
                    res = await client.get(url, headers=headers)
                    assert res.headers["cache-control"] == "no-store"
                    assert res.json()["fields"] == [{"name": "password", "value": "Fake-Only-Test-3189"}]
                    assert (await client.get(url, headers=headers)).status_code == 410
                else:
                    raise ValueError()
    return True


try:
    print(json.dumps(asyncio.run(main(json.load(sys.stdin)))))
except Exception:
    sys.exit("SDK 验收失败")
