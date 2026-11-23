"""仅供 Rust 集成测试启动。假令牌与授权码走匿名管道。"""
import asyncio
import json
import sys

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client


async def exercise(read, write):
    async with ClientSession(read, write) as sdk:
        info = await sdk.initialize()
        assert info.protocolVersion == "2025-11-25"
        names = [t.name for t in (await sdk.list_tools()).tools]
        assert names == ["search_entries", "request_access", "get_request_status", "get_secret"]

        async def call(name, **kwargs):
            reply = await sdk.call_tool(name, kwargs)
            assert not reply.isError
            return json.loads(reply.content[0].text)

        hits = await call("search_entries", query="Cassiopeia")
        request = await call("request_access", item_ref=hits["results"][0]["item_ref"],
                             fields=["password"], reason="官方 SDK 假数据测试")
        rid = request["request_id"]
        assert (await call("get_request_status", request_id=rid))["state"] == "pending"
        print(rid, flush=True)
        code = await asyncio.to_thread(input)
        assert (await call("get_request_status", request_id=rid))["state"] == "code_issued"
        result = await call("get_secret", request_id=rid, code=code)
        assert result["fields"] == [{"name": "password", "value": "Fake-Violet-Secret-7172"}]
        assert (await sdk.call_tool("get_secret", {"request_id": rid, "code": code})).isError


async def main():
    mode, port, bridge = sys.argv[1:]
    token = input()
    if mode == "stdio":
        args = StdioServerParameters(command=bridge, args=["mcp", "codex"],
                                     env={"SUISHEN_CODEX_TOKEN": token, "SUISHEN_PORT": port})
        async with stdio_client(args) as streams:
            await exercise(*streams)
    else:
        async with httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, trust_env=False) as client:
            async with streamable_http_client("http://127.0.0.1:" + port + "/mcp", http_client=client) as (r, w, _):
                await exercise(r, w)


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=25))

