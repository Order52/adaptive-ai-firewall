"""The MCP server driven by a real MCP client (stdio) against the running lab.

Skipped unless AFW_LAB=1. The server process is spawned exactly as an MCP host
would spawn it and talks to the CTRL01 API with the ``channel=mcp`` token.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

pytestmark = pytest.mark.skipif(not os.environ.get("AFW_LAB"), reason="needs the GNS3 lab")

TOKEN = Path("~/.config/afw/api/mcp.token").expanduser()


def _params() -> StdioServerParameters:
    exe = shutil.which("afw-mcp")
    assert exe, "afw-mcp entry point not installed"
    return StdioServerParameters(
        command=exe,
        env={
            "AFW_API_URL": "https://10.77.50.10:8080",
            "AFW_API_CA": str(Path("~/.config/afw/pki/lab-ca.pem").expanduser()),
            "AFW_MCP_TOKEN_FILE": str(TOKEN),
            "PATH": os.environ["PATH"],
        },
    )


def _payload(result: Any) -> Any:
    assert not getattr(result, "isError", False), result
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured.get("result", structured)
    return json.loads(result.content[0].text)


async def test_mcp_tools_against_lab():
    async with stdio_client(_params()) as (read, write), ClientSession(read, write) as s:
        await s.initialize()
        names = {t.name for t in (await s.list_tools()).tools}
        assert {"lab_health", "block_source", "unblock", "country_policy"} <= names

        health = _payload(await s.call_tool("lab_health", {}))
        assert health["status"] == "ok" and health["simulated_backends"] is False

        refused = _payload(
            await s.call_tool(
                "block_source", {"source_ip": "10.77.50.10", "duration_s": 60, "reason": "mcp test"}
            )
        )
        assert refused.get("state") == "rejected" or refused.get("error") == 422

        p = _payload(
            await s.call_tool(
                "block_source", {"source_ip": "10.77.10.10", "duration_s": 60, "reason": "mcp test"}
            )
        )
        try:
            assert p["state"] == "enforced", p.get("history", [])[-3:]
            assert p["intent"]["origin"] == "mcp"
        finally:
            _payload(
                await s.call_tool(
                    "unblock", {"policy_id": p["policy_id"], "reason": "mcp test cleanup"}
                )
            )

        geo = _payload(
            await s.call_tool(
                "country_policy", {"country_code": "CN", "direction": "inbound", "duration_s": 60}
            )
        )
        try:
            assert geo["intent"]["target"]["simulated"] is True
            assert geo["state"] == "enforced", geo.get("history", [])[-3:]
            v = geo.get("verification", {})
            print("\nSIMULATED country policy CN inbound:", geo["state"], v)
            assert v.get("probed_sources", 0) >= 1  # ATK01 owns 10.77.10.10
        finally:
            _payload(await s.call_tool("unblock", {"policy_id": geo["policy_id"]}))
        out = _payload(
            await s.call_tool(
                "country_policy", {"country_code": "CN", "direction": "outbound", "duration_s": 60}
            )
        )
        assert out["state"] == "rejected"
