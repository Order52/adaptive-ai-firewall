"""The MCP restriction tools build the same intents the dashboard sends."""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from afw.mcp import server as mcp_server

IP = IPv4Address("10.77.20.198")


@pytest.mark.parametrize(
    ("action", "kind", "profile"),
    [
        ("firewall_block", "source_block", None),
        ("waf_deny", "waf_deny", None),
        ("rate_limit_strict", "rate_limit", "strict"),
        ("rate_limit_moderate", "rate_limit", "moderate"),
    ],
)
def test_restriction_body(action: str, kind: str, profile: str | None) -> None:
    body = mcp_server._restriction_body(IP, action, 120, "demo")  # type: ignore[arg-type]
    assert body["kind"] == kind
    assert body["target"] == {"type": "source", "source_ip": "10.77.20.198"}
    assert body["duration_s"] == 120
    assert body.get("rate_profile") == profile


def test_tools_are_registered() -> None:
    names = {t.name for t in mcp_server.server._tool_manager.list_tools()}
    assert {"restrict_source", "simulate_restriction", "block_source", "unblock"} <= names
