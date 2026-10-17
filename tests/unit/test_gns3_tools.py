"""Pure-logic checks for the GNS3 MCP tool helpers (no live GNS3 needed)."""

from __future__ import annotations

from afw.mcp import gns3_tools


def test_node_summary_marks_machines_and_reads_resources() -> None:
    node = {
        "name": "CTRL01",
        "node_type": "qemu",
        "status": "started",
        "console": 5009,
        "node_id": "abc",
        "properties": {"ram": 2048, "cpus": 2},
    }
    s = gns3_tools._node_summary(node)
    assert s["is_machine"] is True
    assert s["ram_mb"] == 2048 and s["vcpus"] == 2
    assert s["status"] == "started"


def test_node_summary_switch_is_not_a_machine() -> None:
    s = gns3_tools._node_summary(
        {"name": "SW-MGMT", "node_type": "ethernet_switch", "status": "started", "node_id": "x"}
    )
    assert s["is_machine"] is False
    assert s["ram_mb"] is None


def test_controller_is_guarded_from_power_cycling() -> None:
    # The node running the control plane / MCP backend must never be stopped here.
    assert "CTRL01" in gns3_tools._NEVER_STOP
    assert "FW01" in gns3_tools._WARN_STOP
