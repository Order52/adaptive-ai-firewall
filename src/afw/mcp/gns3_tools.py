"""GNS3 lab-infrastructure MCP tools (host-side).

These tools run where the MCP server runs (the lab host) and talk directly to
the GNS3 REST API (`~/.config/afw/gns3.env`), separate from the controller REST
API that backs the AI/policy tools. They let an operator inspect the real
topology, read node status/resources, run the zone-isolation verification, and
start/stop/restart nodes.

Safety: operational actions are guarded — the controller node (which runs the
control plane and this MCP backend) is never stopped/restarted through MCP, and
every mutating call names the node and action in its result so the MCP client
can surface it for approval. Nothing here can touch hosts outside the GNS3
project.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Literal

from mcp.server import MCPServer

from afw.lab.gns3 import Gns3Client, Gns3Error

PROJECT_NAME = os.environ.get("AFW_GNS3_PROJECT", "AI-Adaptive-Firewall")

# Nodes that must not be stopped/restarted via MCP (would sever the control
# plane / this MCP backend / the firewall that enforces isolation).
_NEVER_STOP = {"CTRL01"}
_WARN_STOP = {"FW01"}

_MACHINE_TYPES = {"qemu", "docker", "vpcs"}


@lru_cache(maxsize=1)
def _client() -> Gns3Client:
    return Gns3Client.from_env()


def _project_id() -> str:
    proj = _client().find_project(PROJECT_NAME)
    if proj is None:
        raise Gns3Error(f"GNS3 project {PROJECT_NAME!r} not found")
    return str(proj["project_id"])


def _node_summary(n: dict[str, Any]) -> dict[str, Any]:
    props = n.get("properties") or {}
    return {
        "name": n["name"],
        "node_type": n["node_type"],
        "status": n["status"],
        "is_machine": n["node_type"] in _MACHINE_TYPES,
        "console": n.get("console"),
        "ram_mb": props.get("ram"),
        "vcpus": props.get("cpus"),
        "node_id": n["node_id"],
    }


def _find_node(pid: str, name: str) -> dict[str, Any]:
    nodes = _client().node_by_name(pid)
    key = next((k for k in nodes if k.lower() == name.lower()), None)
    if key is None:
        raise Gns3Error(f"node {name!r} not in project (have: {', '.join(sorted(nodes))})")
    return dict(nodes[key])


def register(server: MCPServer) -> None:
    """Attach the GNS3 tools to an existing MCPServer instance."""

    @server.tool()
    def lab_topology() -> dict[str, Any]:
        """Full GNS3 topology: every node (type, status, console, RAM/vCPUs) and link.

        Use for 'show me the entire lab / status of every device'. Switches,
        cloud and NAT nodes are infrastructure; `is_machine` marks real guests.
        """
        pid = _project_id()
        nodes = _client().nodes(pid)
        by_id = {n["node_id"]: n["name"] for n in nodes}
        links = []
        for lk in _client().links(pid):
            ends = [
                f"{by_id.get(e['node_id'], e['node_id'])}:{e['adapter_number']}/{e['port_number']}"
                for e in lk.get("nodes", [])
            ]
            links.append(" <-> ".join(ends))
        summaries = [_node_summary(n) for n in nodes]
        return {
            "project": PROJECT_NAME,
            "nodes": sorted(summaries, key=lambda s: s["name"]),
            "machines": sorted(s["name"] for s in summaries if s["is_machine"]),
            "running": sum(1 for s in summaries if s["status"] == "started"),
            "total_nodes": len(summaries),
            "links": sorted(links),
        }

    @server.tool()
    def lab_node(name: str) -> dict[str, Any]:
        """Detailed status of one lab node (status, console, ports, allocated resources)."""
        pid = _project_id()
        n = _find_node(pid, name)
        summary = _node_summary(n)
        summary["ports"] = [
            {
                "name": p.get("name"),
                "adapter": p.get("adapter_number"),
                "port": p.get("port_number"),
            }
            for p in (n.get("ports") or [])
        ]
        return summary

    @server.tool()
    def lab_resources() -> dict[str, Any]:
        """Allocated RAM/vCPUs and run-state per guest (GNS3 does not expose live %).

        For live controller CPU/RSS use `overview` (the AI controller's own
        resource panel). Per-guest live usage would need in-guest agents.
        """
        pid = _project_id()
        machines = [
            _node_summary(n) for n in _client().nodes(pid) if n["node_type"] in _MACHINE_TYPES
        ]
        total_ram = sum(m["ram_mb"] or 0 for m in machines)
        return {
            "guests": sorted(
                (
                    {
                        "name": m["name"],
                        "status": m["status"],
                        "ram_mb": m["ram_mb"],
                        "vcpus": m["vcpus"],
                    }
                    for m in machines
                ),
                key=lambda m: m["name"],
            ),
            "allocated_ram_mb_total": total_ram,
            "note": "RAM/vCPUs are GNS3 allocations, not live usage.",
        }

    def _action(name: str, action: Literal["start", "stop", "reload"]) -> dict[str, Any]:
        pid = _project_id()
        n = _find_node(pid, name)
        real = n["name"]
        if action in ("stop", "reload") and real.upper() in _NEVER_STOP:
            return {
                "refused": True,
                "node": real,
                "reason": f"{real} runs the control plane and this MCP backend; "
                "stopping/restarting it via MCP is not allowed.",
            }
        _client().node_action(pid, n["node_id"], action)
        result = {"node": real, "action": action, "ok": True}
        if real.upper() in _WARN_STOP and action in ("stop", "reload"):
            result["warning"] = (
                f"{real} is the firewall; isolation/enforcement is affected while it restarts."
            )
        return result

    @server.tool()
    def start_node(name: str) -> dict[str, Any]:
        """Start one lab node by name."""
        return _action(name, "start")

    @server.tool()
    def stop_node(name: str) -> dict[str, Any]:
        """Stop one lab node by name (refused for the controller node)."""
        return _action(name, "stop")

    @server.tool()
    def restart_node(name: str) -> dict[str, Any]:
        """Restart one lab node by name (refused for the controller node)."""
        return _action(name, "reload")
