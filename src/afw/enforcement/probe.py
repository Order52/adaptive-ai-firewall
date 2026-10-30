"""Lab verification probes via fixed-target probe agents on USER01/ATTACK01.

Each agent (traffic/probe_agent.py) exposes two operations: one HTTPS request to the
*configured* protected service from a named local source address, and (ADR-036) one TCP
connect to an egress target chosen *by name* from the agent's own fixed allowlist. It
accepts no URL, host, port or command, so the controller cannot use it as a general
attack or execution channel.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import httpx
from pydantic import BaseModel, ConfigDict


class ProbeAgent(BaseModel):
    model_config = ConfigDict(frozen=True)
    url: str
    owns: IPv4Network
    token: str


class LabProbe:
    def __init__(self, agents: list[ProbeAgent], legit_source: IPv4Address, timeout_s: float = 6):
        self.agents = agents
        self.legit_source = legit_source
        self.timeout = timeout_s

    def _ask(
        self, source: IPv4Address, op: str = "probe", **params: str
    ) -> dict[str, object] | None:
        agent = next((a for a in self.agents if source in a.owns), None)
        if agent is None:
            return None
        try:
            r = httpx.get(
                f"{agent.url}/v1/{op}",
                params={"source": str(source), **params},
                headers={"Authorization": f"Bearer {agent.token}"},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, dict) else None
        except httpx.HTTPError:
            return None

    def legitimate_ok(self) -> bool | None:
        res = self._ask(self.legit_source)
        return None if res is None else bool(res.get("ok"))

    def source_blocked(self, source: IPv4Address) -> bool | None:
        res = self._ask(source)
        if res is None or res.get("error") == "source_not_local":
            return None
        return not bool(res.get("connected"))

    def egress_connects(self, source: IPv4Address, target: str) -> bool | None:
        res = self._ask(source, "egress", target=target)
        if res is None or "connected" not in res:
            return None
        return bool(res["connected"])
