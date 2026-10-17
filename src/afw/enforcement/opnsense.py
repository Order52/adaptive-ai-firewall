"""OPNsense network enforcement via the documented alias_util API.

Fixed, pre-installed rules reference the external alias (``AFW_BLOCK_WEB``)
on each client ingress interface, scoped to the protected service. This adapter
only changes alias *membership*; it can never create rules, touch other aliases,
or address non-client networks (the validator guarantees the latter).

A second external alias ``AFW_HEARTBEAT`` holds one sentinel address that is
re-added after every successful reconcile. The firewall-local watchdog
(lab/opnsense/afw-watchdog.sh, cron, checks every 30 s) flushes ``AFW_BLOCK_WEB``
when the sentinel's pf "Cleared" timestamp is older than 90 s, so dynamic blocks
cannot outlive a dead controller by more than ~120 s (measured: 106 s on FW01).
"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Any

import httpx
import structlog

from afw.config import OpnsenseConfig, ServiceConfig
from afw.domain.policy import PolicyKind
from afw.ports.enforcement import ApplyReport, DesiredState, ObservedState

log = structlog.get_logger(__name__)
HEARTBEAT_ALIAS = "AFW_HEARTBEAT"
HEARTBEAT_SENTINEL = "192.0.2.1"  # TEST-NET-1; never routable in the lab


class OpnsenseBackend:
    name = "opnsense"
    handles = frozenset({PolicyKind.SOURCE_BLOCK, PolicyKind.GEO_BLOCK})

    def __init__(self, cfg: OpnsenseConfig, service: ServiceConfig) -> None:
        self.cfg = cfg
        self.service = service
        verify: bool | str = str(cfg.ca_file) if cfg.ca_file and cfg.verify_tls else cfg.verify_tls
        self.client = httpx.Client(
            base_url=cfg.base_url.rstrip("/") + "/api",
            auth=(_read(cfg.key_file), _read(cfg.secret_file)),
            verify=verify,
            timeout=cfg.timeout_s,
        )

    def _call(self, method: str, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self.client.request(method, path, json=json)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError(f"unexpected response from {path}")
        return data

    def _members(self, alias: str) -> frozenset[IPv4Address]:
        data = self._call("GET", f"/firewall/alias_util/list/{alias}")
        out = set()
        for row in data.get("rows", []):
            addr = ip_address(str(row.get("ip", "")).split("/")[0])
            if isinstance(addr, IPv4Address):
                out.add(addr)
        return frozenset(out)

    def observe(self) -> ObservedState:
        try:
            return ObservedState(
                backend=self.name, reachable=True, blocked_sources=self._members(self.cfg.alias)
            )
        except (httpx.HTTPError, ValueError) as exc:
            return ObservedState(backend=self.name, reachable=False, error=str(exc))

    def reconcile(self, desired: DesiredState) -> ApplyReport:
        try:
            current = self._members(self.cfg.alias)
        except httpx.TimeoutException as exc:
            return ApplyReport(backend=self.name, ok=False, error=f"timeout: {exc}", ambiguous=True)
        except (httpx.HTTPError, ValueError) as exc:
            return ApplyReport(backend=self.name, ok=False, error=str(exc), ambiguous=True)
        add = desired.blocked_sources - current
        remove = current - desired.blocked_sources
        errors: list[str] = []
        ambiguous = False
        for verb, items in (("add", add), ("delete", remove)):
            for ip in sorted(items):
                try:
                    res = self._call(
                        "POST",
                        f"/firewall/alias_util/{verb}/{self.cfg.alias}",
                        {"address": str(ip)},
                    )
                    if res.get("status") not in ("done", "ok"):
                        errors.append(f"{verb} {ip}: {res}")
                except httpx.TimeoutException:
                    ambiguous = True
                    errors.append(f"{verb} {ip}: timeout")
                except httpx.HTTPError as exc:
                    errors.append(f"{verb} {ip}: {exc}")
        return ApplyReport(
            backend=self.name,
            ok=not errors,
            added=tuple(map(str, sorted(add))),
            removed=tuple(map(str, sorted(remove))),
            error="; ".join(errors) or None,
            ambiguous=ambiguous,
        )

    def kill_states(self, source: IPv4Address) -> int:
        """Delete only pf states from ``source`` to the protected service."""
        if not self.cfg.kill_states:
            return 0
        data = self._call(
            "POST",
            "/diagnostics/firewall/query_states",
            {"current": 1, "rowCount": 500, "searchPhrase": str(source)},
        )
        # Row format verified on OPNsense 26.7 (scripts/filter/lib/states.py):
        # src_addr/dst_addr are bare addresses, dst_port separate, id is "<id>/<creatorid>".
        # searchPhrase is a substring match, so rows are filtered exactly here.
        killed = 0
        seen: set[str] = set()
        for row in data.get("rows", []):
            if str(row.get("src_addr", "")) != str(source):
                continue
            if str(row.get("dst_addr", "")) != str(self.service.address):
                continue
            if str(row.get("dst_port", "")) != str(self.service.port):
                continue
            sid, _, creator = str(row.get("id", "")).partition("/")
            if not sid or not creator or row["id"] in seen:
                continue
            seen.add(row["id"])
            self._call("POST", f"/diagnostics/firewall/del_state/{sid}/{creator}")
            killed += 1
        return killed

    def heartbeat(self) -> None:
        # delete + add resets the entry's pf "Cleared" timestamp on the firewall clock
        self._call(
            "POST",
            f"/firewall/alias_util/delete/{HEARTBEAT_ALIAS}",
            {"address": HEARTBEAT_SENTINEL},
        )
        self._call(
            "POST", f"/firewall/alias_util/add/{HEARTBEAT_ALIAS}", {"address": HEARTBEAT_SENTINEL}
        )


def _read(path: Path) -> str:
    return path.read_text().strip()
