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

Real-country policies (ADR-036) are not written through this key: the adapter
*publishes* the desired network list per direction (``GeoTables``), FW01 pulls it into
``AFW_GEO_IN`` / ``AFW_GEO_OUT`` with an atomic ``pfctl -T replace``, and this adapter
reads those tables back. The watchdog flushes them with the block table.
"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address, ip_network
from pathlib import Path
from typing import Any

import httpx
import structlog

from afw.config import OpnsenseConfig, ServiceConfig
from afw.domain.policy import PolicyKind
from afw.policy.geo import DIRECTIONS, Direction, GeoTables
from afw.ports.enforcement import ApplyReport, DesiredState, ObservedState

log = structlog.get_logger(__name__)
HEARTBEAT_ALIAS = "AFW_HEARTBEAT"
HEARTBEAT_SENTINEL = "192.0.2.1"  # TEST-NET-1; never routable in the lab
# OPNsense 26.7 returns a malformed chunked body for alias_util/list responses of
# about 5000 rows or more (measured 2026-10-28: 2000-row pages 3/3 ok, 5000-row 0/3), so
# large tables are read in pages well below that.
PAGE = 1000


class OpnsenseBackend:
    name = "opnsense"
    handles = frozenset({PolicyKind.SOURCE_BLOCK, PolicyKind.GEO_BLOCK})

    def __init__(
        self, cfg: OpnsenseConfig, service: ServiceConfig, geo: GeoTables | None = None
    ) -> None:
        self.cfg = cfg
        self.service = service
        self.geo = geo
        # read a geo table only while something is (or was last seen) in it
        self._geo_nonempty: dict[Direction, bool] = {d: True for d in DIRECTIONS}
        self._geo_watch: frozenset[str] = frozenset()
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

    def _table(self, alias: str) -> frozenset[str]:
        """Every entry of a (possibly large) pf table, normalised to CIDR strings."""
        out: set[str] = set()
        page = 1
        while True:
            data = self._call(
                "POST", f"/firewall/alias_util/list/{alias}", {"current": page, "rowCount": PAGE}
            )
            rows = data.get("rows", [])
            out |= {str(ip_network(str(r["ip"]), strict=False)) for r in rows if r.get("ip")}
            if not rows or len(out) >= int(data.get("total", 0)) or len(rows) < PAGE:
                return frozenset(out)
            page += 1

    def _observe_geo(self, d: Direction) -> frozenset[str]:
        assert self.geo is not None
        pub = self.geo.published[d]
        if not pub.networks and not self._geo_nonempty[d]:
            return frozenset()
        table = self._table(self.geo.alias(d))
        self._geo_nonempty[d] = bool(table)
        return self.geo.present(table, frozenset(pub.countries) | self._geo_watch)

    def observe(self) -> ObservedState:
        try:
            geo: dict[Direction, frozenset[str] | None] = {d: None for d in DIRECTIONS}
            if self.geo is not None:
                geo = {d: self._observe_geo(d) for d in DIRECTIONS}
            return ObservedState(
                backend=self.name,
                reachable=True,
                blocked_sources=self._members(self.cfg.alias),
                geo_inbound=geo["inbound"],
                geo_outbound=geo["outbound"],
            )
        except (httpx.HTTPError, ValueError) as exc:
            return ObservedState(backend=self.name, reachable=False, error=str(exc))

    def _geo_desired(self, desired: DesiredState) -> list[str]:
        # The policy service publishes the lists FW01 pulls; this adapter only records
        # which countries to read back (including ones being removed).
        if self.geo is None:
            wanted = desired.geo_inbound or desired.geo_outbound
            return ["real-country enforcement is not configured"] if wanted else []
        self._geo_watch = desired.geo_inbound | desired.geo_outbound | desired.geo_watch
        return []

    def reconcile(self, desired: DesiredState) -> ApplyReport:
        geo_errors = self._geo_desired(desired)
        try:
            current = self._members(self.cfg.alias)
        except httpx.TimeoutException as exc:
            return ApplyReport(backend=self.name, ok=False, error=f"timeout: {exc}", ambiguous=True)
        except (httpx.HTTPError, ValueError) as exc:
            return ApplyReport(backend=self.name, ok=False, error=str(exc), ambiguous=True)
        add = desired.blocked_sources - current
        remove = current - desired.blocked_sources
        errors: list[str] = list(geo_errors)
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
