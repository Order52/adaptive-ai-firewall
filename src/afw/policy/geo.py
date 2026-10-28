"""Real-country enforcement tables (ADR-036).

The controller cannot load thousands of networks with its least-privilege OPNsense
key (alias membership one address per call, ADR-017). Instead it *publishes* the
desired network list per direction; a job on FW01 pulls it over HTTPS and replaces
the pf table in one atomic ``pfctl -T replace``. The controller then verifies by
reading the live table back, so "enforced" never rests on the publication alone.

Lists contain only globally routable networks from the installed GeoIP database;
lab, private and reserved space can never appear in them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from afw.config import GeoEnforcementConfig
from afw.geoip import GeoIpDatabase

Direction = Literal["inbound", "outbound"]
DIRECTIONS: tuple[Direction, ...] = ("inbound", "outbound")


@dataclass(frozen=True)
class GeoList:
    countries: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()

    @property
    def body(self) -> str:
        return "".join(f"{n}\n" for n in self.networks)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body.encode()).hexdigest()

    def text(self, direction: Direction) -> str:
        """What FW01 fetches: one header line, then one network per line."""
        head = (
            f"# afw-geo direction={direction} countries={','.join(self.countries) or '-'} "
            f"count={len(self.networks)} sha256={self.sha256}\n"
        )
        return head + self.body


class GeoTables:
    def __init__(self, cfg: GeoEnforcementConfig, db: Callable[[], GeoIpDatabase | None]) -> None:
        self.cfg = cfg
        self.db = db
        self._nets: dict[str, frozenset[str]] = {}
        self.published: dict[Direction, GeoList] = {d: GeoList() for d in DIRECTIONS}

    def alias(self, direction: Direction) -> str:
        return self.cfg.inbound_alias if direction == "inbound" else self.cfg.outbound_alias

    def networks(self, country_code: str) -> frozenset[str]:
        """Globally routable networks of a country (cached; the scan is O(ranges))."""
        cc = country_code.upper()
        if cc not in self._nets:
            db = self.db()
            if db is None:
                raise ValueError("no GeoIP database loaded")
            self._nets[cc] = frozenset(str(n) for n in db.networks(cc) if n.is_global)
        return self._nets[cc]

    def build(self, countries: frozenset[str]) -> GeoList:
        nets: set[str] = set()
        for cc in countries:
            nets |= self.networks(cc)
        if len(nets) > self.cfg.max_networks:
            raise ValueError(
                f"{len(nets)} networks exceed the per-direction limit {self.cfg.max_networks}"
            )
        ordered = sorted(nets, key=lambda n: IPv4Network(n))
        return GeoList(countries=tuple(sorted(countries)), networks=tuple(ordered))

    def publish(self, direction: Direction, countries: frozenset[str]) -> GeoList:
        """Make ``countries`` the desired content of the direction's table."""
        if tuple(sorted(countries)) != self.published[direction].countries:
            self.published[direction] = self.build(countries)
        return self.published[direction]

    def present(self, table: frozenset[str], candidates: frozenset[str]) -> frozenset[str]:
        """Countries among ``candidates`` whose every network is in the live table."""
        return frozenset(
            cc for cc in candidates if self.networks(cc) and self.networks(cc) <= table
        )

    def country_of(self, address: IPv4Address) -> str | None:
        db = self.db()
        return db.lookup(address) if db is not None else None
