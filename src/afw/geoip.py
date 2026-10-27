"""Real IPv4 country lookup from the DB-IP "IP to Country Lite" database (M7).

The database is CC BY 4.0 ("IP Geolocation by DB-IP", https://db-ip.com) and is
installed on a host with ``afw geoip install``: the CSV is copied next to a metadata
file recording its source, release month and SHA-256. The loader verifies the hash,
keeps only IPv4 ranges, and answers lookups by binary search. No network access at
runtime.

Lab addresses are RFC 1918 and therefore have no country: lookups return ``None`` for
them, so real country policies can never silently match lab clients. Simulated lab
geography stays a separate, labelled mechanism (``geo_simulation``).
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import shutil
from array import array
from bisect import bisect_right
from dataclasses import dataclass
from datetime import UTC, date, datetime
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from pathlib import Path
from typing import Any

ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
DB_FILE = "country.csv.gz"
META_FILE = "country.meta.json"
STALE_AFTER_DAYS = 45  # DB-IP Lite is released monthly


@dataclass(frozen=True)
class GeoIpMeta:
    source: str
    release: str  # YYYY-MM
    sha256: str
    installed_at: str
    license: str = ATTRIBUTION

    @property
    def released(self) -> date:
        y, m = self.release.split("-")
        return date(int(y), int(m), 1)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def install(
    src: Path, geo_dir: Path, release: str, source: str, now: datetime, min_ranges: int = 100_000
) -> GeoIpMeta:
    """Copy a downloaded DB-IP country CSV (.csv.gz) into ``geo_dir`` with metadata."""
    datetime.strptime(release, "%Y-%m")  # validates the format
    geo_dir.mkdir(parents=True, exist_ok=True)
    tmp = geo_dir / f".{DB_FILE}.tmp"
    shutil.copyfile(src, tmp)
    db = GeoIpDatabase.parse(tmp)  # refuse files that do not parse
    if len(db) < min_ranges:
        tmp.unlink()
        raise ValueError(f"only {len(db)} IPv4 ranges: not a full country database")
    meta = GeoIpMeta(
        source=source, release=release, sha256=_sha256(tmp), installed_at=now.isoformat()
    )
    tmp.replace(geo_dir / DB_FILE)
    (geo_dir / META_FILE).write_text(json.dumps(meta.__dict__, indent=2))
    return meta


class GeoIpDatabase:
    def __init__(
        self, starts: array[int], ends: array[int], ccs: list[str], meta: GeoIpMeta | None
    ) -> None:
        self._starts, self._ends, self._ccs, self.meta = starts, ends, ccs, meta

    def __len__(self) -> int:
        return len(self._starts)

    @classmethod
    def parse(cls, path: Path, meta: GeoIpMeta | None = None) -> GeoIpDatabase:
        starts, ends, ccs = array("L"), array("L"), []
        with gzip.open(path, "rt", newline="", encoding="ascii") as f:
            for row in csv.reader(f):
                if len(row) != 3 or ":" in row[0]:
                    continue  # IPv6 or malformed
                lo, hi = int(IPv4Address(row[0])), int(IPv4Address(row[1]))
                if starts and lo <= ends[-1]:
                    raise ValueError(f"ranges unsorted or overlapping at {row[0]}")
                starts.append(lo)
                ends.append(hi)
                ccs.append(row[2].upper())
        return cls(starts, ends, ccs, meta)

    @classmethod
    def load(cls, geo_dir: Path) -> GeoIpDatabase:
        meta = GeoIpMeta(**json.loads((geo_dir / META_FILE).read_text()))
        path = geo_dir / DB_FILE
        if _sha256(path) != meta.sha256:
            raise ValueError("GeoIP database does not match its recorded SHA-256")
        return cls.parse(path, meta)

    def lookup(self, ip: IPv4Address) -> str | None:
        """ISO country code, or None for private/reserved space (DB-IP code ZZ)."""
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            return None
        n = int(ip)
        i = bisect_right(self._starts, n) - 1
        if i < 0 or n > self._ends[i]:
            return None
        cc = self._ccs[i]
        return None if cc == "ZZ" else cc

    def networks(self, country_code: str) -> list[IPv4Network]:
        cc = country_code.upper()
        out: list[IPv4Network] = []
        for lo, hi, c in zip(self._starts, self._ends, self._ccs, strict=True):
            if c == cc:
                out.extend(summarize_address_range(IPv4Address(lo), IPv4Address(hi)))
        return out

    def countries(self) -> set[str]:
        return set(self._ccs) - {"ZZ"}

    def status(self, now: datetime, stale_after_days: int = STALE_AFTER_DAYS) -> dict[str, Any]:
        if self.meta is None:
            return {"loaded": True, "ranges": len(self), "metadata": None, "stale": True}
        age = (now.astimezone(UTC).date() - self.meta.released).days
        return {
            "loaded": True,
            "ranges": len(self),
            "release": self.meta.release,
            "age_days": age,
            "stale": age > stale_after_days,
            "sha256": self.meta.sha256,
            "source": self.meta.source,
            "license": self.meta.license,
        }


def load_optional(geo_dir: Path) -> tuple[GeoIpDatabase | None, str | None]:
    """The installed database, or (None, reason). Never raises at startup."""
    if not (geo_dir / META_FILE).exists():
        return None, "no GeoIP database installed (afw geoip install)"
    try:
        return GeoIpDatabase.load(geo_dir), None
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return None, f"GeoIP database unusable: {exc}"


def country_preview(
    db: GeoIpDatabase,
    country_code: str,
    direction: str,
    observed_sources: list[IPv4Address],
    now: datetime,
    sample: int = 10,
) -> dict[str, Any]:
    """What a real country policy would cover, without enforcing anything."""
    cc = country_code.upper()
    if cc not in db.countries():
        raise ValueError(f"{cc} is not a country in the GeoIP database")
    nets = db.networks(cc)
    matched = sorted({ip for ip in observed_sources if db.lookup(ip) == cc})
    return {
        "country_code": cc,
        "direction": direction,
        "direction_meaning": {
            "inbound": f"connections initiated from {cc} toward the protected services",
            "outbound": f"connections initiated from lab networks toward {cc}",
            "both": "inbound and outbound",
        }[direction],
        "networks": len(nets),
        "addresses": sum(n.num_addresses for n in nets),
        "sample_networks": [str(n) for n in nets[:sample]],
        "observed_sources_in_country": [str(ip) for ip in matched],
        "observed_sources_checked": len(set(observed_sources)),
        "lab_effect": (
            "none: every lab client address is RFC 1918 and has no country"
            if not matched
            else f"{len(matched)} observed source(s) would be covered"
        ),
        "enforcement": "preview only: real-country enforcement is not implemented (ADR-033)",
        "database": db.status(now),
    }
