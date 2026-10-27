"""M7: real GeoIP lookup, provenance/integrity, freshness and preview."""

from __future__ import annotations

import gzip
import json
from datetime import timedelta
from ipaddress import IPv4Address as A
from ipaddress import IPv4Network

import pytest
from conftest import T0

from afw.geoip import GeoIpDatabase, country_preview, install, load_optional

ROWS = [
    "0.0.0.0,0.255.255.255,ZZ",
    "1.0.0.0,1.0.0.255,AU",
    "1.0.1.0,1.0.3.255,CN",
    "5.0.0.0,5.0.0.127,IQ",  # gap follows
    "10.0.0.0,10.255.255.255,ZZ",
    "2001:db8::,2001:db8::ffff,CN",  # IPv6 ignored
    "100.0.0.0,100.0.0.255,US",
    "101.0.0.0,101.0.0.255,ZZ",  # unassigned public space
    "192.168.0.0,192.168.255.255,US",  # bad upstream data must not give lab space a country
]


def _csv(path, rows=ROWS):
    with gzip.open(path, "wt") as f:
        f.write("\n".join(rows) + "\n")
    return path


@pytest.fixture
def geo_dir(tmp_path):
    src = _csv(tmp_path / "dl.csv.gz")
    install(src, tmp_path / "geo", "2026-10", "https://example.test/dl", T0, min_ranges=1)
    return tmp_path / "geo"


def test_lookup_public_private_gaps_and_reserved(geo_dir):
    db, err = load_optional(geo_dir)
    assert db is not None and err is None and len(db) == 8
    assert db.lookup(A("1.0.2.9")) == "CN"
    assert db.lookup(A("1.0.0.1")) == "AU"
    assert db.lookup(A("5.0.0.200")) is None  # gap
    assert db.lookup(A("10.77.10.10")) is None  # lab space never has a country
    assert db.lookup(A("0.0.0.5")) is None
    assert db.lookup(A("101.0.0.9")) is None  # ZZ is not a country
    assert db.lookup(A("192.168.1.1")) is None  # RFC 1918 regardless of the data
    assert db.lookup(A("100.0.0.1")) == "US"
    assert db.countries() == {"AU", "CN", "IQ", "US"}
    assert db.networks("CN") == [IPv4Network("1.0.1.0/24"), IPv4Network("1.0.2.0/23")]


def test_tampered_database_is_refused(geo_dir):
    _csv(geo_dir / "country.csv.gz", [*ROWS[:2], "1.0.1.0,1.0.3.255,US"])
    db, err = load_optional(geo_dir)
    assert db is None and "SHA-256" in err


def test_missing_database_reports_reason(tmp_path):
    db, err = load_optional(tmp_path / "nothing")
    assert db is None and "afw geoip install" in err


def test_install_refuses_partial_or_unsorted_files(tmp_path):
    src = _csv(tmp_path / "small.csv.gz")
    with pytest.raises(ValueError, match="not a full country database"):
        install(src, tmp_path / "g", "2026-10", "u", T0)
    assert not (tmp_path / "g" / "country.csv.gz").exists()
    bad = _csv(tmp_path / "bad.csv.gz", ["1.0.1.0,1.0.3.255,CN", "1.0.2.0,1.0.2.255,AU"])
    with pytest.raises(ValueError, match="overlapping"):
        GeoIpDatabase.parse(bad)
    with pytest.raises(ValueError):
        install(src, tmp_path / "g", "Oct 2026", "u", T0, min_ranges=1)


def test_freshness_is_reported_from_release_month(geo_dir):
    db, _ = load_optional(geo_dir)
    assert db is not None
    meta = json.loads((geo_dir / "country.meta.json").read_text())
    assert meta["release"] == "2026-10" and "DB-IP" in meta["license"]
    fresh = db.status(T0.replace(year=2026, month=10, day=20))
    assert fresh["stale"] is False and fresh["age_days"] == 19
    old = db.status(T0.replace(year=2026, month=10, day=1) + timedelta(days=46))
    assert old["stale"] is True


def test_preview_counts_networks_and_observed_sources(geo_dir):
    db, _ = load_optional(geo_dir)
    assert db is not None
    lab = [A("10.77.10.10"), A("10.77.20.10")]
    p = country_preview(db, "cn", "inbound", lab, T0)
    assert p["networks"] == 2 and p["addresses"] == 768
    assert p["observed_sources_in_country"] == [] and p["lab_effect"].startswith("none")
    assert "preview only" in p["enforcement"]
    p2 = country_preview(db, "CN", "outbound", [*lab, A("1.0.1.7"), A("1.0.1.7")], T0)
    assert p2["observed_sources_in_country"] == ["1.0.1.7"]
    assert "from lab networks toward CN" in p2["direction_meaning"]
    with pytest.raises(ValueError, match="not a country"):
        country_preview(db, "ZZ", "inbound", lab, T0)
