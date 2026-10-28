"""N2/N4: network novelty detector (calibrated unfamiliarity + fixed ceilings)."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import pytest

from afw.features.network import FEATURE_NAMES, NetworkVector
from afw.ml.network_detector import CEILINGS, NetworkNovelty

T = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)


def v(src: str = "10.77.20.150", **vals: float) -> NetworkVector:
    values = dict.fromkeys(FEATURE_NAMES, 0.0) | vals
    return NetworkVector(source_ip=IPv4Address(src), window_end=T, values=values, n_events=1)


def benign(n: int = 200) -> list[NetworkVector]:
    # legitimate residual activity: occasional failed connection, a few DNS lookups
    return [
        v(failed_60=float(i % 3 == 0), dns_queries_60=float(i % 5), dns_names_60=float(i % 4))
        for i in range(n)
    ]


def test_uncalibrated_detector_flags_only_at_ceilings():
    d = NetworkNovelty()
    assert not d.assess(v(dst_ports_60=14)).unfamiliar
    r = d.assess(v(dst_ports_60=15))
    assert r.unfamiliar and r.strong and "dst_ports_60=15 (ceiling" in r.reasons[0]


def test_calibrated_levels_mark_unfamiliar_without_claiming_malice():
    d = NetworkNovelty()
    d.calibrate(benign())
    assert not d.assess(v(failed_60=1, dns_queries_60=4)).unfamiliar
    r = d.assess(v(ssh_flows_60=2))  # never seen in benign, far below the ceiling
    assert r.unfamiliar and not r.strong and r.score > 1


def test_poisoned_calibration_cannot_raise_a_threshold_above_its_ceiling():
    d = NetworkNovelty()
    poisoned = benign(100) + [v(dst_ports_60=500, ssh_flows_60=400) for _ in range(100)]
    d.calibrate(poisoned)
    eff = d.effective()
    for name, ceiling in CEILINGS.items():
        assert eff[name] <= ceiling
    assert d.assess(v(dst_ports_60=20)).strong  # a scan is still a scan


def test_calibration_needs_enough_windows():
    with pytest.raises(ValueError):
        NetworkNovelty().calibrate(benign(10))


def test_slow_scan_is_caught_on_the_long_horizon():
    d = NetworkNovelty()
    d.calibrate(benign())
    r = d.assess(v(dst_ports_60=5, dst_ports_300=60))
    assert r.strong and any(x.startswith("dst_ports_300") for x in r.reasons)
