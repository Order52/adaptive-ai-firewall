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


def test_strong_reason_names_the_ceiling_not_the_calibrated_level():
    # NV1 §7.3: a calibrated level of 7 was printed as "ceiling at 7" (ceiling 10)
    d = NetworkNovelty()
    d.calibrate([*benign(), *[v(sweep_hosts_60=7) for _ in range(20)]])
    r = d.assess(v(sweep_hosts_60=11))
    assert r.strong and r.reasons == ("sweep_hosts_60=11 (ceiling at 10)",)


def test_many_answered_internet_hosts_are_at_most_unfamiliar():
    d = NetworkNovelty()
    d.calibrate(benign())
    r = d.assess(v(dst_hosts_60=11))  # NV1: a heavy legitimate browser
    assert r.unfamiliar and not r.strong


def test_calibration_needs_enough_windows():
    with pytest.raises(ValueError):
        NetworkNovelty().calibrate(benign(10))


def test_slow_scan_is_caught_on_the_long_horizon():
    d = NetworkNovelty()
    d.calibrate(benign())
    r = d.assess(v(dst_ports_60=5, dst_ports_300=60))
    assert r.strong and any(x.startswith("dst_ports_300") for x in r.reasons)


def test_calibration_round_trip_and_schema_check():
    d = NetworkNovelty()
    d.calibrate(benign())
    e = NetworkNovelty()
    e.load(d.to_dict())
    assert e.effective() == d.effective() and e.n_calibration == 200
    with pytest.raises(ValueError, match="schema"):
        e.load(d.to_dict() | {"schema": ["x"]})


def test_calibration_windows_include_quiet_benign_users_as_zero_vectors():
    from test_dataset_validation import manifest
    from test_network_features import SERVICES, USER, dns

    from afw.ml.datasets import Role, SourceLabel
    from afw.ml.network_detector import calibration_windows

    m = manifest(
        start=T,
        end=T + dt.timedelta(minutes=20),
        sources=(
            SourceLabel(ip=USER, role=Role.BENIGN),
            SourceLabel(ip=IPv4Address("10.77.20.151"), role=Role.BENIGN),
        ),
    )
    ev = [dns(name=f"h{i}.lab", at=600 + i) for i in range(5)]
    vs = calibration_windows(m, ev, SERVICES)
    # emissions at start+375 s .. end+75 s (inclusive) every 30 s: 31, two users each
    assert len(vs) == 2 * 31
    active = [v for v in vs if v.n_events]
    assert active and all(v.source_ip == USER for v in active)
    assert max(v.values["dns_queries_300"] for v in active) == 5


def test_score_stays_finite_when_benign_level_is_zero():
    d = NetworkNovelty()
    d.calibrate([v() for _ in range(40)])  # all-zero benign data
    r = d.assess(v(udp_flows_60=1))
    assert r.unfamiliar and not r.strong and r.score == 1.0
