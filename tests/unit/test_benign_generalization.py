"""P1 benign-generalization metrics: denominators, non-overlap and units."""

from __future__ import annotations

import numpy as np
import pytest
from test_evidence_independence import _profile
from test_online_learning import _record, fv

from afw.domain.features import FEATURE_NAMES
from afw.ml.benign_generalization import detector_rates
from afw.ml.inference import LoadedModel

REQ = FEATURE_NAMES.index("req_rate")


class ByReqRate:
    """Scores a window by its req_rate, so tests choose exactly which windows flag."""

    def score(self, x: np.ndarray) -> np.ndarray:
        return x[:, REQ]


def _model(threshold: float) -> LoadedModel:
    rec = _record(_profile()).model_copy(update={"threshold": threshold})
    return LoadedModel(record=rec, detector=ByReqRate())


def _user(src: str, n: int, hot: set[int], hop_s: int = 30) -> list:
    return [fv(src, hop_s * (i + 1), req_rate=5.0 if i in hot else 0.1) for i in range(n)]


def test_rates_use_tumbling_windows_and_report_every_unit():
    a = _user("10.77.20.45", 10, hot={0, 1})  # 2/10 windows flagged
    b = _user("10.77.20.46", 10, hot=set())
    r = detector_rates(a + b, _model(1.0))
    assert r["n_windows"] == 20 and r["rate"] == 0.1
    assert r["users"] == {"n": 2, "with_any_flag": 1, "median_rate": 0.1, "max_rate": 0.2}
    assert r["requests"] == {"n": 240, "in_flagged_windows": 24, "rate": 0.1}
    assert r["ci95"][0] <= 0.1 <= r["ci95"][1]


def test_overlapping_windows_are_not_counted_twice():
    # 30 s windows every 5 s: only every 6th window is non-overlapping
    hopped = [fv("10.77.20.47", 5 * (i + 1), req_rate=5.0) for i in range(60)]
    r = detector_rates(hopped, _model(1.0))
    assert r["n_windows"] == 10
    assert r["requests"]["n"] == 10 * 12


def test_a_quiet_population_has_zero_rates_with_real_denominators():
    r = detector_rates(_user("10.77.20.48", 8, hot=set()), _model(1.0))
    assert r["rate"] == 0.0 and r["users"]["with_any_flag"] == 0
    assert r["requests"]["n"] == 96 and r["requests"]["rate"] == 0.0


@pytest.mark.parametrize("threshold", [0.05, 10.0])
def test_threshold_is_the_stored_one(threshold):
    r = detector_rates(_user("10.77.20.49", 4, hot={0}), _model(threshold))
    assert r["rate"] == (1.0 if threshold < 0.1 else 0.0)


def test_benign_request_impact_counts_each_request_once_at_its_own_time():
    from datetime import timedelta
    from ipaddress import IPv4Address
    from types import SimpleNamespace

    from conftest import T0

    from afw.ml.datasets import Role
    from afw.ml.experiments import _benign_request_impact, _SourceTrack

    ip = IPv4Address("10.77.20.50")
    obs = [SimpleNamespace(client_ip=ip, observed_at=T0 + timedelta(seconds=s)) for s in range(10)]
    labels = SimpleNamespace(role_at=lambda _ip, _t: Role.BENIGN)
    track = _SourceTrack(contained=[(T0 + timedelta(seconds=3), T0 + timedelta(seconds=6))])
    assert _benign_request_impact(obs, {ip: track}, labels) == (10, 3)  # seconds 3, 4, 5
    assert _benign_request_impact(obs, {}, labels) == (10, 0)


class ByFeature:
    def __init__(self, name: str | None) -> None:
        self.j = FEATURE_NAMES.index(name) if name else None

    def score(self, x: np.ndarray) -> np.ndarray:
        return x[:, self.j] if self.j is not None else np.zeros(len(x))


def test_matched_probe_sensitivity_finds_a_blind_new_model():
    from afw.ml.benign_generalization import matched_probe_sensitivity

    prof = _profile()
    ws = _user("10.77.20.51", 6, hot=set())
    rec = _record(prof).model_copy(update={"threshold": 0.5})
    ref = [LoadedModel(record=rec, detector=ByFeature("auth_fail_frac"))]
    blind = [LoadedModel(record=rec, detector=ByFeature(None))]
    r = matched_probe_sensitivity((prof, ref, ws), (prof, blind, ws))
    d = r["detectors"]["half_space_trees"]
    assert r["aligned_windows"] == 6 and d["matched_bases"] == 6
    assert d["per_feature"]["auth_fail_frac"] == {"reference": 1.0, "new": 0.0}
    assert d["per_feature"]["login_rate"] == {"reference": 0.0, "new": 0.0}
