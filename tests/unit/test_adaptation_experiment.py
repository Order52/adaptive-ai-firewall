"""M4 experiment building blocks (synthetic inputs; mechanism only, not results)."""

from __future__ import annotations

import random
from ipaddress import IPv4Address

import numpy as np
import pytest
from test_evidence_independence import BENIGN, _profile
from test_online_learning import W, _record, fv, rows

from afw.ml.adaptation_experiment import POISON_KINDS, _regression, poison_windows, source_ci
from afw.ml.detectors.hst import HalfSpaceTreesDetector
from afw.ml.inference import LoadedModel
from afw.ml.online import malformed
from afw.profiling.eligibility import SENSITIVE


def test_source_ci_resamples_sources_not_windows():
    ws = [fv("10.77.20.11", 30 * i + 30) for i in range(10)]
    ws += [fv("10.77.20.12", 30 * i + 30) for i in range(10)]
    flags = np.array([True] * 10 + [False] * 10)
    r = source_ci(ws, flags, seed=1)
    assert r["rate"] == 0.5 and r["n_sources"] == 2 and r["n_windows"] == 20
    lo, hi = r["ci95"]
    assert lo == 0.0 and hi == 1.0  # two sources that disagree: the CI is honest about it
    assert r["per_source"] == {"10.77.20.11": 1.0, "10.77.20.12": 0.0}


@pytest.mark.parametrize("kind", POISON_KINDS)
def test_poison_stays_inside_sensitive_ranges_and_is_labelled(kind):
    prof = _profile()
    template = [fv("10.77.20.11", 30 * i + 30) for i in range(20)]
    poison = poison_windows(template, prof, ["10.77.20.91", "10.77.20.92"], seed=3, kind=kind)
    assert len(poison) == 2 * 20
    for p in poison:
        assert p.request_ids[0].startswith("poison-")
        for name in SENSITIVE:
            assert p.values[name] <= prof.features[name].q99
        assert malformed(p) is None
        if kind == "detectable":
            assert p.values["unknown_route_frac"] > 0.5
    assert {p.source_ip for p in poison} == {IPv4Address("10.77.20.91"), IPv4Address("10.77.20.92")}


def test_injected_regression_is_rolled_back_by_probation(lab_cfg):
    det = HalfSpaceTreesDetector(_profile(), window_size=W, seed=7)
    det.fit(rows(random.Random(1), BENIGN, 4 * W))
    hst = LoadedModel(
        record=_record(_profile()).model_copy(update={"threshold": 0.9}), detector=det
    )
    hold = [fv(f"10.77.20.{11 + i % 4}", 30 * i + 30) for i in range(400)]
    cfg = lab_cfg.model_copy(
        update={"promotion": lab_cfg.promotion.model_copy(update={"probation_min_windows": 50})}
    )
    r = _regression(cfg, hst, hold, [hst])
    assert r["rolled_back"] is True
    assert r["windows_until_rollback"] == 50
    assert r["regressed_status_after"] == "rejected"
    assert r["active_after"] == ["hst-test"]
    assert "challenger.auto_rollback" in r["audit"]
