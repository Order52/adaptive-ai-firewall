"""N3/N4: supervised known-threat classifier (SYNTHETIC feature vectors, no traffic)."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import numpy as np
import pytest
from test_dataset_validation import T0, manifest

from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml.datasets import Role, SourceLabel
from afw.ml.supervised import (
    BENIGN,
    UNKNOWN,
    KnownThreatClassifier,
    evaluate,
    labelled_windows,
    split_by_dataset,
    wilson,
    withheld_family,
)

USER, BF, SCAN, INJ = (IPv4Address(f"10.77.{z}") for z in ("20.150", "10.21", "10.22", "10.23"))
SHAPES = {  # SYNTHETIC per-family feature centres
    BENIGN: {"req_rate": 0.3, "route_count": 6, "route_entropy": 2.0, "client_err_frac": 0.02},
    "bruteforce": {"req_rate": 2.0, "login_rate": 1.8, "auth_fail_frac": 0.95, "route_count": 1},
    "scan": {"req_rate": 3.0, "route_count": 40, "unknown_route_frac": 0.9, "client_err_frac": 0.9},
    "injection": {"req_rate": 0.8, "route_count": 3, "req_bytes_p95": 4000, "server_err_frac": 0.4},
}
SRC = {BENIGN: USER, "bruteforce": BF, "scan": SCAN, "injection": INJ}


def windows(ds: str, seed: int, families=tuple(SHAPES), n: int = 30):
    rng = np.random.default_rng(seed)
    vecs = []
    for fam in families:
        for i in range(n):
            start = T0 + dt.timedelta(seconds=60 * i)
            vals = {
                f: max(0.0, SHAPES[fam].get(f, 0.0) * rng.normal(1, 0.15)) for f in FEATURE_NAMES
            }
            vecs.append(
                FeatureVector(
                    app_id="rental",
                    source_ip=SRC[fam],
                    window_start=start,
                    window_end=start + dt.timedelta(seconds=60),
                    n_requests=20,
                    values=vals,
                )
            )
    labels = [SourceLabel(ip=USER, role=Role.BENIGN)] + [
        SourceLabel(ip=SRC[f], role=Role.ATTACK, attack_type=f) for f in families if f != BENIGN
    ]
    m = manifest(dataset_id=ds, sources=tuple(labels), generator="SYNTHETIC unit test")
    return labelled_windows(m, vecs, allow_synthetic=True)


ALL = windows("run-a", 1) + windows("run-b", 2) + windows("run-c", 3)


def test_synthetic_manifests_need_an_explicit_opt_in():
    with pytest.raises(ValueError, match="synthetic"):
        labelled_windows(manifest(generator="SYNTHETIC x"), [])


def test_unlabelled_and_family_less_windows_are_dropped():
    m = manifest(sources=(SourceLabel(ip=BF, role=Role.ATTACK),))  # no attack_type
    fv = ALL[40].fv.model_copy(update={"source_ip": BF})
    assert labelled_windows(m, [fv]) == []


def test_known_families_on_an_unseen_run():
    train, test = split_by_dataset(ALL, ["run-c"])
    clf = KnownThreatClassifier().fit(train)
    r = evaluate(clf, test).as_dict()
    assert r["SYNTHETIC"] is True and r["benign_windows"] == 30
    assert r["benign_fpr"] == 0.0
    for fam in ("bruteforce", "scan", "injection"):
        assert r["per_family"][fam]["recall"] >= 0.9


def test_evaluation_refuses_a_leaky_split():
    clf = KnownThreatClassifier().fit(ALL)
    with pytest.raises(ValueError, match="shares datasets"):
        evaluate(clf, ALL[:10])


def test_low_confidence_abstains_instead_of_guessing():
    train, _ = split_by_dataset(ALL, ["run-c"])
    clf = KnownThreatClassifier().fit(train)
    midway = ALL[0].fv.model_copy(
        update={
            "values": {
                f: (SHAPES["scan"].get(f, 0) + SHAPES["injection"].get(f, 0)) / 2
                for f in FEATURE_NAMES
            }
        }
    )
    v = clf.predict([midway])[0]
    assert v.family == UNKNOWN or v.confidence >= clf.min_confidence


def test_withheld_family_is_never_learnt_and_is_reported_honestly():
    r = withheld_family(ALL, "scan", ["run-c"])
    assert "scan" not in r["trained_families"] and r["windows"] == 30
    assert r["as_other_family"] + r["unknown"] + r["as_benign"] == pytest.approx(1.0)


def test_training_needs_enough_windows_per_family():
    with pytest.raises(ValueError, match="too few"):
        KnownThreatClassifier().fit(windows("tiny", 9, n=5))


def test_wilson_interval():
    lo, hi = wilson(0, 30)
    assert lo == 0.0 and 0.10 < hi < 0.13
    assert wilson(0, 0) == (0.0, 1.0)


def test_confirming_one_run_teaches_later_independent_runs():
    from afw.ml.supervised import learn_new_family

    r = learn_new_family(ALL, "scan", introduction=["run-b"], variants=["run-c"])
    assert r["SYNTHETIC"] is True and r["confirmed_windows"] == 30
    assert r["variants_named_before"] == 0.0  # frozen has no "scan" class at all
    assert r["variants_named_after"] >= 0.9
    assert r["benign_fpr_after"] <= r["benign_fpr_before"] + 0.01
    assert r["eligible"] is True and not r["known_family_regressions"]


def test_new_family_experiment_refuses_overlapping_runs():
    from afw.ml.supervised import learn_new_family

    with pytest.raises(ValueError, match="different datasets"):
        learn_new_family(ALL, "scan", introduction=["run-b"], variants=["run-b"])
