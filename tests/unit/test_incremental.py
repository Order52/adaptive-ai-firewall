"""Incremental classifier: verified delayed labels, predict-before-learn, poisoning and
forgetting guards, checkpoints and the champion lifecycle. SYNTHETIC feature windows."""

from __future__ import annotations

import dataclasses
import datetime as dt
import random
from ipaddress import IPv4Address

import pytest
from conftest import T0

from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml import incremental as inc
from afw.ml.supervised import BENIGN, UNKNOWN, KnownThreatVerdict, LabelledWindow

CENTRES = {BENIGN: 1.0, "bruteforce": 20.0, "scan": 60.0}


def fv(i: int, family: str, rng: random.Random, src: int | None = None) -> FeatureVector:
    c = CENTRES[family]
    end = T0 + dt.timedelta(seconds=5 * i)
    return FeatureVector(
        app_id="rental",
        source_ip=IPv4Address(f"10.77.20.{src if src is not None else 100 + i % 50}"),
        window_start=end - dt.timedelta(seconds=30),
        window_end=end,
        n_requests=10,
        values={n: c + rng.gauss(0, 1) for n in FEATURE_NAMES},
    )


def stream(n: int, seed: int = 0, ds: str = "syn-a", families=tuple(CENTRES)):
    rng = random.Random(seed)
    return [
        inc.StreamItem(fv(i, f, rng), f, ds)
        for i in range(n)
        for f in [families[i % len(families)]]
    ]


def labelled(items, ds=None):
    return [LabelledWindow(s.fv, s.family, ds or s.dataset_id, True) for s in items]


def test_predictions_come_before_labels():
    # a delay longer than the stream: nothing is learnt while predicting, so every
    # verdict abstains; the labels are learnt only at the end
    rep, _ = inc.prequential(stream(300), label_delay_s=10_000)
    assert sum(c for (_, p), c in rep.predicted.items() if p != UNKNOWN) == 0
    assert rep.learnt == 300


def test_learns_separable_families_prequentially():
    rep, cps = inc.prequential(stream(1500), label_delay_s=60, checkpoint_every=300)
    d = rep.as_dict()["per_family"]
    assert d["bruteforce"]["recall"] > 0.9 and d["scan"]["recall"] > 0.9
    assert d[BENIGN]["fpr"] < 0.02
    assert len(cps) == 5 and rep.replays > 0


@pytest.mark.parametrize("prov", ["model:arf", "anomaly:hst", "", "network_novelty:x"])
def test_untrusted_labels_are_refused(prov):
    items = stream(30)
    bad = [inc.VerifiedLabel(inc.window_id(s.fv), "scan", prov, s.fv.window_end) for s in items]
    rep, _ = inc.prequential(items, label_delay_s=10, extra_labels=bad)
    assert rep.refused["untrusted_provenance"] == 30


def test_labels_for_unseen_windows_and_conflicts():
    items = stream(30)
    ghost = inc.VerifiedLabel(
        "rental|10.77.20.9|2020-01-01T00:00:00+00:00", "scan", "operator:x", T0
    )
    flip = [
        inc.VerifiedLabel(
            inc.window_id(s.fv),
            "scan" if s.family == BENIGN else BENIGN,
            "operator:x",
            s.fv.window_end + dt.timedelta(seconds=1),
        )
        for s in items
    ]
    rep, _ = inc.prequential(items, label_delay_s=10, extra_labels=[ghost, *flip])
    assert rep.refused["unknown_window"] == 1
    # the operator's contradicting label came first; the manifest's then conflicts
    assert rep.refused["conflicting_label"] == 30
    assert rep.learnt == 30


def test_source_rate_cap():
    rng = random.Random(1)
    items = [inc.StreamItem(fv(i, BENIGN, rng, src=7), BENIGN, "syn") for i in range(200)]
    rep, _ = inc.prequential(items, label_delay_s=1, guard=inc.LabelGuard(per_source_per_hour=50))
    assert rep.learnt == 50 and rep.refused["source_rate_cap"] == 150


def test_rehearsal_keeps_earlier_families_in_the_stream():
    r = inc.Rehearsal(per_family=3, seed=0)
    rng = random.Random(0)
    for i in range(10):
        r.add(fv(i, "scan", rng), "scan")
    assert len(r.buf["scan"]) == 3
    assert [f for _, f in r.replays(BENIGN)] == ["scan"]


def test_checkpoints_are_integrity_checked():
    _, cps = inc.prequential(stream(600), label_delay_s=5, checkpoint_every=300)
    clf = cps[0].load()
    assert isinstance(clf, inc.IncrementalThreatClassifier)
    bad = dataclasses.replace(cps[0], blob=cps[1].blob)
    with pytest.raises(ValueError):
        bad.load()


# ------------------------------------------------------------ lifecycle
def trained(n: int, seed: int) -> inc.IncrementalThreatClassifier:
    _, cps = inc.prequential(stream(n, seed), label_delay_s=5, checkpoint_every=n)
    return cps[-1].load()


class Noisy:
    """A champion that calls every window an attack."""

    def predict(self, fvs):
        return [KnownThreatVerdict("scan", 0.99) for _ in fvs]


def test_gate_needs_independent_data_and_promotion_needs_a_human():
    lc = inc.ClassifierLifecycle()
    lc.propose(trained(900, 0), "c1", ["syn-a"])
    with pytest.raises(ValueError):
        lc.gate(labelled(stream(90, 5)))  # syn-a again
    g = lc.gate(labelled(stream(300, 7), "syn-b"))
    assert g.passed, g.reasons
    with pytest.raises(PermissionError):
        lc.promote(g, approved_by="")
    lc.promote(g, approved_by="operator")
    assert lc.stage is inc.Stage.PROBATION and not lc.enforcing


def test_gate_refuses_a_challenger_with_false_alerts():
    lc = inc.ClassifierLifecycle()
    lc.propose(Noisy(), "noisy", ["syn-a"])
    g = lc.gate(labelled(stream(300, 7), "syn-b"))
    assert not g.passed and "benign fpr" in g.reasons[0]
    with pytest.raises(PermissionError):
        lc.promote(g, approved_by="operator")


def test_probation_rolls_back_on_false_alerts_and_passes_when_clean():
    lc = inc.ClassifierLifecycle(probation_min_windows=100)
    lc.champion, lc.champion_id = trained(600, 1), "old"
    lc.propose(trained(900, 0), "new", ["syn-a"])
    lc.promote(lc.gate(labelled(stream(300, 7), "syn-b")), approved_by="operator")
    lc.observe_benign([KnownThreatVerdict("scan", 0.9)] * 20)
    assert lc.stage is inc.Stage.ROLLED_BACK and lc.champion_id == "old"
    lc.propose(trained(900, 2), "newer", ["syn-a"])
    lc.promote(lc.gate(labelled(stream(300, 8), "syn-c")), approved_by="operator")
    lc.observe_benign([KnownThreatVerdict(BENIGN, 0.9)] * 100)
    assert lc.stage is inc.Stage.CHAMPION and lc.champion_id == "newer"
    assert [h["event"] for h in lc.history].count("rolled_back") == 1
