"""Offline M0/M1/M2 replay runner — SOFTWARE CORRECTNESS on synthetic data.

These assertions check the runner's *plumbing and invariants* (confusion-matrix
arithmetic, arm wiring, fair static baseline). The numbers here come from a
trivially separable synthetic fixture and are NOT experimental results; real
metrics require captured lab runs (see docs/AI_RESEARCH.md).
"""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address

import pytest
from conftest import T0, FakeClock
from fixtures.synthetic import traffic

from afw.container import build_container
from afw.ml.datasets import DatasetManifest, Purpose, Role, SourceLabel
from afw.ml.experiments import run_experiment

BENIGN = [f"10.77.20.{i}" for i in range(11, 21)]
ATTACKER = "10.77.10.23"


def _manifest(ds_id, purpose, obs, benign, attack=None):
    attack = attack or {}
    return DatasetManifest(
        dataset_id=ds_id,
        app_id="rental",
        purpose=purpose,
        scenario="synthetic-correctness",
        seed=1,
        start=obs[0].observed_at,
        end=obs[-1].observed_at,
        app_versions=("1.0.0",),
        sources=tuple(SourceLabel(ip=IPv4Address(i), role=Role.BENIGN) for i in benign)
        + tuple(
            SourceLabel(ip=IPv4Address(ip), role=Role.ATTACK, attack_type=kind)
            for ip, kind in attack.items()
        ),
        generator="tests/fixtures/synthetic.py",
    )


@pytest.fixture
def trained(settings):
    c = build_container(settings, simulated=True)
    c.learning.clock = FakeClock(T0 + timedelta(days=1))
    tr = traffic(1, T0, 1800, BENIGN)
    va = traffic(2, T0 + timedelta(hours=2), 900, BENIGN, attack={ATTACKER: "bruteforce"})
    c.datasets.write(_manifest("syn-train", Purpose.TRAIN, tr, BENIGN), tr)
    c.datasets.write(
        _manifest("syn-val", Purpose.VALIDATION, va, BENIGN, {ATTACKER: "bruteforce"}), va
    )
    result = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"])
    c.learning.promote("rental", result.profile.version, "reviewer", "baseline")
    loaded = c.learning.load_active("rental")
    assert loaded is not None
    return c, loaded


def test_replay_arms_and_confusion_invariants(trained):
    c, (profile, models) = trained
    test_obs = traffic(7, T0 + timedelta(hours=4), 900, BENIGN, attack={ATTACKER: "bruteforce"})
    man = _manifest("syn-test", Purpose.TEST, test_obs, BENIGN, {ATTACKER: "bruteforce"})
    c.datasets.write(man, test_obs)

    report = run_experiment(
        cfg=c.cfg,
        profile=profile,
        models=models,
        manifest=man,
        observations=test_obs,
    )

    assert [a.arm for a in report.arms] == ["M0", "M1", "M2"]
    assert report.fp_budget > 0
    assert report.n_observations == len(test_obs)

    by_arm = {a.arm: a for a in report.arms}
    for a in report.arms:
        # confusion matrix is internally consistent
        assert a.tp + a.fn == a.n_attack_windows
        assert a.fp + a.tn == a.n_benign_windows
        assert a.n_attack_windows > 0 and a.n_benign_windows > 0
        # all three arms replay the identical labeled stream
        assert a.n_attack_windows == by_arm["M0"].n_attack_windows
        assert a.n_benign_windows == by_arm["M0"].n_benign_windows

    # M0 proposes no adaptive action and times no detectors.
    assert by_arm["M0"].decisions == {}
    assert by_arm["M0"].mean_score_latency_us is None
    # M1/M2 actually score; latency is recorded.
    assert by_arm["M2"].mean_score_latency_us is not None

    # Brute force carries no CRS signature, so the static WAF cannot contain it;
    # the behavioural arms must do strictly better at catching the attacker.
    assert report.waf_inline_contained_attack_sources == 0
    assert by_arm["M0"].attack_sources_contained == 0
    assert by_arm["M2"].attack_sources_contained == 1
    assert by_arm["M2"].recall is not None and by_arm["M2"].recall > 0

    # Legitimate traffic must stay essentially unaffected under the ML arm.
    assert by_arm["M2"].benign_sources_flagged == 0
    assert by_arm["M2"].legit_request_success == 1.0
    # Requests are counted once each, not once per overlapping window (P1).
    n_benign = sum(1 for o in test_obs if str(o.client_ip) in BENIGN)
    assert all(a.benign_requests == n_benign for a in report.arms)

    # A contained attacker gets a finite detection latency recorded.
    assert ATTACKER in by_arm["M2"].detection_latency_s
    assert by_arm["M2"].median_detection_latency_s is not None
    # The silent M0 is exposed to strictly more attack traffic than M2, which
    # contains the attacker and would drop the rest.
    assert by_arm["M2"].attack_requests_exposed < by_arm["M0"].attack_requests_exposed

    # Flat per-arm rows match the dashboard's experiments contract exactly.
    rows = report.arm_rows()
    assert len(rows) == 3
    required = {
        "strategy",
        "scenario",
        "datasets",
        "precision",
        "recall",
        "fpr",
        "attack_sources_blocked",
        "benign_sources_restricted",
        "median_first_attack_to_block_s",
        "attack_requests_exposed",
        "notes",
    }
    for row in rows:
        assert required <= set(row)


def test_report_is_json_serializable_and_persistable(trained):
    c, (profile, models) = trained
    test_obs = traffic(9, T0 + timedelta(hours=6), 600, BENIGN)
    man = _manifest("syn-benign-only", Purpose.TEST, test_obs, BENIGN)
    c.datasets.write(man, test_obs)

    report = run_experiment(
        cfg=c.cfg, profile=profile, models=models, manifest=man, observations=test_obs
    )
    # No attack windows => recall is honestly None, not a fabricated number.
    for a in report.arms:
        assert a.n_attack_windows == 0
        assert a.recall is None
    # Persists the flat per-arm rows (dashboard contract) and reads back.
    for row in report.arm_rows():
        c.experiments.add("replay", row)
    stored = c.experiments.list("replay")
    assert len(stored) == 3
    assert {r["strategy"].split()[0] for r in stored} == {"M0", "M1", "M2"}
    assert all(r["datasets"] == ["syn-benign-only"] for r in stored)
