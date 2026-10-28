"""Closed-loop AI pipeline on SYNTHETIC fixtures (functional test, not evaluation)."""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address

import pytest
from conftest import T0, FakeClock
from fixtures.synthetic import traffic

from afw.container import build_container
from afw.domain.policy import OperatingMode, PolicyKind, PolicyState
from afw.domain.profiles import ProfileStatus
from afw.ml.datasets import DatasetManifest, Purpose, Role, SourceLabel

BENIGN = [f"10.77.20.{i}" for i in range(11, 19)]
ATTACKER = "10.77.10.23"


def manifest(ds_id, purpose, obs, benign, attack=()):
    return DatasetManifest(
        dataset_id=ds_id,
        app_id="rental",
        purpose=purpose,
        scenario="synthetic-test",
        seed=1,
        start=obs[0].observed_at,
        end=obs[-1].observed_at,
        app_versions=("1.0.0",),
        sources=tuple(SourceLabel(ip=IPv4Address(i), role=Role.BENIGN) for i in benign)
        + tuple(
            SourceLabel(ip=IPv4Address(i), role=Role.ATTACK, attack_type="bruteforce")
            for i in attack
        ),
        generator="tests/fixtures/synthetic.py",
    )


@pytest.fixture
def trained(settings):
    c = build_container(settings, simulated=True)
    clock = FakeClock(T0 + timedelta(days=1))
    c.policy_service.clock = clock
    c.controller.clock = clock
    tr = traffic(1, T0, 1800, BENIGN)
    va = traffic(2, T0 + timedelta(hours=2), 900, BENIGN, attack={ATTACKER: "bruteforce"})
    c.datasets.write(manifest("syn-train", Purpose.TRAIN, tr, BENIGN), tr)
    c.datasets.write(manifest("syn-val", Purpose.VALIDATION, va, BENIGN, [ATTACKER]), va)
    result = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"])
    return c, clock, result


def test_bootstrap_trains_versioned_models_without_leakage(trained):
    c, _, result = trained
    assert result.profile.status is ProfileStatus.CANDIDATE
    assert {m.detector.value for m in result.models} == {
        "robust_stats",
        "isolation_forest",
        "half_space_trees",
    }
    for m in result.models:
        assert m.train_dataset_ids == ("syn-train",)
        assert m.validation_dataset_ids == ("syn-val",)
        assert m.validation_metrics.n_attack > 0
        assert len(m.benign_score_quantiles) == 101
    # Overlapping splits are refused
    with pytest.raises(ValueError, match="more than one split"):
        c.learning.bootstrap("rental", ["syn-train"], ["syn-train"])


def _run_live(c, clock, attack):
    live = traffic(9, clock(), 300, BENIGN, attack={ATTACKER: attack})
    t = clock()
    for o in live:
        while o.observed_at > t:
            c.controller.tick(t)
            t += timedelta(seconds=1)
            clock.now = t
        c.controller.ingest_observations([o])
    c.controller.tick(t)
    return c.policies_repo.recent(200)


def _auto(c, result):
    assert result.evaluation.passed, result.evaluation.checks
    c.learning.promote("rental", result.profile.version, "reviewer", "initial baseline")
    assert c.controller.reload()
    c.settings_repo.set_mode(OperatingMode.AUTO, "test")
    c.policy_service.reconcile()


def test_bruteforce_alone_is_rate_limited_not_blocked(trained):
    """Every attacker request is a failed login: once those requests are removed nothing
    is left, so the behaviour anomaly is the AUTH evidence again, not corroboration
    (ADR-027, SV-1). One category never authorizes a block."""
    c, clock, result = trained
    _auto(c, result)
    policies = _run_live(c, clock, "bruteforce")
    assert not [p for p in policies if p.kind is PolicyKind.SOURCE_BLOCK]
    limits = [
        p
        for p in policies
        if p.kind is PolicyKind.RATE_LIMIT and str(p.intent.target.source_ip) == ATTACKER
    ]
    assert limits
    for p in policies:
        if str(p.intent.target.source_ip) in BENIGN:
            assert p.kind is PolicyKind.WATCH


def test_end_to_end_bruteforce_is_blocked_and_legit_users_are_not(trained):
    """Brute force plus scraping from the same source: without the failed logins the
    window is still anomalous, so behaviour independently corroborates AUTH."""
    c, clock, result = trained
    _auto(c, result)
    policies = _run_live(c, clock, "bruteforce+scrape")
    blocks = [p for p in policies if p.kind is PolicyKind.SOURCE_BLOCK]
    assert blocks, "brute force should lead to a verified block"
    blocked_ips = {str(p.intent.target.source_ip) for p in blocks}
    assert blocked_ips == {ATTACKER}
    enforced = [p for p in blocks if any(h.to_state is PolicyState.ENFORCED for h in p.history)]
    assert enforced
    ra = c.analysis.get_assessment(enforced[0].intent.risk_assessment_id)
    cats = {str(e.category) for e in ra.evidence}
    assert "auth" in cats and ({"behavior_ml", "behavior_stat"} & cats)
    # No benign source got a traffic-affecting policy
    for p in policies:
        if str(p.intent.target.source_ip) in BENIGN:
            assert p.kind is PolicyKind.WATCH
