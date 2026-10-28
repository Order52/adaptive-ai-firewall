"""Behaviour-only evidence and the `behavior_only_rate_limit` switch (P6 amendment A2)."""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest
from conftest import T0

from afw.domain.policy import PolicyKind, RateProfile
from afw.domain.risk import EvidenceCategory, EvidenceItem, RiskAssessment, RiskBand
from afw.policy.decision import DecisionEngine

ML, STAT, AUTH = EvidenceCategory.BEHAVIOR_ML, EvidenceCategory.BEHAVIOR_STAT, EvidenceCategory.AUTH


def ra(items: list[tuple[EvidenceCategory, float]], corroborating, discounted=()):
    ev = tuple(EvidenceItem(category=c, code=f"{c.value}_x", points=p, detail="") for c, p in items)
    return RiskAssessment(
        assessment_id="risk-1",
        app_id="rental",
        source_ip=IPv4Address("10.77.20.150"),
        assessed_at=T0,
        window_end=T0,
        score=min(100.0, sum(p for _, p in items)),
        band=RiskBand.ELEVATED,
        evidence=ev,
        corroborating_categories=tuple(corroborating),
        model_version=None,
        profile_version=2,
        discounted_categories=tuple(discounted),
    )


def engine(lab_cfg, on: bool) -> DecisionEngine:
    cfg = lab_cfg.model_copy(
        update={"safety": lab_cfg.safety.model_copy(update={"behavior_only_rate_limit": on})}
    )
    return DecisionEngine(cfg)


AGREE = [(STAT, 20.0), (ML, 30.0)]  # 50: above rate_limit (45), both detectors anomalous


def test_default_keeps_the_existing_behaviour(lab_cfg):
    assert lab_cfg.safety.behavior_only_rate_limit is True
    it = engine(lab_cfg, True).decide(ra(AGREE, [ML]), 0, T0)
    assert it is not None and it.kind is PolicyKind.RATE_LIMIT
    assert it.rate_profile is RateProfile.MODERATE


def test_off_makes_behaviour_only_evidence_observe_only(lab_cfg):
    it = engine(lab_cfg, False).decide(ra(AGREE, [ML]), 0, T0)
    assert it is not None and it.kind is PolicyKind.WATCH
    assert "anomaly_only_observe" in it.reason_codes


@pytest.mark.parametrize("on", [True, False])
def test_switch_never_weakens_non_behavioural_paths(lab_cfg, on):
    # pure brute force (ADR-039): AUTH plus dependent behaviour points -> rate limit either way
    it = engine(lab_cfg, on).decide(ra([(AUTH, 20.0), *AGREE], [AUTH], [ML]), 0, T0)
    assert it is not None and it.kind is PolicyKind.RATE_LIMIT
    # two independent categories above the block level -> block either way
    it = engine(lab_cfg, on).decide(ra([(AUTH, 30.0), (ML, 35.0)], [AUTH, ML]), 0, T0)
    assert it is not None and it.kind is PolicyKind.SOURCE_BLOCK
