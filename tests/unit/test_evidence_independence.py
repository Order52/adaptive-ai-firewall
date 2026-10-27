"""Evidence independence (ADR-027): one event stream must not count twice.

Failed logins produce AUTH evidence *and* move the auth-derived behaviour
features (login_rate, auth_fail_frac, distinct_usernames, 401s in
client_err_frac). A behaviour detection counts as independent corroboration
only if the detector is still anomalous with those features occluded.
"""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address

import numpy as np
import pytest
from conftest import T0

from afw.correlation.engine import CorrelationEngine
from afw.domain.detection import DetectorKind
from afw.domain.features import FEATURE_NAMES, FeatureVector, WindowSpec
from afw.domain.policy import PolicyKind
from afw.domain.profiles import BehaviorProfile, FeatureStats, ProfileProvenance, ProfileStatus
from afw.domain.risk import EVIDENCE_FEATURES, EvidenceCategory
from afw.ml.detectors.robust import RobustStatsDetector
from afw.ml.inference import InferenceEngine, LoadedModel
from afw.policy.decision import DecisionEngine

BENIGN = {
    "req_rate": 0.4,
    "route_count": 4.0,
    "route_entropy": 1.8,
    "unknown_route_frac": 0.0,
    "novel_method_frac": 0.0,
    "write_frac": 0.1,
    "client_err_frac": 0.02,
    "server_err_frac": 0.0,
    "login_rate": 0.5,
    "auth_fail_frac": 0.0,
    "distinct_usernames": 1.0,
    "req_bytes_p95": 400.0,
    "interarrival_cv": 1.0,
}


def _profile() -> BehaviorProfile:
    feats = {
        n: FeatureStats(
            median=v,
            mad=max(v * 0.2, 0.01),
            q01=v * 0.5,
            q05=v * 0.6,
            q95=v * 1.4 + 0.1,
            q99=v * 1.5 + 0.1,
            mean=v,
            std=0.1,
        )
        for n, v in BENIGN.items()
    }
    return BehaviorProfile(
        profile_id="prof-unit",
        app_id="rental",
        version=1,
        status=ProfileStatus.TRUSTED,
        created_at=T0,
        window=WindowSpec(),
        features=feats,
        endpoints=(),
        provenance=ProfileProvenance(
            dataset_ids=("unit",),
            n_windows=100,
            n_sources=5,
            max_source_share=0.2,
            app_versions=("1.0.0",),
        ),
        content_hash="unit",
    )


def _engine() -> InferenceEngine:
    from afw.domain.detection import ModelMetrics, ModelRecord, ModelStatus

    prof = _profile()
    det = RobustStatsDetector(prof)
    rec = ModelRecord(
        model_id="m1",
        app_id="rental",
        detector=DetectorKind.ROBUST_STATS,
        version="robust-test",
        profile_version=1,
        status=ModelStatus.ACTIVE,
        created_at=T0,
        params={},
        threshold=4.0,
        feature_names=FEATURE_NAMES,
        train_dataset_ids=("unit",),
        validation_dataset_ids=("unit-val",),
        artifact_sha256="0" * 64,
        artifact_path="-",
        validation_metrics=ModelMetrics(),
        benign_score_quantiles=tuple(float(i) / 25 for i in range(101)),
    )
    eng = InferenceEngine()
    eng.load(prof, [LoadedModel(record=rec, detector=det)])
    return eng


def _fv(evidence: dict[str, float], **overrides: float) -> FeatureVector:
    values = {**BENIGN, **overrides}
    return FeatureVector(
        app_id="rental",
        source_ip=IPv4Address("10.77.10.23"),
        window_start=T0,
        window_end=T0 + timedelta(seconds=30),
        n_requests=60,
        values=values,
        evidence=evidence,
        request_ids=("r1",),
        app_versions=("1.0.0",),
    )


AUTH_ATTACK = {"auth_failures": 40.0, "login_attempts": 40.0}
WAF_ATTACK = {"waf_signal_requests": 8.0, "waf_blocked": 8.0, "crs_sqli": 8.0}


def test_mapping_covers_known_features_only():
    for cat, feats in EVIDENCE_FEATURES.items():
        assert feats <= set(FEATURE_NAMES), cat
    # 401s (failed logins) and 403s (WAF blocks) both land in client_err_frac
    assert "client_err_frac" in EVIDENCE_FEATURES[EvidenceCategory.AUTH]
    assert "client_err_frac" in EVIDENCE_FEATURES[EvidenceCategory.WAF]


def test_auth_only_anomaly_is_not_independent_of_auth_evidence(lab_cfg):
    # Anomalous *only* in auth-derived features: the same failed logins.
    fv = _fv(
        AUTH_ATTACK,
        login_rate=60.0,
        auth_fail_frac=1.0,
        distinct_usernames=30.0,
        client_err_frac=0.9,
    )
    dets = _engine().score(fv)
    assert dets and dets[0].is_anomalous
    assert "auth" not in dets[0].independent_of
    ra = CorrelationEngine(lab_cfg.risk).assess(fv, dets, fv.window_end)
    assert set(ra.corroborating_categories) == {EvidenceCategory.AUTH}
    assert EvidenceCategory.BEHAVIOR_ML in ra.discounted_categories
    intent = DecisionEngine(lab_cfg).decide(ra, 0, fv.window_end)
    assert intent is None or intent.kind is not PolicyKind.SOURCE_BLOCK


def test_independent_behaviour_still_corroborates_auth(lab_cfg):
    # Same auth failures, plus a request-volume/shape anomaly that the
    # detector flags even with every auth-derived feature occluded.
    fv = _fv(
        AUTH_ATTACK,
        login_rate=60.0,
        auth_fail_frac=1.0,
        distinct_usernames=30.0,
        client_err_frac=0.9,
        req_rate=40.0,
        req_bytes_p95=9000.0,
    )
    dets = _engine().score(fv)
    assert "auth" in dets[0].independent_of
    ra = CorrelationEngine(lab_cfg.risk).assess(fv, dets, fv.window_end)
    assert {EvidenceCategory.AUTH, EvidenceCategory.BEHAVIOR_ML} <= set(ra.corroborating_categories)
    assert ra.discounted_categories == ()


def test_waf_403s_do_not_double_count_as_behaviour(lab_cfg):
    fv = _fv(WAF_ATTACK, client_err_frac=1.0)
    dets = _engine().score(fv)
    assert dets[0].is_anomalous
    assert "waf" not in dets[0].independent_of
    ra = CorrelationEngine(lab_cfg.risk).assess(fv, dets, fv.window_end)
    assert set(ra.corroborating_categories) == {EvidenceCategory.WAF}


@pytest.mark.parametrize("present", [("auth",), ("waf",), ("auth", "waf")])
def test_residual_check_occludes_exactly_the_dependent_features(present):
    prof = _profile()
    det = RobustStatsDetector(prof)
    row = np.array([BENIGN[n] for n in FEATURE_NAMES])
    row[FEATURE_NAMES.index("client_err_frac")] = 1.0  # shared by auth and waf
    feats = set().union(*(EVIDENCE_FEATURES[EvidenceCategory(p)] for p in present))
    assert det.score(row[None, :])[0] >= 4.0
    assert not det.anomalous_without(row, feats, 4.0)
