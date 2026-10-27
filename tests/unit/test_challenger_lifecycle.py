"""M3 acceptance: challenger promotion gate, human promotion, probation, rollback (ADR-030).

Synthetic feature vectors only: these tests prove the *mechanism* (what the
gate refuses, what promotion and rollback change). They are not detection
results and are never cited as such.
"""

from __future__ import annotations

import itertools
import random
from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path

import numpy as np
import pytest
from conftest import T0
from test_evidence_independence import BENIGN, _profile
from test_online_learning import SHIFT, NullAudit, W, _record, fv, rows

from afw.config import PromotionConfig
from afw.domain.detection import DetectionResult, DetectorKind, ModelStatus
from afw.domain.learning import LearnedWindow, ProbationStatus
from afw.ml.challenger_gate import Holdout, evaluate_challenger, tumbling
from afw.ml.detectors.hst import HalfSpaceTreesDetector
from afw.ml.inference import LoadedModel
from afw.ml.online import CheckpointStore, OnlineChallenger, fingerprint
from afw.ml.registry import ArtifactStore
from afw.persistence.db import make_engine, upgrade
from afw.persistence.repositories import SqlLearningRepository, SqlModelRepository
from afw.services.challenger import ChallengerLifecycle, PromotionRefused

DRIFT = {**BENIGN, **SHIFT}  # a legitimate application change
ATTACK = {**BENIGN, "req_rate": 9.0, "login_rate": 6.0, "route_count": 1.0, "route_entropy": 0.0}
PC = PromotionConfig(min_holdout_windows=20, probation_min_windows=20)


def _champion_detector() -> HalfSpaceTreesDetector:
    det = HalfSpaceTreesDetector(_profile(), window_size=W, seed=7)
    det.fit(rows(random.Random(1), BENIGN, 4 * W))
    return det


def _threshold(det: HalfSpaceTreesDetector) -> float:
    return float(np.quantile(det.score(rows(random.Random(2), BENIGN, 200)), 0.99))


def _windows(base, srcs, n, start_s):
    out = []
    for src in srcs:
        rng = random.Random(int(IPv4Address(src)) + int(start_s))
        out += [fv(src, start_s + 30 * (i + 1), base, rng) for i in range(n)]
    return out


def _learn(ch: OnlineChallenger, windows) -> list[LearnedWindow]:
    out = []
    for v in windows:
        before, warm = ch.score_then_learn(v)
        out.append(
            LearnedWindow(
                fingerprint=fingerprint(v),
                app_id="rental",
                source_ip=v.source_ip,
                window_start=v.window_start,
                window_end=v.window_end,
                learned_at=v.window_end,
                challenger_score_before=before,
                champion_score=before,
                challenger_warm_before=warm,
                n_learned_after=ch.n_learned,
                parent_model_id=ch.parent.model_id,
            )
        )
    return out


LEARN_SRCS = ("10.77.20.11", "10.77.20.12", "10.77.20.13", "10.77.20.14")
HOLD_SRCS = ("10.77.20.21", "10.77.20.22", "10.77.20.23")


def _holdout(attack: bool = True, synthetic: bool = False, n: int = 20) -> Holdout:
    benign = _windows(DRIFT, HOLD_SRCS, n, 20_000)
    atk = _windows(ATTACK, ("10.77.10.66",), 30, 20_000) if attack else []
    end = T0 + timedelta(seconds=20_000 + 30 * (n + 1))
    spans = tuple((IPv4Address(s), T0 + timedelta(seconds=20_000), end) for s in HOLD_SRCS)
    return Holdout(
        benign=benign,
        attack=atk,
        benign_dataset_ids=("hold-benign",),
        attack_dataset_ids=("hold-attack",) if attack else (),
        synthetic_attack=synthetic,
        spans=spans,
    )


@pytest.fixture
def adapted():
    """Champion + a challenger that learned one full reference window of drift."""
    det = _champion_detector()
    rec = _record(_profile()).model_copy(update={"threshold": _threshold(det)})
    champion = LoadedModel(record=rec, detector=det)
    ch = OnlineChallenger.from_champion(det, rec)
    lineage = _learn(ch, _windows(DRIFT, LEARN_SRCS, W // len(LEARN_SRCS), 0))
    assert ch.n_learned == W
    return champion, ch, lineage


def _gate(adapted, **kw):
    champion, ch, lineage = adapted
    args = {
        "champion": champion,
        "challenger": ch,
        "profile": _profile(),
        "holdout": _holdout(),
        "lineage": lineage,
        "tainted": set(),
        "pc": PC,
    }
    return evaluate_challenger(**{**args, **kw})


def _by_name(res):
    return {c.name: c for c in res.checks}


# ---------------------------------------------------------------- the gate
def test_gate_passes_adapted_challenger_and_reports_the_benefit(adapted):
    res = _gate(adapted)
    checks = _by_name(res)
    assert all(c.passed for c in res.checks), [c for c in res.checks if not c.passed]
    # the drifted (legitimate) pattern: challenger has fewer false alarms than the champion
    assert res.metrics["challenger_fpr"] < res.metrics["champion_fpr"]
    assert checks["attack_recall_regression"].value >= checks["attack_recall_regression"].limit
    assert len(res.benign_quantiles) == 101


def test_gate_fails_without_attack_evidence(adapted):
    chk = _by_name(_gate(adapted, holdout=_holdout(attack=False)))["attack_recall_regression"]
    assert not chk.passed and "no labelled attack" in chk.detail


def test_gate_refuses_synthetic_attack_evidence(adapted):
    chk = _by_name(_gate(adapted, holdout=_holdout(synthetic=True)))["attack_recall_regression"]
    assert not chk.passed and "synthetic" in chk.detail


def test_gate_requires_a_full_reference_window(adapted):
    champion, _, _ = adapted
    young = OnlineChallenger.from_champion(champion.detector, champion.record)
    lineage = _learn(young, _windows(DRIFT, LEARN_SRCS, 2, 0))
    chk = _by_name(_gate(adapted, challenger=young, lineage=lineage))["min_learning"]
    assert not chk.passed and chk.value == 8 and chk.limit == W


def test_gate_detects_holdout_leakage(adapted):
    _, ch, lineage = adapted
    leak = _learn(ch, _windows(DRIFT, (HOLD_SRCS[0],), 1, 20_000))
    chk = _by_name(_gate(adapted, lineage=[*lineage, *leak]))["holdout_not_learned"]
    assert not chk.passed and chk.value == 1


def test_gate_fails_when_a_learned_source_is_tainted_later(adapted):
    chk = _by_name(_gate(adapted, tainted={IPv4Address(LEARN_SRCS[2])}))["ledger_clean"]
    assert not chk.passed and LEARN_SRCS[2] in chk.detail


def test_gate_refuses_a_small_holdout(adapted):
    res = _gate(adapted, holdout=_holdout(n=5))
    assert not _by_name(res)["holdout_size"].passed
    assert "benign_fpr_not_worse" not in _by_name(res)  # nothing computed on too little data


def test_holdout_windows_are_non_overlapping():
    w = [fv("10.77.20.30", 5 * i + 30) for i in range(60)]  # 30 s windows, 5 s hop
    t = tumbling(w)
    assert len(t) == 10
    assert all(b.window_start >= a.window_end for a, b in itertools.pairwise(t))


def test_gate_catches_a_challenger_poisoned_toward_attack_like_behaviour(adapted):
    """A challenger that learned windows with attack-like sensitive features (what the
    eligibility gate exists to prevent) loses sensitivity and must fail the gate."""
    champion, _, _ = adapted
    poisoned = OnlineChallenger.from_champion(champion.detector, champion.record)
    bad = {**DRIFT, "auth_fail_frac": 0.9, "login_rate": 6.0, "distinct_usernames": 8.0}
    lineage = _learn(poisoned, _windows(bad, LEARN_SRCS, 2 * W // len(LEARN_SRCS), 0))
    res = _gate(adapted, challenger=poisoned, lineage=lineage)
    failed = {c.name for c in res.checks if not c.passed}
    assert "sensitive_invariance" in failed, res.checks


# --------------------------------------------------- promotion / rollback
class FakeLearning:
    """load_active reflects the model registry, like LearningService.load_active."""

    def __init__(self, models: SqlModelRepository, artifacts: ArtifactStore) -> None:
        self.models, self.artifacts = models, artifacts

    def load_active(self, app_id):
        return _profile(), [
            LoadedModel(record=r, detector=self.artifacts.load(r))
            for r in self.models.active(app_id)
        ]

    def catalog(self, app_id, profile):
        return None


class Env:
    def __init__(self, tmp: Path, lab_cfg) -> None:
        url = f"sqlite:///{tmp / 'afw.sqlite3'}"
        upgrade(url)
        engine = make_engine(url)
        self.models = SqlModelRepository(engine)
        self.repo = SqlLearningRepository(engine)
        self.artifacts = ArtifactStore(tmp / "models")
        self.store = CheckpointStore(tmp / "challengers", self.repo, keep=3)
        self.audit = NullAudit()
        self.now = T0 + timedelta(days=1)
        self.fps = 0
        det = _champion_detector()
        path, sha, _ = self.artifacts.save("rental", "mdl-champion-hst", det)
        self.parent = _record(_profile()).model_copy(
            update={"threshold": _threshold(det), "artifact_path": path, "artifact_sha256": sha}
        )
        self.models.save(self.parent)
        ch = OnlineChallenger.from_champion(det, self.parent)
        learned = _learn(ch, _windows(DRIFT, LEARN_SRCS, W // len(LEARN_SRCS), 0))
        self.store.save(ch, app_id="rental", watermarks={}, learned=learned, now=self.now)
        self.cfg = lab_cfg.model_copy(update={"promotion": PC})
        self.lc = self.lifecycle()

    def lifecycle(self) -> ChallengerLifecycle:
        lc = ChallengerLifecycle(
            self.cfg,
            FakeLearning(self.models, self.artifacts),  # type: ignore[arg-type]
            self.repo,
            self.store,
            self.models,
            self.artifacts,
            None,  # type: ignore[arg-type]
            self.audit,
            false_positives=lambda app, since: self.fps,
            clock=lambda: self.now,
        )
        lc._holdout = lambda app_id, b, a, cat: _holdout(attack=bool(a))  # type: ignore[method-assign]
        return lc

    def active_hst(self):
        return self.models.active("rental", DetectorKind.HALF_SPACE_TREES.value)

    def evaluate(self, attack=True):
        return self.lc.evaluate("rental", ["hold-benign"], ["hold-attack"] if attack else [], "t")

    def actions(self):
        return [a for a, _ in self.audit.events]


@pytest.fixture
def env(tmp_path, lab_cfg):
    return Env(tmp_path, lab_cfg)


def _hst(env: Env, anomalous: bool) -> DetectionResult:
    return DetectionResult(
        detection_id="d",
        detector=DetectorKind.HALF_SPACE_TREES,
        model_version="x",
        profile_version=1,
        app_id="rental",
        source_ip=IPv4Address("10.77.20.11"),
        window_end=env.now,
        n_requests=10,
        score=0.9 if anomalous else 0.1,
        threshold=0.5,
        is_anomalous=anomalous,
        benign_percentile=50,
    )


def test_passing_evaluation_freezes_a_candidate_but_never_promotes_it(env):
    ev = env.evaluate()
    assert ev.passed and ev.candidate_model_id
    cand = env.models.get(ev.candidate_model_id)
    assert cand.status is ModelStatus.CANDIDATE and cand.threshold == ev.threshold
    assert cand.params["parent_model_id"] == env.parent.model_id
    assert [m.model_id for m in env.active_hst()] == [env.parent.model_id]  # unchanged


def test_failed_evaluation_registers_nothing_and_cannot_be_promoted(env):
    ev = env.evaluate(attack=False)
    assert not ev.passed and ev.candidate_model_id == ""
    with pytest.raises(PromotionRefused, match="attack_recall_regression"):
        env.lc.promote("rental", ev.evaluation_id, "admin", "try")
    assert [m.model_id for m in env.active_hst()] == [env.parent.model_id]


def test_human_promotion_activates_exactly_the_evaluated_snapshot(env):
    ev = env.evaluate()
    rec = env.lc.promote("rental", ev.evaluation_id, "admin", "reviewed")
    assert [m.model_id for m in env.active_hst()] == [rec.model_id]
    assert env.models.get(env.parent.model_id).status is ModelStatus.RETIRED
    _, loaded = FakeLearning(env.models, env.artifacts).load_active("rental")
    assert loaded[0].record.threshold == ev.threshold
    (p,) = env.repo.probations("rental", active_only=True)
    assert p.model_id == rec.model_id and p.parent_model_id == env.parent.model_id
    assert "challenger.promote" in env.actions()


def test_promotion_refused_when_stale_or_champion_changed_or_artifact_tampered(env):
    ev = env.evaluate()
    env.now += timedelta(seconds=PC.max_evaluation_age_s + 1)
    with pytest.raises(PromotionRefused, match="stale"):
        env.lc.promote("rental", ev.evaluation_id, "admin", "late")
    ev = env.evaluate()
    Path(env.models.get(ev.candidate_model_id).artifact_path).write_bytes(b"tampered")
    with pytest.raises(PromotionRefused, match="artifact rejected"):
        env.lc.promote("rental", ev.evaluation_id, "admin", "tampered")
    ev = env.evaluate()
    env.models.set_status(env.parent.model_id, ModelStatus.RETIRED)
    with pytest.raises(PromotionRefused, match="champion changed"):
        env.lc.promote("rental", ev.evaluation_id, "admin", "moved")


def test_probation_breach_rolls_back_automatically(env):
    rec = env.lc.promote("rental", env.evaluate().evaluation_id, "admin", "ok")
    for _ in range(PC.probation_min_windows):
        env.lc.observe("rental", [_hst(env, anomalous=True)])
    assert env.lc.check("rental", env.now) is True
    assert [m.model_id for m in env.active_hst()] == [env.parent.model_id]
    assert env.models.get(rec.model_id).status is ModelStatus.REJECTED  # never re-activated
    (p,) = env.repo.probations("rental")
    assert p.status is ProbationStatus.ROLLED_BACK and "anomalous rate" in p.reason
    assert "challenger.auto_rollback" in env.actions()


def test_operator_false_positive_reports_roll_back(env):
    env.lc.promote("rental", env.evaluate().evaluation_id, "admin", "ok")
    env.fps = PC.probation_max_false_positives
    assert env.lc.check("rental", env.now) is True
    assert [m.model_id for m in env.active_hst()] == [env.parent.model_id]


def test_quiet_probation_passes_and_manual_rollback_remains_possible(env):
    rec = env.lc.promote("rental", env.evaluate().evaluation_id, "admin", "ok")
    for _ in range(PC.probation_min_windows):
        env.lc.observe("rental", [_hst(env, anomalous=False)])
    assert env.lc.check("rental", env.now + timedelta(seconds=PC.probation_s)) is False
    assert env.repo.probations("rental")[0].status is ProbationStatus.PASSED
    assert [m.model_id for m in env.active_hst()] == [rec.model_id]
    env.lc.rollback("rental", "admin", "operator decision")
    assert [m.model_id for m in env.active_hst()] == [env.parent.model_id]
    assert env.models.get(rec.model_id).status is ModelStatus.RETIRED


def test_probation_counts_survive_restart(env):
    env.lc.promote("rental", env.evaluate().evaluation_id, "admin", "ok")
    for _ in range(7):
        env.lc.observe("rental", [_hst(env, anomalous=True)])
    env.lc.check("rental", env.now)  # persists
    restarted = env.lifecycle()
    restarted.observe("rental", [_hst(env, anomalous=False)])
    p = restarted._probation("rental")
    assert (p.windows, p.anomalous) == (8, 7)


def test_second_promotion_refused_during_probation(env):
    first, second = env.evaluate(), env.evaluate()
    env.lc.promote("rental", first.evaluation_id, "admin", "ok")
    with pytest.raises(PromotionRefused, match="still on probation"):
        env.lc.promote("rental", second.evaluation_id, "admin", "again")


def test_rollback_refused_when_active_model_was_not_promoted(env):
    with pytest.raises(PromotionRefused, match="not a promoted challenger"):
        env.lc.rollback("rental", "admin", "nothing to undo")


def test_controller_reloads_when_probation_rolls_back(settings, monkeypatch):
    from afw.container import build_container

    c = build_container(settings, simulated=True)
    assert c.controller.lifecycle is c.challenger
    reloads: list[bool] = []
    monkeypatch.setattr(c.challenger, "check", lambda app_id, now: True)
    monkeypatch.setattr(c.controller, "reload", lambda: reloads.append(True) or True)
    c.controller.tick(T0)
    assert reloads == [True]
