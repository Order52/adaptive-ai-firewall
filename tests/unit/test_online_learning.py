"""M2 acceptance: online shadow challenger (ADR-028).

Each test maps to an acceptance criterion in
docs/engineering/M2_ONLINE_LEARNING_DESIGN.md §8.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import random
import time
from collections import Counter
from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path

import numpy as np
import pytest
from conftest import T0
from test_evidence_independence import BENIGN, _profile

from afw.config import OnlineLearningConfig
from afw.domain.detection import (
    DetectionResult,
    DetectorKind,
    FeatureContribution,
    ModelMetrics,
    ModelRecord,
    ModelStatus,
)
from afw.domain.events import Provenance
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.learning import Exclusion
from afw.domain.risk import EvidenceCategory, EvidenceItem, RiskAssessment, RiskBand
from afw.ml.detectors.hst import HalfSpaceTreesDetector
from afw.ml.inference import LoadedModel
from afw.ml.online import CheckpointStore, OnlineChallenger
from afw.persistence.db import make_engine, upgrade
from afw.persistence.repositories import SqlLearningRepository
from afw.profiling.eligibility import StageOne
from afw.services.shadow import ShadowLearner


class NullAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def record(self, actor, action, subject, detail=None) -> None:
        self.events.append((action, subject))


W = 40  # HST window size used in these tests (pivot every W learns)
SHIFT = {"req_rate": 1.6, "route_count": 9.0, "route_entropy": 3.1, "write_frac": 0.3}
_ids = itertools.count()


# ------------------------------------------------------------------ fixtures
def rows(rng: random.Random, base: dict[str, float], n: int) -> np.ndarray:
    out = []
    for _ in range(n):
        out.append([max(0.0, base[f] * rng.uniform(0.85, 1.15)) for f in FEATURE_NAMES])
    return np.array(out)


def fv(
    src: str,
    end_s: float,
    base: dict[str, float] | None = None,
    rng: random.Random | None = None,
    *,
    untrusted: float = 0.0,
    unjoined: float = 0.0,
    **override: float,
) -> FeatureVector:
    rng = rng or random.Random(int(end_s * 7) + int(IPv4Address(src)))
    base = {**(base or BENIGN)}
    values = {f: max(0.0, base[f] * rng.uniform(0.9, 1.1)) for f in FEATURE_NAMES}
    for k in ("auth_fail_frac", "client_err_frac"):
        values[k] = min(values[k], BENIGN[k])
    values.update(override)
    end = T0 + timedelta(seconds=end_s)
    return FeatureVector(
        app_id="rental",
        source_ip=IPv4Address(src),
        window_start=end - timedelta(seconds=30),
        window_end=end,
        n_requests=12,
        values=values,
        evidence={"untrusted_obs": untrusted, "unjoined_obs": unjoined},
        request_ids=tuple(f"r{next(_ids)}" for _ in range(3)),
        app_versions=("1.0.0",),
    )


def ra_for(
    v: FeatureVector, *, evidence: tuple[EvidenceItem, ...] = (), anomalous: tuple[str, ...] = ()
) -> RiskAssessment:
    dets = ()
    if anomalous:
        dets = (
            DetectionResult(
                detection_id="d",
                detector=DetectorKind.ISOLATION_FOREST,
                model_version="m",
                profile_version=1,
                app_id="rental",
                source_ip=v.source_ip,
                window_end=v.window_end,
                n_requests=v.n_requests,
                score=1.0,
                threshold=0.5,
                is_anomalous=True,
                benign_percentile=100,
                contributions=tuple(
                    FeatureContribution(
                        feature=f,
                        value=1,
                        baseline_median=0,
                        baseline_q99=0,
                        robust_z=9,
                        score_delta=0.1,
                    )
                    for f in anomalous
                ),
            ),
        )
    return RiskAssessment(
        assessment_id="ra",
        app_id="rental",
        source_ip=v.source_ip,
        assessed_at=v.window_end,
        window_end=v.window_end,
        score=0.0,
        band=RiskBand.NONE,
        evidence=evidence,
        corroborating_categories=(),
        model_version=None,
        profile_version=1,
        detections=dets,
    )


WAF_HIT = EvidenceItem(category=EvidenceCategory.WAF, code="crs_blocked", points=20, detail="x")


@pytest.fixture
def champion() -> LoadedModel:
    prof = _profile()
    det = HalfSpaceTreesDetector(prof, window_size=W, seed=7)
    det.fit(rows(random.Random(1), BENIGN, 4 * W))
    blob_sha = hashlib.sha256(OnlineChallenger(det, _record(prof)).blob()).hexdigest()
    rec = _record(prof).model_copy(update={"artifact_sha256": blob_sha})
    thr = float(np.quantile(det.score(rows(random.Random(2), BENIGN, 200)), 0.99))
    return LoadedModel(record=rec.model_copy(update={"threshold": thr}), detector=det)


def _record(prof) -> ModelRecord:
    return ModelRecord(
        model_id="mdl-champion-hst",
        app_id="rental",
        detector=DetectorKind.HALF_SPACE_TREES,
        version="hst-test",
        profile_version=prof.version,
        status=ModelStatus.ACTIVE,
        created_at=T0,
        params={},
        threshold=0.5,
        feature_names=FEATURE_NAMES,
        train_dataset_ids=("unit",),
        validation_dataset_ids=("unit-val",),
        artifact_sha256="0" * 64,
        artifact_path="-",
        validation_metrics=ModelMetrics(),
        benign_score_quantiles=tuple(float(i) / 100 for i in range(101)),
    )


class Env:
    def __init__(self, lab_cfg, tmp: Path, champion: LoadedModel, **learning) -> None:
        defaults = {
            "admission_delay_s": 60,
            "min_source_tenure_s": 0,
            "max_windows_per_source_per_hour": 1000,
            "max_source_share": 0.5,
            "share_window": 400,
            "min_distinct_sources": 1,
            "checkpoint_every": 10_000,
            "checkpoint_interval_s": 10**6,
        }
        self.cfg = lab_cfg.model_copy(
            update={"learning": OnlineLearningConfig(**{**defaults, **learning})}
        )
        url = f"sqlite:///{tmp / 'afw.sqlite3'}"
        upgrade(url)
        self.repo = SqlLearningRepository(make_engine(url))
        self.tmp = tmp
        self.champion = champion
        self.policed: set[IPv4Address] = set()
        self.reported: set[IPv4Address] = set()
        self.learner = self.new_learner()

    def new_learner(self) -> ShadowLearner:
        sl = ShadowLearner(
            self.cfg,
            self.repo,
            CheckpointStore(self.tmp / "challengers", self.repo, keep=3),
            NullAudit(),
            policed=lambda ip: ip in self.policed,
            reported=lambda app: set(self.reported),
            clock=lambda: T0,
        )
        sl.reload(_profile(), self.champion)
        return sl

    def feed(self, items, release_after_s: float = 61) -> None:
        last = T0
        for v, ra in items:
            self.learner.submit(v, ra)
            last = max(last, v.window_end)
        self.learner.process(last)
        self.learner.process(last + timedelta(seconds=release_after_s))


@pytest.fixture
def env(lab_cfg, tmp_path, champion):
    return Env(lab_cfg, tmp_path, champion)


def tumbling(src: str, n: int, start_s: float = 0, base=None, step: float = 30):
    rng = random.Random(int(IPv4Address(src)) + int(start_s))
    out = []
    for i in range(n):
        v = fv(src, start_s + step * (i + 1), base, rng)
        out.append((v, ra_for(v)))
    return out


# ------------------------------------------- 1-3: learning, prediction, prequential
def test_learning_changes_state_and_never_touches_champion(champion):
    champ_blob = OnlineChallenger(champion.detector, champion.record).blob()
    ch = OnlineChallenger.from_champion(champion.detector, champion.record)
    before = ch.state()
    v = fv("10.77.20.11", 30)
    ch.score_then_learn(v)
    after = ch.state()
    assert after["n_learned"] == before["n_learned"] + 1
    assert after["counter"] == (before["counter"] + 1) % W
    assert after["l_mass_total"] > before["l_mass_total"]
    assert OnlineChallenger(champion.detector, champion.record).blob() == champ_blob


def test_score_is_taken_before_learning(champion):
    ch = OnlineChallenger.from_champion(champion.detector, champion.record)
    v = fv("10.77.20.11", 30)
    expected = ch.score(v)
    before, warm = ch.score_then_learn(v)
    assert before == expected and warm


def test_predictions_change_at_pivot_toward_learned_pattern(champion):
    """After a full window of a (legitimate) shifted pattern the challenger scores
    that pattern as more normal than the frozen champion does. Before the pivot,
    predictions are unchanged (River HST scores from the reference mass)."""
    ch = OnlineChallenger.from_champion(champion.detector, champion.record)
    shifted = {**BENIGN, **SHIFT}
    probe = [fv("10.77.20.40", 9000 + 30 * i, shifted) for i in range(30)]
    champ = np.array([ch.score(p) for p in probe])
    for i in range(W - 1):
        ch.score_then_learn(fv("10.77.20.41", 30 * (i + 1), shifted))
    mid = np.array([ch.score(p) for p in probe])
    assert np.allclose(mid, champ)  # no pivot yet: predictions unchanged, state changed
    ch.score_then_learn(fv("10.77.20.41", 30 * W, shifted))  # completes the window
    post = np.array([ch.score(p) for p in probe])
    assert post.mean() < champ.mean() - 0.05, (champ.mean(), post.mean())


def test_cold_model_is_flagged_not_trusted():
    prof = _profile()
    cold = HalfSpaceTreesDetector(prof, window_size=W, seed=7)
    ch = OnlineChallenger(cold, _record(prof))
    assert not ch.warm
    assert ch.score(fv("10.77.20.11", 30)) == 0.0  # River's cold-start "normal"


# ---------------------------------------------------------- 4: stage-1 exclusions
@pytest.mark.parametrize(
    ("kwargs", "src", "expected"),
    [
        ({"untrusted": 1}, "10.77.20.11", Exclusion.UNVERIFIED),
        ({"unjoined": 1}, "10.77.20.11", Exclusion.UNJOINED),
        ({"write_frac": 1.5}, "10.77.20.11", Exclusion.MALFORMED),
        ({"req_rate": float("nan")}, "10.77.20.11", Exclusion.MALFORMED),
        ({}, "10.77.20.250", Exclusion.PROTECTED),  # probe source (protected)
        ({"auth_fail_frac": 0.9}, "10.77.20.11", Exclusion.SENSITIVE_RANGE),
    ],
)
def test_stage_one_exclusions(lab_cfg, kwargs, src, expected):
    gate = StageOne.build((p.network for p in lab_cfg.safety.protected), ())
    v = fv(src, 30, **kwargs)
    got = gate.check(
        v, ra_for(v), _profile(), watermark=None, candidate_end=None, tainted=False, learned=False
    )
    assert got is expected


def test_negative_evidence_excludes_and_taints(env):
    v = fv("10.77.20.11", 30)
    env.feed([(v, ra_for(v, evidence=(WAF_HIT,)))])
    assert env.learner.excluded["negative_evidence"] == 1
    later = fv("10.77.20.11", 300)
    env.feed([(later, ra_for(later))])
    assert env.learner.excluded["tainted"] == 1
    assert env.learner.challenger.n_learned == 0


def test_missing_provenance_fields_count_as_untrusted(lab_cfg):
    gate = StageOne.build((), ())
    v = fv("10.77.20.11", 30).model_copy(update={"evidence": {}})
    assert (
        gate.check(
            v,
            ra_for(v),
            _profile(),
            watermark=None,
            candidate_end=None,
            tainted=False,
            learned=False,
        )
        is Exclusion.UNVERIFIED
    )


# ---------------------------------------------- 5: overlap, duplicates, replay
def test_overlapping_windows_are_learned_at_most_once(env):
    rng = random.Random(3)
    items = []
    for k in range(12):  # sliding windows: 30 s long, 5 s hop -> heavy overlap
        v = fv("10.77.20.11", 30 + 5 * k, rng=rng)
        items.append((v, ra_for(v)))
    env.feed(items)
    assert env.learner.challenger.n_learned == 2  # t=30 and t=60 are disjoint
    assert env.learner.excluded["overlap"] == 10


def test_replayed_window_after_restart_is_not_relearned(env):
    items = tumbling("10.77.20.11", 5) + tumbling("10.77.20.12", 5)
    env.feed(items)
    env.learner.checkpoint_now(T0 + timedelta(hours=1))
    n = env.learner.challenger.n_learned
    assert n == 10
    restarted = env.new_learner()
    restarted.submit(*items[2])  # exact replay of a learned window
    restarted.process(T0 + timedelta(hours=2))
    assert restarted.excluded["duplicate"] == 1
    assert restarted.challenger.n_learned == n


# ------------------------------------------------------- 6: poisoning controls
def test_single_source_flood_is_capped(lab_cfg, tmp_path, champion):
    env = Env(lab_cfg, tmp_path, champion, max_windows_per_source_per_hour=5)
    env.feed(tumbling("10.77.10.66", 60, step=30))
    assert env.learner.challenger.n_learned == 5
    assert env.learner.excluded["source_rate"] >= 50


def test_per_source_rate_cap_holds_with_many_sources(lab_cfg, tmp_path, champion):
    """Regression (P4, found live 2026-10-28): the hourly per-source cap was counted
    over the share-window deque, so with more sources than share_window / cap the
    oldest admissions fell out and every source exceeded its cap."""
    env = Env(
        lab_cfg,
        tmp_path,
        champion,
        max_windows_per_source_per_hour=5,
        share_window=20,
        max_source_share=1.0,
    )
    srcs = [f"10.77.20.{i}" for i in range(100, 110)]
    env.feed([item for i in range(20) for item in (tumbling(s, 20)[i] for s in srcs)])
    per = Counter(str(w.source_ip) for w in env.learner.unflushed)
    assert set(per) == set(srcs) and max(per.values()) == 5, per


def test_per_source_rate_cap_survives_a_restart(lab_cfg, tmp_path, champion):
    env = Env(lab_cfg, tmp_path, champion, max_windows_per_source_per_hour=5)
    first = tumbling("10.77.20.120", 10)
    env.feed(first[:5])
    env.learner.checkpoint_now(first[4][0].window_end + timedelta(seconds=61))
    restarted = env.new_learner()
    for v, ra in first[5:]:
        restarted.submit(v, ra)
    restarted.process(first[-1][0].window_end)
    restarted.process(first[-1][0].window_end + timedelta(seconds=61))
    assert restarted.challenger.n_learned == 5
    assert restarted.excluded["source_rate"] == 5


def test_share_cap_bounds_one_source_influence(lab_cfg, tmp_path, champion):
    env = Env(lab_cfg, tmp_path, champion, share_window=20, max_source_share=0.25)
    env.feed(tumbling("10.77.10.66", 40) + tumbling("10.77.20.11", 3))
    learned = [w.source_ip for w in env.learner.unflushed]
    assert learned.count(IPv4Address("10.77.10.66")) == 5  # ceil(0.25 * 20)
    assert env.learner.excluded["source_share"] > 0


def test_concentrated_anomalous_pattern_never_learned(lab_cfg, tmp_path, champion):
    """Gradual poisoning from two sources: novel behaviour flagged by the trusted
    detectors, no WAF/IDS evidence. Fewer than anomaly_min_sources -> never learned."""
    env = Env(lab_cfg, tmp_path, champion)
    shifted = {**BENIGN, **SHIFT}
    items = []
    for src in ("10.77.10.66", "10.77.10.67"):
        for v, _ in tumbling(src, 20, base=shifted):
            items.append((v, ra_for(v, anomalous=("req_rate", "route_count"))))
    env.feed(items, release_after_s=61)
    env.learner.process(T0 + timedelta(hours=3))  # hold expiry passes
    assert env.learner.challenger.n_learned == 0
    assert env.learner.excluded["champion_anomalous"] == 40


def test_benign_drift_cannot_vouch_for_poison_sharing_a_driver_name(lab_cfg, tmp_path, champion):
    """M4 finding (real-data experiment B): corroboration by shared anomaly-driver
    *names* let 4 legitimately drifting sources vouch for poison from 2 sources.
    Corroboration must require behavioural similarity."""
    env = Env(lab_cfg, tmp_path, champion)
    shifted = {**BENIGN, **SHIFT}
    poison = {**BENIGN, "route_count": 9.0, "unknown_route_frac": 0.6, "novel_method_frac": 0.3}
    items = []
    for src in ("10.77.20.21", "10.77.20.22", "10.77.20.23", "10.77.20.24"):
        for v, _ in tumbling(src, 10, base=shifted):
            items.append((v, ra_for(v, anomalous=("req_rate", "route_count"))))
    for src in ("10.77.10.66", "10.77.10.67"):
        for v, _ in tumbling(src, 10, base=poison):
            items.append((v, ra_for(v, anomalous=("route_count", "unknown_route_frac"))))
    env.feed(items)
    env.learner.process(T0 + timedelta(hours=3))  # hold expiry passes
    learned = {w.source_ip for w in env.learner.unflushed}
    assert IPv4Address("10.77.10.66") not in learned and IPv4Address("10.77.10.67") not in learned
    assert env.learner.challenger.n_learned == 40  # the legitimate drift is still learned
    assert env.learner.excluded["champion_anomalous"] == 20


def test_population_level_legitimate_change_is_eventually_learned(lab_cfg, tmp_path, champion):
    env = Env(lab_cfg, tmp_path, champion)
    shifted = {**BENIGN, **SHIFT}
    items = []
    for src in ("10.77.20.21", "10.77.20.22", "10.77.20.23", "10.77.20.24"):
        for v, _ in tumbling(src, 10, base=shifted):
            items.append((v, ra_for(v, anomalous=("req_rate", "route_count"))))
    env.feed(items)
    assert env.learner.challenger.n_learned == 40
    assert env.learner.counts["learned_anomalous_corroborated"] == 40


def test_late_evidence_during_quarantine_disqualifies(env):
    items = tumbling("10.77.20.11", 3)
    for v, ra in items:
        env.learner.submit(v, ra)
    env.learner.process(T0 + timedelta(seconds=85))  # quarantined, none due yet (first: 90 s)
    assert len(env.learner.quarantine) == 3
    env.policed.add(IPv4Address("10.77.20.11"))  # e.g. rate-limited meanwhile
    env.learner.process(T0 + timedelta(seconds=400))
    assert env.learner.challenger.n_learned == 0
    assert env.learner.excluded["late_taint"] == 3


def test_tenure_and_population_requirements(lab_cfg, tmp_path, champion):
    env = Env(lab_cfg, tmp_path, champion, min_source_tenure_s=600, min_distinct_sources=2)
    env.feed(tumbling("10.77.20.11", 30))  # first 600 s fail tenure; the rest are alone
    assert env.learner.excluded["tenure"] == 20
    assert env.learner.challenger.n_learned == 0
    assert len(env.learner.quarantine) == 10  # held for population, not dropped
    env.feed(tumbling("10.77.20.12", 50, start_s=1000))  # a second tenured source appears
    learned = {w.source_ip for w in env.learner.unflushed}
    assert learned == {IPv4Address("10.77.20.11"), IPv4Address("10.77.20.12")}


# ---------------------------------------------- 7: persistence and recovery
def test_restart_restores_exact_state(env):
    env.feed(tumbling("10.77.20.11", 6) + tumbling("10.77.20.12", 6))
    ck = env.learner.checkpoint_now(T0 + timedelta(hours=1))
    blob = env.learner.challenger.blob()
    marks = dict(env.learner.watermarks)
    restarted = env.new_learner()
    assert restarted.checkpoint.checkpoint_id == ck.checkpoint_id
    assert restarted.challenger.n_learned == 12
    assert restarted.challenger.blob() == blob
    assert restarted.watermarks == marks
    assert len(env.repo.learned("rental")) == 12  # ledger consistent with checkpoint


def test_crash_between_checkpoints_rolls_back_consistently(env):
    env.feed(tumbling("10.77.20.11", 4))
    env.learner.checkpoint_now(T0 + timedelta(hours=1))
    env.feed(tumbling("10.77.20.12", 4, start_s=500))  # learned, never checkpointed
    assert env.learner.challenger.n_learned == 8
    crashed = env.new_learner()  # process died: no stop(), no checkpoint
    assert crashed.challenger.n_learned == 4
    assert len(env.repo.learned("rental")) == 4


def test_corrupt_checkpoint_falls_back_to_previous(env):
    env.feed(tumbling("10.77.20.11", 3))
    first = env.learner.checkpoint_now(T0 + timedelta(hours=1))
    env.feed(tumbling("10.77.20.12", 3, start_s=500))
    second = env.learner.checkpoint_now(T0 + timedelta(hours=2))
    p = Path(second.artifact_path)
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    p.write_bytes(bytes(raw))
    restarted = env.new_learner()
    assert restarted.checkpoint.checkpoint_id == first.checkpoint_id
    assert restarted.challenger.n_learned == 3
    statuses = {c.checkpoint_id: c.status.value for c in env.repo.checkpoints("rental")}
    assert statuses[second.checkpoint_id] == "corrupt"


def test_all_checkpoints_bad_or_foreign_starts_fresh_from_champion(env, champion):
    env.feed(tumbling("10.77.20.11", 3))
    ck = env.learner.checkpoint_now(T0 + timedelta(hours=1))
    Path(ck.artifact_path).unlink()
    restarted = env.new_learner()
    assert restarted.checkpoint is None and restarted.challenger.n_learned == 0
    # a checkpoint descending from another champion is never loaded
    env.feed(tumbling("10.77.20.12", 3, start_s=900))
    env.learner.checkpoint_now(T0 + timedelta(hours=3))
    other = LoadedModel(
        record=champion.record.model_copy(update={"model_id": "mdl-other"}),
        detector=champion.detector,
    )
    env.champion = other
    assert env.new_learner().challenger.n_learned == 0


def test_checkpoint_files_are_pruned_and_written_atomically(env):
    for k in range(5):
        env.feed(tumbling(f"10.77.20.{30 + k}", 2, start_s=1000 * k))
        env.learner.checkpoint_now(T0 + timedelta(hours=k + 1))
    files = sorted((env.tmp / "challengers" / "rental").iterdir())
    assert len(files) == 3  # keep=3, no temp files left behind
    assert not any(f.name.startswith(".") for f in files)


# --------------------------------------------------- 8-9: isolation, resources
def run_bruteforce(settings, learning: bool) -> list[tuple[str, str, str]]:
    """The closed-loop brute-force scenario; returns (kind, target, final state)."""
    import sys

    from conftest import ROOT, FakeClock
    from fixtures.synthetic import traffic

    sys.path.insert(0, str(ROOT / "tests" / "integration"))
    from test_closed_loop import ATTACKER, manifest
    from test_closed_loop import BENIGN as USERS

    from afw.container import build_container
    from afw.domain.policy import OperatingMode
    from afw.ml.datasets import Purpose

    c = build_container(settings, simulated=True)
    # Permissive learning so the "on" run really learns during the scenario.
    lc = c.cfg.learning.model_copy(
        update={
            "enabled": learning,
            "admission_delay_s": 0,
            "min_source_tenure_s": 0,
            "min_distinct_sources": 1,
            "max_source_share": 1.0,
        }
    )
    c.controller.shadow.lc = lc
    clock = FakeClock(T0 + timedelta(days=1))
    c.policy_service.clock = clock
    c.controller.clock = clock
    tr = traffic(1, T0, 1800, USERS)
    va = traffic(2, T0 + timedelta(hours=2), 900, USERS, attack={ATTACKER: "bruteforce"})
    c.datasets.write(manifest("syn-train", Purpose.TRAIN, tr, USERS), tr)
    c.datasets.write(manifest("syn-val", Purpose.VALIDATION, va, USERS, [ATTACKER]), va)
    res = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"])
    c.learning.promote("rental", res.profile.version, "reviewer", "baseline")
    assert c.controller.reload()
    c.settings_repo.set_mode(OperatingMode.AUTO, "test")
    c.policy_service.reconcile()
    t = clock()
    for o in traffic(9, clock(), 300, USERS, attack={ATTACKER: "bruteforce"}):
        while o.observed_at > t:
            c.controller.tick(t)
            c.controller.shadow.process(t)
            t += timedelta(seconds=1)
            clock.now = t
        # curated + joined: eligible provenance, so the learner can actually learn
        c.controller.ingest_observations(
            [o.model_copy(update={"provenance": Provenance.CURATED, "app_joined": True})]
        )
    c.controller.tick(t)
    c.controller.shadow.process(t + timedelta(seconds=1))
    if learning:
        assert c.controller.shadow.challenger.n_learned > 0  # it really learned
    return sorted(
        (p.kind.value, str(p.intent.target.source_ip), p.state.value)
        for p in c.policies_repo.recent(500)
    )


def test_enforcement_outcomes_identical_with_learner_on_or_off(tmp_path):
    from conftest import ROOT

    from afw.config import Settings

    def s(name):
        return Settings(config=ROOT / "config" / "lab.yaml", data_dir=tmp_path / name)

    on = run_bruteforce(s("on"), learning=True)
    off = run_bruteforce(s("off"), learning=False)
    assert on, "scenario must produce policies"
    assert on == off


def test_resource_cost_is_bounded(env):
    items = []
    for k in range(8):
        items += tumbling(f"10.77.20.{40 + k}", 25)
    t0 = time.perf_counter()
    env.feed(items)
    per_window_ms = (time.perf_counter() - t0) * 1000 / len(items)
    ck = env.learner.checkpoint_now(T0 + timedelta(days=1))
    assert env.learner.challenger.n_learned == 200
    assert per_window_ms < 25, per_window_ms
    assert ck.size_bytes < 2_000_000, ck.size_bytes
    copy.deepcopy(env.learner.challenger)  # challenger is self-contained
