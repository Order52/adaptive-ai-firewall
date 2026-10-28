"""Use cases for profile/model learning, the evaluation gate and promotion."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import numpy as np

from afw.config import LabConfig
from afw.domain.adaptation import CandidateEvaluation, FeedbackLabel, GateCheck
from afw.domain.common import utcnow
from afw.domain.detection import DetectorKind, ModelRecord, ModelStatus
from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector
from afw.domain.profiles import BehaviorProfile, ProfileStatus
from afw.features.extract import EndpointCatalog
from afw.features.windows import replay_windows
from afw.ml.datasets import DatasetStore, LabelIndex, Purpose, Role, assert_disjoint
from afw.ml.evaluation import metrics
from afw.ml.inference import LoadedModel
from afw.ml.registry import ArtifactStore
from afw.ml.training import TrainingData, train_and_register
from afw.persistence.repositories import (
    SqlAdaptationRepository,
    SqlEventRepository,
    SqlModelRepository,
    SqlProfileRepository,
)
from afw.ports.repositories import AuditLog
from afw.profiling.builder import _endpoint_stats, build_profile

DEFAULT_KINDS = (
    DetectorKind.ROBUST_STATS,
    DetectorKind.ISOLATION_FOREST,
    DetectorKind.HALF_SPACE_TREES,
)
SENSITIVE_LIMITS = {"auth_fail_frac": 0.6, "client_err_frac": 0.5}


class GateFailed(ValueError):
    pass


@dataclass
class CandidateResult:
    profile: BehaviorProfile
    models: list[ModelRecord]
    evaluation: CandidateEvaluation


class LearningService:
    def __init__(
        self,
        cfg: LabConfig,
        profiles: SqlProfileRepository,
        models: SqlModelRepository,
        adaptation: SqlAdaptationRepository,
        events: SqlEventRepository,
        datasets: DatasetStore,
        artifacts: ArtifactStore,
        audit: AuditLog,
        clock: Callable[[], datetime] = utcnow,
        target_fpr: float = 0.01,
    ) -> None:
        self.cfg = cfg
        self.profiles = profiles
        self.models = models
        self.adaptation = adaptation
        self.events = events
        self.datasets = datasets
        self.artifacts = artifacts
        self.audit = audit
        self.clock = clock
        self.target_fpr = target_fpr

    # ---------------------------------------------------------------- helpers
    def catalog(self, app_id: str, profile: BehaviorProfile | None) -> EndpointCatalog:
        login = self.cfg.application(app_id).login_routes()
        if profile is None:
            return EndpointCatalog(frozenset(), frozenset(), login)
        return EndpointCatalog(profile.known_routes(), profile.known_methods(), login)

    def _catalog_from(
        self, app_id: str, obs: Sequence[HttpObservation], min_sources: int
    ) -> EndpointCatalog:
        eps = [e for e in _endpoint_stats(obs) if e.n_sources >= min_sources]
        return EndpointCatalog(
            frozenset(e.route for e in eps),
            frozenset((e.route, e.method) for e in eps),
            self.cfg.application(app_id).login_routes(),
        )

    def windows(
        self, obs: Sequence[HttpObservation], catalog: EndpointCatalog
    ) -> list[FeatureVector]:
        return list(replay_windows(obs, self.cfg.window, catalog))

    def _labeled(
        self, dataset_ids: Sequence[str], catalog: EndpointCatalog
    ) -> tuple[list[FeatureVector], list[FeatureVector]]:
        benign: list[FeatureVector] = []
        attack: list[FeatureVector] = []
        for ds in dataset_ids:
            labels = LabelIndex(self.datasets.manifest(ds))
            for v in self.windows(self.datasets.observations(ds), catalog):
                role = labels.label(v)
                if role is Role.BENIGN:
                    benign.append(v)
                elif role is Role.ATTACK:
                    attack.append(v)
        return benign, attack

    def _benign_observations(self, dataset_ids: Sequence[str]) -> list[HttpObservation]:
        out: list[HttpObservation] = []
        for ds in dataset_ids:
            m = self.datasets.manifest(ds)
            benign = {s.ip for s in m.sources if s.role is Role.BENIGN}
            out += [o for o in self.datasets.observations(ds) if o.client_ip in benign]
        return out

    # -------------------------------------------------------------- bootstrap
    def bootstrap(
        self, app_id: str, train_ids: Sequence[str], val_ids: Sequence[str], seed: int = 42
    ) -> CandidateResult:
        """Initial trusted-profile candidate from curated benign TRAIN runs."""
        assert_disjoint(train_ids, val_ids)
        for ds, purpose in [(d, Purpose.TRAIN) for d in train_ids] + [
            (d, Purpose.VALIDATION) for d in val_ids
        ]:
            got = self.datasets.manifest(ds).purpose
            if got is not purpose:
                raise ValueError(f"dataset {ds} has purpose {got}, expected {purpose}")
        obs = self._benign_observations(train_ids)
        catalog = self._catalog_from(app_id, obs, min_sources=2)
        train_vectors = self.windows(obs, catalog)
        now = self.clock()
        version = self.profiles.next_version(app_id)
        parent = self.profiles.trusted(app_id)
        profile = build_profile(
            app_id=app_id,
            version=version,
            parent_version=parent.version if parent else None,
            window=self.cfg.window,
            vectors=train_vectors,
            observations=obs,
            dataset_ids=train_ids,
            created_at=now,
        )
        val_benign, val_attack = self._labeled(val_ids, self.catalog(app_id, profile))
        records = train_and_register(
            profile=profile,
            data=TrainingData(
                train_benign=train_vectors,
                val_benign=val_benign,
                val_attack=val_attack,
                train_dataset_ids=tuple(train_ids),
                val_dataset_ids=tuple(val_ids),
            ),
            store=self.artifacts,
            kinds=DEFAULT_KINDS,
            target_fpr=self.target_fpr,
            created_at=now,
            seed=seed,
        )
        checks = [
            GateCheck(name="train_windows", passed=True, value=profile.provenance.n_windows),
            GateCheck(name="train_sources", passed=True, value=profile.provenance.n_sources),
            GateCheck(
                name="validation_benign_windows",
                passed=len(val_benign) >= 50,
                value=len(val_benign),
                limit=50,
            ),
        ]
        for r in records:
            m = r.validation_metrics
            checks.append(
                GateCheck(
                    name=f"{r.detector.value}_validation_fpr",
                    passed=(m.fpr or 0.0) <= self.target_fpr * 2,
                    value=m.fpr,
                    limit=self.target_fpr * 2,
                    detail=f"recall={m.recall} (reported, not tuned)",
                )
            )
        return self._persist(profile, records, checks, now)

    # ---------------------------------------------------- live candidate build
    def build_candidate(
        self,
        app_id: str,
        since: datetime,
        until: datetime,
        tainted: set[IPv4Address],
        attack_validation_ids: Sequence[str] = (),
        seed: int = 42,
    ) -> CandidateResult:
        trusted = self.profiles.trusted(app_id)
        if trusted is None:
            raise ValueError("no trusted profile to adapt from")
        obs = self.events.observations_between(app_id, since, until)
        excluded = self._excluded_sources(app_id, obs, tainted)
        clean = [o for o in obs if o.client_ip not in excluded]
        if not clean:
            raise GateFailed("no clean observations in the shadow period")
        # time split with a guard gap of one window length (no overlapping windows)
        t0, t1 = clean[0].observed_at, clean[-1].observed_at
        cut = t0 + (t1 - t0) * 0.7
        gap = timedelta(seconds=self.cfg.window.length_s)
        train_obs = [o for o in clean if o.observed_at < cut]
        val_obs = [o for o in clean if o.observed_at >= cut + gap]

        catalog = self._catalog_from(app_id, train_obs, min_sources=3)
        now = self.clock()
        profile = build_profile(
            app_id=app_id,
            version=self.profiles.next_version(app_id),
            parent_version=trusted.version,
            window=self.cfg.window,
            vectors=self.windows(train_obs, catalog),
            observations=train_obs,
            dataset_ids=(f"live:{since.isoformat()}..{until.isoformat()}",),
            created_at=now,
            min_endpoint_sources=3,
            min_windows=100,
        )
        new_catalog = self.catalog(app_id, profile)
        val_benign = self.windows(val_obs, new_catalog)
        attack_val: list[FeatureVector] = []
        if attack_validation_ids:
            _, attack_val = self._labeled(attack_validation_ids, new_catalog)
        records = train_and_register(
            profile=profile,
            data=TrainingData(
                train_benign=self.windows(train_obs, catalog),
                val_benign=val_benign,
                val_attack=attack_val,
                train_dataset_ids=profile.provenance.dataset_ids,
                val_dataset_ids=tuple(attack_validation_ids) or ("live-validation-slice",),
            ),
            store=self.artifacts,
            kinds=DEFAULT_KINDS,
            target_fpr=self.target_fpr,
            created_at=now,
            seed=seed,
        )
        checks = self._gate(
            trusted, profile, records, val_obs, attack_validation_ids, len(excluded)
        )
        return self._persist(profile, records, checks, now)

    def _excluded_sources(
        self, app_id: str, obs: Sequence[HttpObservation], tainted: set[IPv4Address]
    ) -> set[IPv4Address]:
        excluded = set(tainted)
        excluded |= {o.client_ip for o in obs if o.waf_rule_ids or o.waf_blocked}
        for fb in self.adaptation.feedback(app_id):
            if fb.label is FeedbackLabel.TRUE_POSITIVE and fb.source_ip:
                excluded.add(fb.source_ip)
        for p in self.cfg.safety.protected:
            excluded |= {o.client_ip for o in obs if o.client_ip in p.network}
        return excluded

    def _gate(
        self,
        trusted: BehaviorProfile,
        cand: BehaviorProfile,
        records: list[ModelRecord],
        val_obs: Sequence[HttpObservation],
        attack_ids: Sequence[str],
        n_excluded: int,
    ) -> list[GateCheck]:
        checks = [
            GateCheck(
                name="max_source_share",
                passed=cand.provenance.max_source_share <= 0.35,
                value=round(cand.provenance.max_source_share, 3),
                limit=0.35,
                detail="no single source may dominate the candidate (anti-poisoning)",
            ),
            GateCheck(
                name="independent_sources",
                passed=cand.provenance.n_sources >= 3,
                value=cand.provenance.n_sources,
                limit=3,
            ),
            GateCheck(
                name="excluded_sources",
                passed=True,
                value=n_excluded,
                detail="tainted/WAF/feedback/probe sources removed before learning",
            ),
        ]
        for name, limit in SENSITIVE_LIMITS.items():
            old, new = trusted.features[name].q99, cand.features[name].q99
            checks.append(
                GateCheck(
                    name=f"sensitive_{name}_q99",
                    passed=new <= max(limit, old * 1.5),
                    value=round(new, 4),
                    limit=round(max(limit, old * 1.5), 4),
                    detail=f"trusted q99={old:.4f}; attack-like behavior must not become normal",
                )
            )
        # Attack regression and FP comparison (Isolation Forest is the ML arm)
        cand_if = next((r for r in records if r.detector is DetectorKind.ISOLATION_FOREST), None)
        trusted_if = next(
            iter(self.models.active(trusted.app_id, DetectorKind.ISOLATION_FOREST.value)), None
        )
        if cand_if and trusted_if:
            cand_det = self.artifacts.load(cand_if)
            trusted_det = self.artifacts.load(trusted_if)
            old_v = self.windows(val_obs, self.catalog(trusted.app_id, trusted))
            new_v = self.windows(val_obs, self.catalog(cand.app_id, cand))
            if old_v and new_v:
                old_fpr = float(np.mean(trusted_det.score(_rows(old_v)) >= trusted_if.threshold))
                new_fpr = float(np.mean(cand_det.score(_rows(new_v)) >= cand_if.threshold))
                checks.append(
                    GateCheck(
                        name="benign_fpr_not_worse",
                        passed=new_fpr <= max(old_fpr, self.target_fpr * 2),
                        value=round(new_fpr, 4),
                        limit=round(max(old_fpr, self.target_fpr * 2), 4),
                        detail=f"trusted model FPR on the same recent benign slice = {old_fpr:.4f}",
                    )
                )
            if attack_ids:
                rec = {}
                for label, prof, det, thr in (
                    ("trusted", trusted, trusted_det, trusted_if.threshold),
                    ("candidate", cand, cand_det, cand_if.threshold),
                ):
                    b, a = self._labeled(attack_ids, self.catalog(prof.app_id, prof))
                    y = np.r_[np.zeros(len(b), int), np.ones(len(a), int)]
                    rows = _rows([*b, *a])
                    rec[label] = metrics(det.score(rows), y, thr).recall or 0.0
                checks.append(
                    GateCheck(
                        name="attack_recall_regression",
                        passed=rec["candidate"] >= rec["trusted"] - 0.05,
                        value=round(rec["candidate"], 4),
                        limit=round(rec["trusted"] - 0.05, 4),
                        detail=f"trusted recall {rec['trusted']:.4f} on {', '.join(attack_ids)}",
                    )
                )
            else:
                checks.append(
                    GateCheck(
                        name="attack_recall_regression",
                        passed=False,
                        detail="no labeled attack validation runs supplied",
                    )
                )
        return checks

    def _persist(
        self,
        profile: BehaviorProfile,
        records: list[ModelRecord],
        checks: list[GateCheck],
        now: datetime,
    ) -> CandidateResult:
        self.profiles.save(profile)
        for r in records:
            self.models.save(r)
        evaluation = CandidateEvaluation(
            app_id=profile.app_id,
            candidate_profile_version=profile.version,
            candidate_model_version=next(
                (r.version for r in records if r.detector is DetectorKind.ISOLATION_FOREST), None
            ),
            evaluated_at=now,
            checks=tuple(checks),
        )
        self.adaptation.add_evaluation(evaluation)
        self.audit.record(
            "learning",
            "profile.candidate",
            f"{profile.app_id}:v{profile.version}",
            {"passed": evaluation.passed, "hash": profile.content_hash},
        )
        return CandidateResult(profile=profile, models=records, evaluation=evaluation)

    # -------------------------------------------------------------- lifecycle
    def promote(self, app_id: str, version: int, reviewer: str, note: str) -> BehaviorProfile:
        evals = [
            e for e in self.adaptation.evaluations(app_id) if e.candidate_profile_version == version
        ]
        if not evals or not evals[0].passed:
            failed = (
                [c.name for c in evals[0].checks if not c.passed] if evals else ["no evaluation"]
            )
            raise GateFailed(f"profile v{version} has not passed the evaluation gate: {failed}")
        prof = self.profiles.switch(
            app_id, version, ProfileStatus.TRUSTED, reviewer, note, self._verified(app_id, version)
        )
        self.audit.record(reviewer, "profile.promote", f"{app_id}:v{version}", {"note": note})
        return prof

    def rollback(self, app_id: str, version: int, reviewer: str, note: str) -> BehaviorProfile:
        prof = self.profiles.get(app_id, version)
        if prof is None or prof.status not in (ProfileStatus.RETIRED, ProfileStatus.TRUSTED):
            raise ValueError("can only roll back to a previously trusted profile")
        prof = self.profiles.switch(
            app_id, version, ProfileStatus.TRUSTED, reviewer, note, self._verified(app_id, version)
        )
        self.audit.record(reviewer, "profile.rollback", f"{app_id}:v{version}", {"note": note})
        return prof

    def reject(self, app_id: str, version: int, reviewer: str, note: str) -> BehaviorProfile:
        prof = self.profiles.set_status(app_id, version, ProfileStatus.REJECTED, reviewer, note)
        for r in self.models.list(app_id):
            if r.profile_version == version:
                self.models.set_status(r.model_id, ModelStatus.REJECTED)
        return prof

    def _verified(self, app_id: str, version: int) -> list[ModelRecord]:
        """The models a switch to ``version`` would activate, each artifact checked
        (sha256) BEFORE anything changes: a switch never trusts a profile no controller
        could load (found 2026-10-28)."""
        models = self._models_of(app_id, version)
        if not models:
            raise ValueError(f"profile v{version} has no models")
        for r in models:
            try:
                self.artifacts.load(r)
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError(f"profile v{version}: artifact rejected: {exc}") from exc
        return models

    def _models_of(self, app_id: str, version: int) -> list[ModelRecord]:
        """The newest model per detector trained for profile ``version``."""
        latest: dict[DetectorKind, ModelRecord] = {}
        for r in self.models.list(app_id):  # newest first
            if r.profile_version == version and r.detector not in latest:
                latest[r.detector] = r
        return list(latest.values())

    def load_active(self, app_id: str) -> tuple[BehaviorProfile, list[LoadedModel]] | None:
        prof = self.profiles.trusted(app_id)
        if prof is None:
            return None
        loaded = [
            LoadedModel(record=r, detector=self.artifacts.load(r))
            for r in self.models.active(app_id)
            if r.profile_version == prof.version
        ]
        return prof, loaded

    def load_version(self, app_id: str, version: int) -> tuple[BehaviorProfile, list[LoadedModel]]:
        """Any stored profile version and its models, whatever their status (read-only
        evaluation of candidates; loading never activates anything)."""
        prof = self.profiles.get(app_id, version)
        if prof is None:
            raise ValueError(f"no profile v{version} for {app_id}")
        loaded = [
            LoadedModel(record=r, detector=self.artifacts.load(r))
            for r in self.models.list(app_id)
            if r.profile_version == version
        ]
        return prof, loaded


def _rows(vectors: Sequence[FeatureVector]) -> np.ndarray:
    from afw.domain.features import FEATURE_NAMES

    return np.array([v.as_row() for v in vectors], dtype=float).reshape(-1, len(FEATURE_NAMES))
