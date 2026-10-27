"""Challenger lifecycle: evaluate, human-approved promotion, probation, rollback (ADR-030).

* **evaluate** freezes the newest valid challenger checkpoint, runs the
  promotion gate (``afw.ml.challenger_gate``) on recorded holdout runs and, only
  if every check passes, registers the frozen snapshot as a CANDIDATE model.
* **promote** is a human (admin) decision and is refused unless the evaluation
  passed, is recent, its candidate is intact and the champion it was compared
  with is still the active one. There is no automatic promotion.
* **probation** watches the promoted model live. Too high an anomalous-window
  rate or too many operator false-positive reports roll back to the parent
  *automatically*: rollback only ever returns to a previously trusted model.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta

from afw.config import LabConfig
from afw.domain.common import new_id, utcnow
from afw.domain.detection import (
    DetectionResult,
    DetectorKind,
    ModelMetrics,
    ModelRecord,
    ModelStatus,
)
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.learning import ChallengerEvaluation, Probation, ProbationStatus
from afw.ml.challenger_gate import Holdout, evaluate_challenger
from afw.ml.datasets import DatasetStore, LabelIndex, Role, assert_disjoint
from afw.ml.online import CheckpointStore
from afw.ml.registry import ArtifactStore
from afw.persistence.repositories import SqlLearningRepository, SqlModelRepository
from afw.ports.repositories import AuditLog
from afw.services.learning import LearningService

_SAVE_EVERY = timedelta(seconds=30)


class PromotionRefused(ValueError):
    pass


class ChallengerLifecycle:
    def __init__(
        self,
        cfg: LabConfig,
        learning: LearningService,
        repo: SqlLearningRepository,
        store: CheckpointStore,
        models: SqlModelRepository,
        artifacts: ArtifactStore,
        datasets: DatasetStore,
        audit: AuditLog,
        false_positives: Callable[[str, datetime], int],
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.cfg = cfg
        self.pc = cfg.promotion
        self.learning = learning
        self.repo = repo
        self.store = store
        self.models = models
        self.artifacts = artifacts
        self.datasets = datasets
        self.audit = audit
        self.false_positives = false_positives
        self.clock = clock
        self._lock = threading.Lock()
        self._active: dict[str, Probation | None] = {}
        self._saved_at: datetime | None = None

    # ------------------------------------------------------------ evaluate
    def _holdout(
        self, app_id: str, benign_ids: Sequence[str], attack_ids: Sequence[str], catalog: object
    ) -> Holdout:
        benign: list[FeatureVector] = []
        attack: list[FeatureVector] = []
        spans = []
        synthetic = False
        for ds, want in [
            *((d, Role.BENIGN) for d in benign_ids),
            *((d, Role.ATTACK) for d in attack_ids),
        ]:
            m = self.datasets.manifest(ds)
            if m.app_id != app_id:
                raise ValueError(f"dataset {ds} belongs to {m.app_id}")
            if want is Role.ATTACK:
                synthetic |= "synthetic" in f"{m.scenario} {m.generator}".lower()
            spans += [(s.ip, s.start or m.start, s.end or m.end) for s in m.sources]
            labels = LabelIndex(m)
            for v in self.learning.windows(self.datasets.observations(ds), catalog):  # type: ignore[arg-type]
                if labels.label(v) is want:
                    (benign if want is Role.BENIGN else attack).append(v)
        return Holdout(
            benign=benign,
            attack=attack,
            benign_dataset_ids=tuple(benign_ids),
            attack_dataset_ids=tuple(attack_ids),
            synthetic_attack=synthetic,
            spans=tuple(spans),
        )

    def evaluate(
        self, app_id: str, benign_ids: Sequence[str], attack_ids: Sequence[str], actor: str
    ) -> ChallengerEvaluation:
        loaded = self.learning.load_active(app_id)
        if loaded is None:
            raise PromotionRefused("no trusted profile")
        profile, active = loaded
        champion = next(
            (m for m in active if m.record.detector is DetectorKind.HALF_SPACE_TREES), None
        )
        if champion is None:
            raise PromotionRefused("no active HST champion")
        restored = self.store.restore(app_id, champion.record)
        if restored is None:
            raise PromotionRefused("no valid challenger checkpoint for the active champion")
        challenger, ckpt = restored
        if not benign_ids:
            raise ValueError("at least one benign holdout dataset is required")
        assert_disjoint(benign_ids, attack_ids, champion.record.train_dataset_ids)
        holdout = self._holdout(
            app_id, benign_ids, attack_ids, self.learning.catalog(app_id, profile)
        )
        now = self.clock()
        result = evaluate_challenger(
            champion=champion,
            challenger=challenger,
            profile=profile,
            holdout=holdout,
            lineage=self.repo.lineage(app_id, champion.record.model_id, challenger.n_learned),
            tainted=self.repo.tainted_sources(now),
            pc=self.pc,
        )
        candidate_id = ""
        if all(c.passed for c in result.checks):
            model_id = new_id("mdl")
            path, digest, size = self.artifacts.save(app_id, model_id, challenger.detector)
            parent = champion.record
            self.models.save(
                ModelRecord(
                    model_id=model_id,
                    app_id=app_id,
                    detector=DetectorKind.HALF_SPACE_TREES,
                    version=f"half_space_trees-p{profile.version}-online{ckpt.seq}-{now:%Y%m%d%H%M%S}",
                    profile_version=profile.version,
                    status=ModelStatus.CANDIDATE,
                    created_at=now,
                    params={
                        **challenger.detector.params(),
                        "parent_model_id": parent.model_id,
                        "checkpoint_id": ckpt.checkpoint_id,
                        "n_learned": challenger.n_learned,
                        "target_fpr": self.pc.target_fpr,
                    },
                    threshold=result.threshold,
                    feature_names=FEATURE_NAMES,
                    train_dataset_ids=(*parent.train_dataset_ids, f"online:{ckpt.checkpoint_id}"),
                    validation_dataset_ids=tuple(benign_ids),
                    artifact_sha256=digest,
                    artifact_path=path,
                    validation_metrics=ModelMetrics(
                        fpr=result.metrics.get("challenger_fpr"),
                        recall=result.metrics.get("challenger_recall"),
                        n_benign=int(result.metrics.get("holdout_test") or 0),
                        n_attack=int(result.metrics.get("attack_windows") or 0),
                        model_bytes=size,
                    ),
                    benign_score_quantiles=result.benign_quantiles,
                )
            )
            candidate_id = model_id
        ev = ChallengerEvaluation(
            evaluation_id=new_id("ceval"),
            app_id=app_id,
            evaluated_at=now,
            checkpoint_id=ckpt.checkpoint_id,
            candidate_model_id=candidate_id,
            parent_model_id=champion.record.model_id,
            n_learned=challenger.n_learned,
            threshold=result.threshold,
            benign_dataset_ids=tuple(benign_ids),
            attack_dataset_ids=tuple(attack_ids),
            checks=result.checks,
            metrics=result.metrics,
        )
        self.repo.add_evaluation(ev)
        self.audit.record(
            actor,
            "challenger.evaluate",
            f"{app_id}:{ckpt.checkpoint_id}",
            {
                "evaluation": ev.evaluation_id,
                "passed": ev.passed,
                "failed": [c.name for c in ev.checks if not c.passed],
            },
        )
        return ev

    # ------------------------------------------------------------- promote
    def promote(self, app_id: str, evaluation_id: str, reviewer: str, note: str) -> ModelRecord:
        with self._lock:
            ev = self.repo.evaluation(evaluation_id)
            if ev is None or ev.app_id != app_id:
                raise PromotionRefused("unknown evaluation")
            if not ev.passed:
                failed = [c.name for c in ev.checks if not c.passed]
                raise PromotionRefused(f"evaluation did not pass the gate: {failed}")
            now = self.clock()
            if now - ev.evaluated_at > timedelta(seconds=self.pc.max_evaluation_age_s):
                raise PromotionRefused("evaluation is stale; evaluate again")
            if self.repo.probations(app_id, active_only=True):
                raise PromotionRefused("another promotion is still on probation")
            cand = self.models.get(ev.candidate_model_id)
            parent = self.models.get(ev.parent_model_id)
            if cand is None or cand.status is not ModelStatus.CANDIDATE:
                raise PromotionRefused("candidate model is missing or no longer a candidate")
            if parent is None or parent.status is not ModelStatus.ACTIVE:
                raise PromotionRefused("the champion changed since the evaluation")
            try:
                self.artifacts.load(cand)  # sha256-verified
            except (OSError, ValueError, TypeError) as exc:
                raise PromotionRefused(f"candidate artifact rejected: {exc}") from exc
            self.models.set_status(parent.model_id, ModelStatus.RETIRED)
            self.models.set_status(cand.model_id, ModelStatus.ACTIVE)
            fpr = ev.metrics.get("challenger_fpr")
            p = Probation(
                probation_id=new_id("prob"),
                app_id=app_id,
                model_id=cand.model_id,
                parent_model_id=parent.model_id,
                evaluation_id=ev.evaluation_id,
                started_at=now,
                until=now + timedelta(seconds=self.pc.probation_s),
                baseline_rate=max(float(fpr or 0.0), self.pc.target_fpr),
            )
            self.repo.save_probation(p)
            self._active[app_id] = p
            self.audit.record(
                reviewer,
                "challenger.promote",
                f"{app_id}:{cand.version}",
                {"evaluation": ev.evaluation_id, "parent": parent.version, "note": note},
            )
            return cand.model_copy(update={"status": ModelStatus.ACTIVE})

    # ------------------------------------------------------------ rollback
    def rollback(self, app_id: str, actor: str, reason: str) -> ModelRecord:
        with self._lock:
            return self._rollback(app_id, actor, reason, automatic=False)

    def _rollback(self, app_id: str, actor: str, reason: str, *, automatic: bool) -> ModelRecord:
        current = self.models.active(app_id, DetectorKind.HALF_SPACE_TREES.value)
        p = next(
            (
                p
                for p in self.repo.probations(app_id)
                if p.status is not ProbationStatus.ROLLED_BACK
                and any(m.model_id == p.model_id for m in current)
            ),
            None,
        )
        if p is None:
            raise PromotionRefused("the active HST is not a promoted challenger")
        parent = self.models.get(p.parent_model_id)
        if parent is None:
            raise PromotionRefused("parent model record is missing")
        try:
            self.artifacts.load(parent)
        except (OSError, ValueError, TypeError) as exc:
            raise PromotionRefused(f"parent artifact rejected: {exc}") from exc
        now = self.clock()
        # A model that breached probation is never re-activated by accident.
        self.models.set_status(
            p.model_id, ModelStatus.REJECTED if automatic else ModelStatus.RETIRED
        )
        self.models.set_status(parent.model_id, ModelStatus.ACTIVE)
        closed = p.model_copy(
            update={"status": ProbationStatus.ROLLED_BACK, "closed_at": now, "reason": reason}
        )
        self.repo.save_probation(closed)
        self._active[app_id] = None
        self.audit.record(
            actor,
            "challenger.auto_rollback" if automatic else "challenger.rollback",
            f"{app_id}:{p.model_id}",
            {
                "parent": parent.version,
                "reason": reason,
                "windows": p.windows,
                "anomalous": p.anomalous,
            },
        )
        return parent.model_copy(update={"status": ModelStatus.ACTIVE})

    # ----------------------------------------------------------- probation
    def _probation(self, app_id: str) -> Probation | None:
        if app_id not in self._active:
            active = self.repo.probations(app_id, active_only=True)
            self._active[app_id] = active[0] if active else None
        return self._active[app_id]

    def observe(self, app_id: str, detections: Sequence[DetectionResult]) -> None:
        """Count the promoted model's live verdicts (processor thread)."""
        with self._lock:
            p = self._probation(app_id)
            if p is None:
                return
            for d in detections:
                if d.detector is DetectorKind.HALF_SPACE_TREES:
                    p = p.model_copy(
                        update={
                            "windows": p.windows + 1,
                            "anomalous": p.anomalous + int(d.is_anomalous),
                        }
                    )
            self._active[app_id] = p

    def check(self, app_id: str, now: datetime | None = None) -> bool:
        """Apply the probation rules; True if the model was rolled back (caller reloads)."""
        now = now or self.clock()
        with self._lock:
            p = self._probation(app_id)
            if p is None:
                return False
            fps = self.false_positives(app_id, p.started_at)
            if fps >= self.pc.probation_max_false_positives:
                self._rollback(app_id, "probation", f"{fps} false-positive reports", automatic=True)
                return True
            if p.windows >= self.pc.probation_min_windows:
                rate = p.anomalous / p.windows
                limit = max(
                    self.pc.probation_rate_factor * p.baseline_rate,
                    p.baseline_rate + self.pc.probation_rate_margin,
                )
                if rate > limit:
                    self.repo.save_probation(p)
                    self._rollback(
                        app_id,
                        "probation",
                        f"anomalous rate {rate:.3f} > {limit:.3f} over {p.windows} windows",
                        automatic=True,
                    )
                    return True
            if now >= p.until:
                done = p.model_copy(
                    update={
                        "status": ProbationStatus.PASSED,
                        "closed_at": now,
                        "reason": "period elapsed",
                    }
                )
                self.repo.save_probation(done)
                self._active[app_id] = None
                self.audit.record(
                    "probation",
                    "challenger.probation_passed",
                    f"{app_id}:{p.model_id}",
                    {"windows": p.windows, "anomalous": p.anomalous},
                )
                return False
            if self._saved_at is None or now - self._saved_at >= _SAVE_EVERY:
                self.repo.save_probation(p)
                self._saved_at = now
            return False

    def snapshot(self, app_id: str) -> dict[str, object]:
        with self._lock:
            p = self._probation(app_id)
        return {
            "probation": None if p is None else p.model_dump(mode="json"),
            "evaluations": [
                {
                    "evaluation_id": e.evaluation_id,
                    "evaluated_at": e.evaluated_at.isoformat(),
                    "passed": e.passed,
                    "candidate_model_id": e.candidate_model_id or None,
                    "n_learned": e.n_learned,
                    "checks": [c.model_dump(mode="json") for c in e.checks],
                    "metrics": e.metrics,
                }
                for e in self.repo.evaluations(app_id, limit=5)
            ],
            "history": [p.model_dump(mode="json") for p in self.repo.probations(app_id)[:5]],
        }
