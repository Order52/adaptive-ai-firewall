"""SQLAlchemy implementations of the repository ports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy import Engine, Table, delete, desc, insert, select, union, update
from sqlalchemy.exc import IntegrityError

from afw.domain.adaptation import CandidateEvaluation, DriftReport, Feedback
from afw.domain.common import utcnow
from afw.domain.detection import DetectionResult, ModelRecord, ModelStatus
from afw.domain.events import HttpObservation, IdsAlert
from afw.domain.features import FeatureVector
from afw.domain.learning import (
    ChallengerCheckpoint,
    ChallengerEvaluation,
    CheckpointStatus,
    LearnedWindow,
    Probation,
    ProbationStatus,
    ShadowScore,
    SourceRecord,
)
from afw.domain.policy import OperatingMode, Policy, PolicyState
from afw.domain.profiles import BehaviorProfile, ProfileStatus
from afw.domain.risk import RiskAssessment
from afw.persistence import schema as t
from afw.persistence.db import utc_naive

M = TypeVar("M", bound=BaseModel)


def _load[M: BaseModel](model: type[M], rows: Sequence[Any]) -> list[M]:
    return [model.model_validate_json(r.body) for r in rows]


class _Repo:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def _upsert(self, table: Table, key: str, values: dict[str, Any]) -> None:
        with self.engine.begin() as c:
            res = c.execute(update(table).where(table.c[key] == values[key]).values(**values))
            if res.rowcount == 0:
                c.execute(insert(table).values(**values))


class SqlEventRepository(_Repo):
    def add_observations(self, items: Sequence[HttpObservation]) -> list[HttpObservation]:
        """Insert observations; return only the ones accepted (new request ids)."""
        added: list[HttpObservation] = []
        with self.engine.begin() as c:
            for o in items:
                try:
                    with c.begin_nested():
                        c.execute(
                            insert(t.observations).values(
                                event_id=o.event_id,
                                request_id=o.request_id,
                                app_id=o.app_id,
                                observed_at=utc_naive(o.observed_at),
                                client_ip=str(o.client_ip),
                                body=o.model_dump_json(),
                            )
                        )
                    added.append(o)
                except IntegrityError:
                    continue  # duplicate request id: idempotent replay
        return added

    def add_ids_alerts(self, items: Sequence[IdsAlert]) -> list[IdsAlert]:
        """Insert alerts; return only the new ones (content-derived ids, idempotent)."""
        added: list[IdsAlert] = []
        with self.engine.begin() as c:
            for a in items:
                try:
                    with c.begin_nested():
                        c.execute(
                            insert(t.ids_alerts).values(
                                event_id=a.event_id,
                                observed_at=utc_naive(a.observed_at),
                                src_ip=str(a.src_ip),
                                body=a.model_dump_json(),
                            )
                        )
                    added.append(a)
                except IntegrityError:
                    continue  # duplicate alert line: already stored and counted
        return added

    def recent_observations(
        self, limit: int = 100, source_ip: IPv4Address | None = None
    ) -> list[HttpObservation]:
        q = select(t.observations.c.body).order_by(desc(t.observations.c.observed_at)).limit(limit)
        if source_ip is not None:
            q = q.where(t.observations.c.client_ip == str(source_ip))
        with self.engine.connect() as c:
            return _load(HttpObservation, c.execute(q).all())

    def observations_between(
        self, app_id: str, start: datetime, end: datetime
    ) -> list[HttpObservation]:
        q = (
            select(t.observations.c.body)
            .where(t.observations.c.app_id == app_id)
            .where(t.observations.c.observed_at >= utc_naive(start))
            .where(t.observations.c.observed_at <= utc_naive(end))
            .order_by(t.observations.c.observed_at)
        )
        with self.engine.connect() as c:
            return _load(HttpObservation, c.execute(q).all())

    def recent_sources(self, since: datetime) -> list[IPv4Address]:
        """Distinct HTTP client and IDS source addresses seen since ``since``."""
        cut = utc_naive(since)
        q = union(
            select(t.observations.c.client_ip.label("ip")).where(
                t.observations.c.observed_at >= cut
            ),
            select(t.ids_alerts.c.src_ip.label("ip")).where(t.ids_alerts.c.observed_at >= cut),
        )
        with self.engine.connect() as c:
            return [IPv4Address(r[0]) for r in c.execute(q).all()]

    def ids_alerts_between(self, start: datetime, end: datetime) -> list[IdsAlert]:
        q = (
            select(t.ids_alerts.c.body)
            .where(t.ids_alerts.c.observed_at >= utc_naive(start))
            .where(t.ids_alerts.c.observed_at <= utc_naive(end))
            .order_by(t.ids_alerts.c.observed_at)
        )
        with self.engine.connect() as c:
            return _load(IdsAlert, c.execute(q).all())

    def recent_ids_alerts(self, since: datetime) -> list[IdsAlert]:
        q = select(t.ids_alerts.c.body).where(t.ids_alerts.c.observed_at >= utc_naive(since))
        with self.engine.connect() as c:
            return _load(IdsAlert, c.execute(q).all())

    def count_observations(self) -> int:
        with self.engine.connect() as c:
            return len(c.execute(select(t.observations.c.event_id)).all())

    def purge_before(self, cutoff: datetime) -> int:
        with self.engine.begin() as c:
            n = c.execute(
                delete(t.observations).where(t.observations.c.observed_at < utc_naive(cutoff))
            ).rowcount
            c.execute(delete(t.features).where(t.features.c.window_end < utc_naive(cutoff)))
            c.execute(delete(t.detections).where(t.detections.c.window_end < utc_naive(cutoff)))
            c.execute(delete(t.ids_alerts).where(t.ids_alerts.c.observed_at < utc_naive(cutoff)))
        return int(n)


class SqlAnalysisRepository(_Repo):
    def add_features(self, items: Sequence[FeatureVector], dataset_id: str | None) -> None:
        if not items:
            return
        with self.engine.begin() as c:
            c.execute(
                insert(t.features),
                [
                    {
                        "app_id": v.app_id,
                        "source_ip": str(v.source_ip),
                        "window_end": utc_naive(v.window_end),
                        "dataset_id": dataset_id,
                        "body": v.model_dump_json(),
                    }
                    for v in items
                ],
            )

    def features_for_datasets(self, app_id: str, dataset_ids: Sequence[str]) -> list[FeatureVector]:
        q = (
            select(t.features.c.body)
            .where(t.features.c.app_id == app_id)
            .where(t.features.c.dataset_id.in_(list(dataset_ids)))
            .order_by(t.features.c.window_end)
        )
        with self.engine.connect() as c:
            return _load(FeatureVector, c.execute(q).all())

    def recent_features(
        self, since: datetime, source_ip: IPv4Address | None = None
    ) -> list[FeatureVector]:
        q = select(t.features.c.body).where(t.features.c.window_end >= utc_naive(since))
        if source_ip is not None:
            q = q.where(t.features.c.source_ip == str(source_ip))
        with self.engine.connect() as c:
            return _load(FeatureVector, c.execute(q.order_by(t.features.c.window_end)).all())

    def add_detection(self, item: DetectionResult) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.detections).values(
                    detection_id=item.detection_id,
                    window_end=utc_naive(item.window_end),
                    source_ip=str(item.source_ip),
                    detector=item.detector.value,
                    anomalous=item.is_anomalous,
                    body=item.model_dump_json(),
                )
            )

    def recent_detections(
        self, limit: int = 100, anomalous_only: bool = False
    ) -> list[DetectionResult]:
        q = select(t.detections.c.body).order_by(desc(t.detections.c.window_end)).limit(limit)
        if anomalous_only:
            q = q.where(t.detections.c.anomalous.is_(True))
        with self.engine.connect() as c:
            return _load(DetectionResult, c.execute(q).all())

    def add_assessment(self, item: RiskAssessment) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.assessments).values(
                    assessment_id=item.assessment_id,
                    assessed_at=utc_naive(item.assessed_at),
                    source_ip=str(item.source_ip),
                    score=item.score,
                    body=item.model_dump_json(),
                )
            )

    def get_assessment(self, assessment_id: str) -> RiskAssessment | None:
        q = select(t.assessments.c.body).where(t.assessments.c.assessment_id == assessment_id)
        with self.engine.connect() as c:
            rows = _load(RiskAssessment, c.execute(q).all())
        return rows[0] if rows else None

    def recent_assessments(
        self, limit: int = 100, min_score: float = 0.0, source_ip: IPv4Address | None = None
    ) -> list[RiskAssessment]:
        q = (
            select(t.assessments.c.body)
            .where(t.assessments.c.score >= min_score)
            .order_by(desc(t.assessments.c.assessed_at))
            .limit(limit)
        )
        if source_ip is not None:
            q = q.where(t.assessments.c.source_ip == str(source_ip))
        with self.engine.connect() as c:
            return _load(RiskAssessment, c.execute(q).all())


class SqlProfileRepository(_Repo):
    def save(self, profile: BehaviorProfile) -> None:
        self._upsert(
            t.profiles,
            "profile_id",
            {
                "profile_id": profile.profile_id,
                "app_id": profile.app_id,
                "version": profile.version,
                "status": profile.status.value,
                "body": profile.model_dump_json(),
            },
        )

    def get(self, app_id: str, version: int) -> BehaviorProfile | None:
        q = select(t.profiles.c.body).where(
            (t.profiles.c.app_id == app_id) & (t.profiles.c.version == version)
        )
        with self.engine.connect() as c:
            rows = _load(BehaviorProfile, c.execute(q).all())
        return rows[0] if rows else None

    def trusted(self, app_id: str) -> BehaviorProfile | None:
        q = select(t.profiles.c.body).where(
            (t.profiles.c.app_id == app_id) & (t.profiles.c.status == ProfileStatus.TRUSTED.value)
        )
        with self.engine.connect() as c:
            rows = _load(BehaviorProfile, c.execute(q).all())
        return rows[0] if rows else None

    def list(self, app_id: str | None = None) -> list[BehaviorProfile]:
        q = select(t.profiles.c.body).order_by(t.profiles.c.app_id, t.profiles.c.version)
        if app_id:
            q = q.where(t.profiles.c.app_id == app_id)
        with self.engine.connect() as c:
            return _load(BehaviorProfile, c.execute(q).all())

    def set_status(
        self, app_id: str, version: int, status: ProfileStatus, reviewer: str | None, note: str
    ) -> BehaviorProfile:
        prof = self.get(app_id, version)
        if prof is None:
            raise KeyError(f"profile {app_id} v{version} not found")
        if status is ProfileStatus.TRUSTED:
            current = self.trusted(app_id)
            if current and current.version != version:
                self.save(current.model_copy(update={"status": ProfileStatus.RETIRED}))
        updated = prof.model_copy(
            update={
                "status": status,
                "reviewed_by": reviewer,
                "reviewed_at": utcnow(),
                "review_note": note,
            }
        )
        self.save(updated)
        return updated

    def next_version(self, app_id: str) -> int:
        versions = [p.version for p in self.list(app_id)]
        return max(versions, default=0) + 1


class SqlModelRepository(_Repo):
    def save(self, record: ModelRecord) -> None:
        self._upsert(
            t.models,
            "model_id",
            {
                "model_id": record.model_id,
                "app_id": record.app_id,
                "detector": record.detector.value,
                "status": record.status.value,
                "created_at": utc_naive(record.created_at),
                "body": record.model_dump_json(),
            },
        )

    def get(self, model_id: str) -> ModelRecord | None:
        with self.engine.connect() as c:
            rows = _load(
                ModelRecord,
                c.execute(select(t.models.c.body).where(t.models.c.model_id == model_id)).all(),
            )
        return rows[0] if rows else None

    def active(self, app_id: str, detector: str | None = None) -> list[ModelRecord]:
        q = select(t.models.c.body).where(
            (t.models.c.app_id == app_id) & (t.models.c.status == ModelStatus.ACTIVE.value)
        )
        if detector:
            q = q.where(t.models.c.detector == detector)
        with self.engine.connect() as c:
            return _load(ModelRecord, c.execute(q).all())

    def list(self, app_id: str | None = None) -> list[ModelRecord]:
        q = select(t.models.c.body).order_by(desc(t.models.c.created_at))
        if app_id:
            q = q.where(t.models.c.app_id == app_id)
        with self.engine.connect() as c:
            return _load(ModelRecord, c.execute(q).all())

    def set_status(self, model_id: str, status: ModelStatus) -> None:
        self.set_statuses([(model_id, status)])

    def set_statuses(self, changes: Sequence[tuple[str, ModelStatus]]) -> None:
        """Apply several status changes atomically (one transaction). Activating a model
        retires the other active models of its detector, unless ``changes`` sets them."""
        recs = []
        for model_id, status in changes:
            rec = self.get(model_id)
            if rec is None:
                raise KeyError(model_id)
            recs.append(rec.model_copy(update={"status": status}))
        named = {r.model_id for r in recs}
        for r in list(recs):
            if r.status is ModelStatus.ACTIVE:
                recs += [
                    o.model_copy(update={"status": ModelStatus.RETIRED})
                    for o in self.active(r.app_id, r.detector.value)
                    if o.model_id not in named
                ]
        with self.engine.begin() as c:
            for r in recs:
                c.execute(
                    update(t.models)
                    .where(t.models.c.model_id == r.model_id)
                    .values(status=r.status.value, body=r.model_dump_json())
                )


class SqlPolicyRepository(_Repo):
    def save(self, policy: Policy) -> None:
        self._upsert(
            t.policies,
            "policy_id",
            {
                "policy_id": policy.policy_id,
                "idempotency_key": policy.idempotency_key,
                "state": policy.state.value,
                "updated_at": utc_naive(policy.updated_at),
                "body": policy.model_dump_json(),
            },
        )

    def get(self, policy_id: str) -> Policy | None:
        with self.engine.connect() as c:
            rows = _load(
                Policy,
                c.execute(
                    select(t.policies.c.body).where(t.policies.c.policy_id == policy_id)
                ).all(),
            )
        return rows[0] if rows else None

    def by_idempotency_key(self, key: str) -> Policy | None:
        q = (
            select(t.policies.c.body)
            .where(t.policies.c.idempotency_key == key)
            .order_by(desc(t.policies.c.updated_at))
            .limit(1)
        )
        with self.engine.connect() as c:
            rows = _load(Policy, c.execute(q).all())
        return rows[0] if rows else None

    def in_states(self, states: frozenset[PolicyState]) -> list[Policy]:
        q = select(t.policies.c.body).where(t.policies.c.state.in_([s.value for s in states]))
        with self.engine.connect() as c:
            return _load(Policy, c.execute(q).all())

    def recent(self, limit: int = 100) -> list[Policy]:
        q = select(t.policies.c.body).order_by(desc(t.policies.c.updated_at)).limit(limit)
        with self.engine.connect() as c:
            return _load(Policy, c.execute(q).all())


class SqlAdaptationRepository(_Repo):
    def add_drift(self, report: DriftReport) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.drift_reports).values(
                    report_id=report.report_id,
                    app_id=report.app_id,
                    detected_at=utc_naive(report.detected_at),
                    body=report.model_dump_json(),
                )
            )

    def recent_drift(self, limit: int = 50) -> list[DriftReport]:
        q = (
            select(t.drift_reports.c.body)
            .order_by(desc(t.drift_reports.c.detected_at))
            .limit(limit)
        )
        with self.engine.connect() as c:
            return _load(DriftReport, c.execute(q).all())

    def add_feedback(self, item: Feedback) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.feedback).values(
                    feedback_id=item.feedback_id,
                    app_id=item.app_id,
                    created_at=utc_naive(item.created_at),
                    body=item.model_dump_json(),
                )
            )

    def feedback(self, app_id: str | None = None) -> list[Feedback]:
        q = select(t.feedback.c.body).order_by(desc(t.feedback.c.created_at))
        if app_id:
            q = q.where(t.feedback.c.app_id == app_id)
        with self.engine.connect() as c:
            return _load(Feedback, c.execute(q).all())

    def add_evaluation(self, item: CandidateEvaluation) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.evaluations).values(
                    app_id=item.app_id,
                    evaluated_at=utc_naive(item.evaluated_at),
                    body=item.model_dump_json(),
                )
            )

    def evaluations(self, app_id: str) -> list[CandidateEvaluation]:
        q = (
            select(t.evaluations.c.body)
            .where(t.evaluations.c.app_id == app_id)
            .order_by(desc(t.evaluations.c.evaluated_at))
        )
        with self.engine.connect() as c:
            return _load(CandidateEvaluation, c.execute(q).all())


class SqlSettingsRepository(_Repo):
    def __init__(self, engine: Engine, default_mode: OperatingMode) -> None:
        super().__init__(engine)
        self.default_mode = default_mode

    def get(self, key: str) -> str | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.settings.c.value).where(t.settings.c.key == key)).first()
        return None if row is None else str(row.value)

    def put(self, key: str, value: str) -> None:
        self._upsert(t.settings, "key", {"key": key, "value": value})

    def get_mode(self) -> OperatingMode:
        raw = self.get("mode")
        return OperatingMode(raw) if raw else self.default_mode

    def set_mode(self, mode: OperatingMode, actor: str) -> None:
        self.put("mode", mode.value)


class SqlAuditLog(_Repo):
    def record(self, actor: str, action: str, subject: str, detail: dict[str, object]) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.audit).values(
                    at=utc_naive(utcnow()),
                    actor=actor[:64],
                    action=action[:64],
                    subject=subject[:64],
                    detail=json.dumps(detail, default=str),
                )
            )

    def recent(self, limit: int = 100) -> list[dict[str, object]]:
        q = select(t.audit).order_by(desc(t.audit.c.id)).limit(limit)
        with self.engine.connect() as c:
            return [
                {
                    "at": r.at.isoformat() + "Z",
                    "actor": r.actor,
                    "action": r.action,
                    "subject": r.subject,
                    "detail": json.loads(r.detail),
                }
                for r in c.execute(q).all()
            ]


class SqlExperimentRepository(_Repo):
    def add(self, experiment: str, body: dict[str, Any]) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.experiment_results).values(
                    experiment=experiment,
                    created_at=utc_naive(utcnow()),
                    body=json.dumps(body, default=str),
                )
            )

    def list(self, experiment: str | None = None) -> list[dict[str, Any]]:
        q = select(t.experiment_results).order_by(desc(t.experiment_results.c.id))
        if experiment:
            q = q.where(t.experiment_results.c.experiment == experiment)
        with self.engine.connect() as c:
            return [
                {
                    "experiment": r.experiment,
                    "created_at": r.created_at.isoformat() + "Z",
                    **json.loads(r.body),
                }
                for r in c.execute(q).all()
            ]


class SqlLearningRepository(_Repo):
    """Persistence for the online shadow learner (ADR-028)."""

    # ---------------------------------------------------------- reputation
    def source(self, ip: IPv4Address) -> SourceRecord | None:
        q = select(t.source_reputation).where(t.source_reputation.c.source_ip == str(ip))
        with self.engine.connect() as c:
            row = c.execute(q).first()
        return None if row is None else _source(row)

    def touch(self, ip: IPv4Address, at: datetime) -> SourceRecord:
        """Record that ``ip`` was seen; ``first_seen`` is never moved forward."""
        with self.engine.begin() as c:
            row = c.execute(
                select(t.source_reputation).where(t.source_reputation.c.source_ip == str(ip))
            ).first()
            if row is None:
                c.execute(
                    insert(t.source_reputation).values(
                        source_ip=str(ip), first_seen=utc_naive(at), last_seen=utc_naive(at)
                    )
                )
                return SourceRecord(source_ip=ip, first_seen=at, last_seen=at)
            rec = _source(row)
            if at > rec.last_seen:
                c.execute(
                    update(t.source_reputation)
                    .where(t.source_reputation.c.source_ip == str(ip))
                    .values(last_seen=utc_naive(at))
                )
                rec = rec.model_copy(update={"last_seen": at})
            return rec

    def taint(self, ip: IPv4Address, at: datetime, until: datetime, reason: str) -> None:
        """Taint for learning until ``until``; an existing longer taint is kept."""
        rec = self.touch(ip, at)
        if rec.taint_until is not None and rec.taint_until >= until:
            return
        with self.engine.begin() as c:
            c.execute(
                update(t.source_reputation)
                .where(t.source_reputation.c.source_ip == str(ip))
                .values(taint_until=utc_naive(until), taint_reason=reason[:64])
            )

    def tainted_sources(self, now: datetime) -> set[IPv4Address]:
        q = select(t.source_reputation.c.source_ip).where(
            t.source_reputation.c.taint_until > utc_naive(now)
        )
        with self.engine.connect() as c:
            return {IPv4Address(r.source_ip) for r in c.execute(q)}

    def purge_sources(self, idle_before: datetime, now: datetime) -> int:
        """Bounded retention: forget idle sources whose taint has expired."""
        tbl = t.source_reputation
        q = delete(tbl).where(
            tbl.c.last_seen < utc_naive(idle_before),
            (tbl.c.taint_until.is_(None)) | (tbl.c.taint_until <= utc_naive(now)),
        )
        with self.engine.begin() as c:
            return int(c.execute(q).rowcount or 0)

    # --------------------------------------------------- checkpoints/ledger
    def commit_checkpoint(
        self, ckpt: ChallengerCheckpoint, learned: Sequence[LearnedWindow]
    ) -> None:
        """Checkpoint row and the windows learned since the previous one, atomically."""
        with self.engine.begin() as c:
            c.execute(
                insert(t.challenger_checkpoints).values(
                    checkpoint_id=ckpt.checkpoint_id,
                    app_id=ckpt.app_id,
                    seq=ckpt.seq,
                    status=ckpt.status.value,
                    created_at=utc_naive(ckpt.created_at),
                    body=ckpt.model_dump_json(),
                )
            )
            for w in learned:
                c.execute(
                    insert(t.learned_windows).values(
                        fingerprint=w.fingerprint,
                        app_id=w.app_id,
                        source_ip=str(w.source_ip),
                        window_end=utc_naive(w.window_end),
                        checkpoint_id=ckpt.checkpoint_id,
                        body=w.model_dump_json(),
                    )
                )

    def checkpoints(self, app_id: str) -> list[ChallengerCheckpoint]:
        """Newest first."""
        q = (
            select(t.challenger_checkpoints.c.body)
            .where(t.challenger_checkpoints.c.app_id == app_id)
            .order_by(desc(t.challenger_checkpoints.c.seq))
        )
        with self.engine.connect() as c:
            return _load(ChallengerCheckpoint, c.execute(q).all())

    def mark_checkpoint(self, ckpt: ChallengerCheckpoint, status: CheckpointStatus) -> None:
        body = ckpt.model_copy(update={"status": status})
        with self.engine.begin() as c:
            c.execute(
                update(t.challenger_checkpoints)
                .where(t.challenger_checkpoints.c.checkpoint_id == ckpt.checkpoint_id)
                .values(status=status.value, body=body.model_dump_json())
            )

    def drop_checkpoints(self, ids: Sequence[str]) -> None:
        """Remove superseded checkpoint rows (their ledger rows are kept)."""
        if not ids:
            return
        with self.engine.begin() as c:
            c.execute(
                delete(t.challenger_checkpoints).where(
                    t.challenger_checkpoints.c.checkpoint_id.in_(list(ids))
                )
            )

    def is_learned(self, fingerprint: str) -> bool:
        q = select(t.learned_windows.c.fingerprint).where(
            t.learned_windows.c.fingerprint == fingerprint
        )
        with self.engine.connect() as c:
            return c.execute(q).first() is not None

    def learned(self, app_id: str, limit: int = 1000) -> list[LearnedWindow]:
        """Ledger entries, newest first."""
        q = (
            select(t.learned_windows.c.body)
            .where(t.learned_windows.c.app_id == app_id)
            .order_by(desc(t.learned_windows.c.window_end))
            .limit(limit)
        )
        with self.engine.connect() as c:
            return _load(LearnedWindow, c.execute(q).all())

    def lineage(self, app_id: str, parent_model_id: str, n_learned: int) -> list[LearnedWindow]:
        """Every window learned into a challenger of ``parent_model_id`` up to ``n_learned``."""
        q = select(t.learned_windows.c.body).where(t.learned_windows.c.app_id == app_id)
        with self.engine.connect() as c:
            rows = _load(LearnedWindow, c.execute(q).all())
        return [
            w
            for w in rows
            if w.parent_model_id == parent_model_id and w.n_learned_after <= n_learned
        ]

    # ------------------------------------------------- promotion lifecycle
    def add_evaluation(self, ev: ChallengerEvaluation) -> None:
        with self.engine.begin() as c:
            c.execute(
                insert(t.challenger_evaluations).values(
                    evaluation_id=ev.evaluation_id,
                    app_id=ev.app_id,
                    evaluated_at=utc_naive(ev.evaluated_at),
                    body=ev.model_dump_json(),
                )
            )

    def evaluation(self, evaluation_id: str) -> ChallengerEvaluation | None:
        q = select(t.challenger_evaluations.c.body).where(
            t.challenger_evaluations.c.evaluation_id == evaluation_id
        )
        with self.engine.connect() as c:
            rows = _load(ChallengerEvaluation, c.execute(q).all())
        return rows[0] if rows else None

    def evaluations(self, app_id: str, limit: int = 20) -> list[ChallengerEvaluation]:
        """Newest first."""
        q = (
            select(t.challenger_evaluations.c.body)
            .where(t.challenger_evaluations.c.app_id == app_id)
            .order_by(desc(t.challenger_evaluations.c.evaluated_at))
            .limit(limit)
        )
        with self.engine.connect() as c:
            return _load(ChallengerEvaluation, c.execute(q).all())

    def save_probation(self, p: Probation) -> None:
        tbl = t.model_probations
        with self.engine.begin() as c:
            exists = c.execute(
                select(tbl.c.probation_id).where(tbl.c.probation_id == p.probation_id)
            ).first()
            values = {"status": p.status.value, "body": p.model_dump_json()}
            if exists:
                c.execute(update(tbl).where(tbl.c.probation_id == p.probation_id).values(**values))
            else:
                c.execute(
                    insert(tbl).values(
                        probation_id=p.probation_id,
                        app_id=p.app_id,
                        started_at=utc_naive(p.started_at),
                        **values,
                    )
                )

    def probations(self, app_id: str, active_only: bool = False) -> list[Probation]:
        """Newest first."""
        tbl = t.model_probations
        q = select(tbl.c.body).where(tbl.c.app_id == app_id).order_by(desc(tbl.c.started_at))
        if active_only:
            q = q.where(tbl.c.status == ProbationStatus.ACTIVE.value)
        with self.engine.connect() as c:
            return _load(Probation, c.execute(q).all())

    # ---------------------------------------------------------- shadow
    def add_shadow(self, items: Sequence[ShadowScore]) -> None:
        if not items:
            return
        with self.engine.begin() as c:
            c.execute(
                insert(t.shadow_scores),
                [
                    {
                        "app_id": s.app_id,
                        "window_end": utc_naive(s.window_end),
                        "body": s.model_dump_json(),
                    }
                    for s in items
                ],
            )

    def shadow(self, app_id: str, limit: int = 500) -> list[ShadowScore]:
        q = (
            select(t.shadow_scores.c.body)
            .where(t.shadow_scores.c.app_id == app_id)
            .order_by(desc(t.shadow_scores.c.window_end))
            .limit(limit)
        )
        with self.engine.connect() as c:
            return _load(ShadowScore, c.execute(q).all())

    def purge_shadow(self, before: datetime) -> int:
        q = delete(t.shadow_scores).where(t.shadow_scores.c.window_end < utc_naive(before))
        with self.engine.begin() as c:
            return int(c.execute(q).rowcount or 0)


def _source(row: Any) -> SourceRecord:
    return SourceRecord(
        source_ip=IPv4Address(row.source_ip),
        first_seen=_aware(row.first_seen),
        last_seen=_aware(row.last_seen),
        taint_until=_aware(row.taint_until) if row.taint_until else None,
        taint_reason=row.taint_reason,
    )


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
