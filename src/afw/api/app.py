"""REST API and dashboard host. All mutations go through PolicyService/LearningService."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Any

import psutil
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from afw import __version__
from afw.api.auth import Principal, Role, TokenStore, require
from afw.container import Container
from afw.domain.adaptation import Feedback, FeedbackLabel
from afw.domain.common import new_id, utcnow
from afw.domain.features import FEATURE_BY_NAME, FEATURE_NAMES
from afw.domain.policy import (
    InvalidTransition,
    OperatingMode,
    PolicyIntent,
    PolicyKind,
    PolicyOrigin,
    PolicyTarget,
    RateProfile,
)
from afw.ml.inference import Strategy
from afw.policy.service import PolicyError
from afw.profiling.builder import diff_profiles
from afw.services.challenger import PromotionRefused
from afw.services.explain import explain_policy
from afw.services.learning import GateFailed

STATIC = Path(__file__).resolve().parent.parent / "dashboard" / "static"
Viewer = Annotated[Principal, Depends(require(Role.VIEWER))]
Operator = Annotated[Principal, Depends(require(Role.OPERATOR))]
Admin = Annotated[Principal, Depends(require(Role.ADMIN))]
_PROCESS = psutil.Process(os.getpid())
_STARTED = time.time()


class IntentRequest(BaseModel):
    kind: PolicyKind
    app_id: str = "rental"
    target: PolicyTarget
    duration_s: int | None = Field(default=None, ge=1)
    rate_profile: RateProfile | None = None
    reason: str = Field(default="operator request", max_length=200)


class ModeRequest(BaseModel):
    mode: OperatingMode


class StrategyRequest(BaseModel):
    strategy: Strategy


class ReasonRequest(BaseModel):
    reason: str = Field(default="", max_length=200)


class FeedbackRequest(BaseModel):
    label: FeedbackLabel
    app_id: str = "rental"
    source_ip: IPv4Address | None = None
    assessment_id: str | None = None
    policy_id: str | None = None
    note: str = Field(default="", max_length=500)


class CandidateRequest(BaseModel):
    since: datetime
    until: datetime
    attack_validation_ids: list[str] = []


class ReviewRequest(BaseModel):
    note: str = Field(min_length=3, max_length=500)


class ChallengerEvalRequest(BaseModel):
    app_id: str = "rental"
    benign_dataset_ids: list[str] = Field(min_length=1)
    attack_dataset_ids: list[str] = []


def _intent(c: Container, req: IntentRequest, who: Principal) -> PolicyIntent:
    app = c.cfg.application(req.app_id)
    return PolicyIntent(
        kind=req.kind,
        app_id=req.app_id,
        service=app.service,
        target=req.target,
        duration_s=req.duration_s,
        rate_profile=req.rate_profile,
        origin=PolicyOrigin.MCP if who.channel == "mcp" else PolicyOrigin.OPERATOR,
        requested_by=who.name,
        reason_codes=(req.reason,),
    )


def resources(c: Container) -> dict[str, Any]:
    vm = psutil.virtual_memory()
    with _PROCESS.oneshot():
        rss = _PROCESS.memory_info().rss
        cpu = _PROCESS.cpu_percent(interval=None)
    ticks = list(c.controller.tick_ms)
    return {
        "controller_rss_mb": round(rss / 2**20, 1),
        "controller_cpu_pct": cpu,
        "system_mem_available_mb": round(vm.available / 2**20),
        "system_mem_total_mb": round(vm.total / 2**20),
        "system_cpu_pct": psutil.cpu_percent(interval=None),
        "load_avg": os.getloadavg(),
        "tick_ms_p50": sorted(ticks)[len(ticks) // 2] if ticks else None,
        "tick_ms_max": max(ticks) if ticks else None,
        "uptime_s": round(time.time() - _STARTED),
        "tracked_sources": c.controller.windows.tracked_sources,
        "pending_joins": c.controller.correlator.pending,
    }


def create_app(c: Container) -> FastAPI:
    app = FastAPI(title="AI-Adaptive-Firewall", version=__version__)
    app.state.c = c
    app.state.tokens = TokenStore(c.settings.api_tokens_file)

    @app.exception_handler(PolicyError)
    @app.exception_handler(InvalidTransition)
    @app.exception_handler(GateFailed)
    @app.exception_handler(PromotionRefused)
    async def _conflict(_: Any, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    # ------------------------------------------------------------- health
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        rep = c.policy_service.last_report
        return {
            "status": "ok",
            "version": __version__,
            "mode": c.settings_repo.get_mode(),
            "strategy": c.controller.inference.strategy,
            "simulated_backends": c.simulated,
            "reconciled_since_start": c.policy_service.reconciled_since_start,
            "telemetry_degraded": c.controller.degraded(),
            "backends": [o.model_dump(mode="json") for o in rep.observed] if rep else [],
            "last_reconcile": rep.at.isoformat() if rep else None,
        }

    @app.get("/api/overview")
    def overview(_: Viewer) -> dict[str, Any]:
        ctl = c.controller
        prof = ctl.inference.profile
        now = utcnow()
        live = sorted(
            (s for s in ctl.live.values() if now - s.last_seen < timedelta(minutes=2)),
            key=lambda s: -s.risk.score,
        )[:25]
        active = c.policy_service.active()
        return {
            "mode": c.settings_repo.get_mode(),
            "strategy": ctl.inference.strategy,
            "profile": None
            if prof is None
            else {
                "app_id": prof.app_id,
                "version": prof.version,
                "hash": prof.content_hash[:12],
                "windows": prof.provenance.n_windows,
                "sources": prof.provenance.n_sources,
                "endpoints": len(prof.endpoints),
            },
            "models": [
                {
                    "detector": m.record.detector,
                    "version": m.record.version,
                    "threshold": m.record.threshold,
                    "sha256": m.record.artifact_sha256[:12],
                }
                for m in ctl.inference.models.values()
            ],
            "live_sources": [
                {
                    "source_ip": str(s.source_ip),
                    "last_seen": s.last_seen.isoformat(),
                    "risk": s.risk.score,
                    "band": s.risk.band,
                    "categories": s.risk.corroborating_categories,
                    "requests": s.features.n_requests,
                    "assessment_id": s.risk.assessment_id,
                    "detections": [
                        {
                            "detector": d.detector,
                            "score": d.score,
                            "threshold": d.threshold,
                            "anomalous": d.is_anomalous,
                            "pct": d.benign_percentile,
                        }
                        for d in s.detections
                    ],
                }
                for s in live
            ],
            "timeline": list(ctl.timeline)[-180:],
            "active_policies": [p.model_dump(mode="json") for p in active],
            "pending_approval": len(
                [p for p in c.policies_repo.recent(200) if p.state.value == "pending_approval"]
            ),
            "telemetry": c.stats.snapshot(),
            "telemetry_degraded": ctl.degraded(),
            "adaptation": ctl.drift.snapshot() if ctl.drift else None,
            "resources": resources(c),
        }

    # ------------------------------------------------------------ evidence
    @app.get("/api/events")
    def events(_: Viewer, limit: int = Query(100, le=1000), source: IPv4Address | None = None):  # type: ignore[no-untyped-def]
        return [o.model_dump(mode="json") for o in c.events.recent_observations(limit, source)]

    @app.get("/api/detections")
    def detections(_: Viewer, limit: int = Query(100, le=1000), anomalous: bool = True):  # type: ignore[no-untyped-def]
        return [
            d.model_dump(mode="json")
            for d in c.analysis.recent_detections(limit, anomalous_only=anomalous)
        ]

    @app.get("/api/assessments")
    def assessments(  # type: ignore[no-untyped-def]
        _: Viewer,
        limit: int = Query(100, le=1000),
        min_score: float = 0.0,
        source: IPv4Address | None = None,
    ):
        return [
            a.model_dump(mode="json")
            for a in c.analysis.recent_assessments(limit, min_score, source)
        ]

    @app.get("/api/assessments/{assessment_id}")
    def assessment(assessment_id: str, _: Viewer):  # type: ignore[no-untyped-def]
        a = c.analysis.get_assessment(assessment_id)
        if a is None:
            raise HTTPException(404, "not found")
        return a.model_dump(mode="json")

    @app.get("/api/sources/{ip}")
    def source(ip: IPv4Address, _: Viewer) -> dict[str, Any]:
        prof = c.controller.inference.profile
        feats = c.analysis.recent_features(utcnow() - timedelta(minutes=15), ip)
        baseline = (
            {
                n: {**prof.features[n].model_dump(), **FEATURE_BY_NAME[n].model_dump()}
                for n in FEATURE_NAMES
            }
            if prof
            else {}
        )
        return {
            "source_ip": str(ip),
            "baseline": baseline,
            "series": [
                {"t": f.window_end.isoformat(), "n": f.n_requests, **f.values} for f in feats
            ],
            "assessments": [
                a.model_dump(mode="json") for a in c.analysis.recent_assessments(50, 0, ip)
            ],
        }

    # ------------------------------------------------------------- policies
    @app.get("/api/policies")
    def policies(_: Viewer, limit: int = Query(100, le=1000)):  # type: ignore[no-untyped-def]
        return [p.model_dump(mode="json") for p in c.policies_repo.recent(limit)]

    @app.get("/api/policies/{policy_id}")
    def policy(policy_id: str, _: Viewer):  # type: ignore[no-untyped-def]
        p = c.policies_repo.get(policy_id)
        if p is None:
            raise HTTPException(404, "not found")
        return p.model_dump(mode="json")

    @app.get("/api/policies/{policy_id}/explain")
    def explain(policy_id: str, _: Viewer) -> dict[str, Any]:
        p = c.policies_repo.get(policy_id)
        if p is None:
            raise HTTPException(404, "not found")
        return explain_policy(p, c.analysis, c.events)

    @app.post("/api/policies/simulate")
    def simulate(req: IntentRequest, who: Operator) -> dict[str, Any]:
        intent = _intent(c, req, who)
        v = c.policy_service.simulate(intent, degraded=c.controller.degraded())
        return {
            "valid": v.ok,
            "errors": v.errors,
            "notes": v.notes,
            "would_auto_apply": v.auto_eligible,
            "intent": intent.model_dump(mode="json"),
        }

    @app.post("/api/policies")
    def submit(req: IntentRequest, who: Operator):  # type: ignore[no-untyped-def]
        p = c.policy_service.submit(_intent(c, req, who), degraded=c.controller.degraded())
        return p.model_dump(mode="json")

    @app.post("/api/policies/{policy_id}/approve")
    def approve(policy_id: str, who: Operator):  # type: ignore[no-untyped-def]
        return c.policy_service.approve(policy_id, who.name).model_dump(mode="json")

    @app.post("/api/policies/{policy_id}/reject")
    def reject(policy_id: str, req: ReasonRequest, who: Operator):  # type: ignore[no-untyped-def]
        return c.policy_service.reject(policy_id, who.name, req.reason).model_dump(mode="json")

    @app.post("/api/policies/{policy_id}/revoke")
    def revoke(policy_id: str, req: ReasonRequest, who: Operator):  # type: ignore[no-untyped-def]
        return c.policy_service.revoke(policy_id, who.name, req.reason).model_dump(mode="json")

    @app.post("/api/mode")
    def set_mode(req: ModeRequest, who: Admin) -> dict[str, str]:
        if req.mode is OperatingMode.AUTO and not c.policy_service.reconciled_since_start:
            raise HTTPException(409, "cannot enable automatic mode before state is reconciled")
        c.settings_repo.set_mode(req.mode, who.name)
        c.audit.record(who.name, "mode.set", req.mode.value, {})
        return {"mode": req.mode.value}

    @app.post("/api/strategy")
    def set_strategy(req: StrategyRequest, who: Admin) -> dict[str, str]:
        c.controller.set_strategy(req.strategy)
        c.audit.record(who.name, "strategy.set", req.strategy.value, {})
        return {"strategy": req.strategy.value}

    # ------------------------------------------------------ learning/adaptation
    @app.get("/api/profiles")
    def profiles(_: Viewer):  # type: ignore[no-untyped-def]
        return [p.model_dump(mode="json") for p in c.profiles.list()]

    @app.get("/api/profiles/{app_id}/diff")
    def profile_diff(app_id: str, _: Viewer, a: int, b: int):  # type: ignore[no-untyped-def]
        pa, pb = c.profiles.get(app_id, a), c.profiles.get(app_id, b)
        if pa is None or pb is None:
            raise HTTPException(404, "profile not found")
        return diff_profiles(pa, pb).model_dump(mode="json")

    @app.get("/api/models")
    def models(_: Viewer):  # type: ignore[no-untyped-def]
        return [m.model_dump(mode="json") for m in c.models.list()]

    @app.get("/api/adaptation")
    def adaptation(_: Viewer, app_id: str = "rental") -> dict[str, Any]:
        return {
            "monitor": c.controller.drift.snapshot() if c.controller.drift else None,
            "drift_reports": [d.model_dump(mode="json") for d in c.adaptation.recent_drift()],
            "evaluations": [
                {**e.model_dump(mode="json"), "passed": e.passed}
                for e in c.adaptation.evaluations(app_id)
            ],
            "feedback": [f.model_dump(mode="json") for f in c.adaptation.feedback(app_id)][:100],
            "shadow_learner": c.controller.shadow.snapshot() if c.controller.shadow else None,
        }

    @app.get("/api/learning/shadow")
    def shadow_learning(_: Viewer, app_id: str = "rental", limit: int = 200) -> dict[str, Any]:
        """Online challenger (shadow only): state, gate outcomes, champion-vs-challenger."""
        sh = c.controller.shadow
        repo = sh.repo if sh else None
        scores = repo.shadow(app_id, min(limit, 1000)) if repo else []
        valid = [s for s in scores if s.challenger_warm]
        return {
            "status": sh.snapshot() if sh else None,
            "agreement": None
            if not valid
            else {
                "windows": len(valid),
                "both_normal": sum(
                    1 for s in valid if not s.champion_anomalous and not s.challenger_anomalous
                ),
                "champion_only_anomalous": sum(
                    1 for s in valid if s.champion_anomalous and not s.challenger_anomalous
                ),
                "challenger_only_anomalous": sum(
                    1 for s in valid if s.challenger_anomalous and not s.champion_anomalous
                ),
                "both_anomalous": sum(
                    1 for s in valid if s.champion_anomalous and s.challenger_anomalous
                ),
                "note": "challenger flags use the champion threshold; the calibrated "
                "threshold is set by a promotion-gate evaluation",
            },
            "recent_shadow": [s.model_dump(mode="json") for s in scores[:50]],
            "recent_learned": [w.model_dump(mode="json") for w in repo.learned(app_id, 50)]
            if repo
            else [],
            "checkpoints": [k.model_dump(mode="json") for k in repo.checkpoints(app_id)]
            if repo
            else [],
        }

    @app.get("/api/learning/challenger")
    def challenger_status(_: Viewer, app_id: str = "rental") -> dict[str, Any]:
        """Promotion-gate evaluations and the probation of a promoted challenger."""
        return c.challenger.snapshot(app_id)

    @app.post("/api/learning/challenger/evaluate")
    def challenger_evaluate(req: ChallengerEvalRequest, who: Admin) -> dict[str, Any]:
        ev = c.challenger.evaluate(
            req.app_id, req.benign_dataset_ids, req.attack_dataset_ids, who.name
        )
        return {**ev.model_dump(mode="json"), "passed": ev.passed}

    @app.post("/api/learning/challenger/{evaluation_id}/promote")
    def challenger_promote(
        evaluation_id: str, req: ReviewRequest, who: Admin, app_id: str = "rental"
    ) -> dict[str, Any]:
        rec = c.challenger.promote(app_id, evaluation_id, who.name, req.note)
        c.controller.reload()
        return {"active_hst": rec.version, "threshold": rec.threshold}

    @app.post("/api/learning/challenger/rollback")
    def challenger_rollback(
        req: ReviewRequest, who: Admin, app_id: str = "rental"
    ) -> dict[str, Any]:
        rec = c.challenger.rollback(app_id, who.name, req.note)
        c.controller.reload()
        return {"active_hst": rec.version, "threshold": rec.threshold}

    @app.post("/api/feedback")
    def feedback(req: FeedbackRequest, who: Operator) -> dict[str, str]:
        fb = Feedback(
            feedback_id=new_id("fb"),
            created_at=utcnow(),
            author=who.name,
            **req.model_dump(),
        )
        c.adaptation.add_feedback(fb)
        if c.controller.drift:
            c.controller.drift.note_feedback(fb.label)
        if fb.label is FeedbackLabel.TRUE_POSITIVE and fb.source_ip:
            c.controller.reputation.taint(fb.source_ip, fb.created_at, "operator_feedback")
        return {"feedback_id": fb.feedback_id}

    @app.post("/api/profiles/{app_id}/candidates")
    def candidate(app_id: str, req: CandidateRequest, who: Operator) -> dict[str, Any]:
        tainted = c.controller.reputation.tainted_sources(utcnow())
        res = c.learning.build_candidate(
            app_id, req.since, req.until, tainted, req.attack_validation_ids
        )
        c.audit.record(who.name, "profile.build_candidate", app_id, {"v": res.profile.version})
        trusted = c.profiles.trusted(app_id)
        return {
            "profile_version": res.profile.version,
            "evaluation": {
                **res.evaluation.model_dump(mode="json"),
                "passed": res.evaluation.passed,
            },
            "diff": diff_profiles(trusted, res.profile).model_dump(mode="json")
            if trusted
            else None,
        }

    @app.post("/api/profiles/{app_id}/{version}/promote")
    def promote(app_id: str, version: int, req: ReviewRequest, who: Admin) -> dict[str, Any]:
        prof = c.learning.promote(app_id, version, who.name, req.note)
        c.controller.reload()
        return {"trusted_version": prof.version}

    @app.post("/api/profiles/{app_id}/{version}/rollback")
    def rollback(app_id: str, version: int, req: ReviewRequest, who: Admin) -> dict[str, Any]:
        prof = c.learning.rollback(app_id, version, who.name, req.note)
        c.controller.reload()
        return {"trusted_version": prof.version}

    @app.post("/api/profiles/{app_id}/{version}/reject")
    def reject_profile(app_id: str, version: int, req: ReviewRequest, who: Admin):  # type: ignore[no-untyped-def]
        return c.learning.reject(app_id, version, who.name, req.note).model_dump(mode="json")

    # ----------------------------------------------------------- experiments
    @app.get("/api/experiments")
    def experiments(_: Viewer, name: str | None = None):  # type: ignore[no-untyped-def]
        return c.experiments.list(name)

    @app.get("/api/audit")
    def audit(_: Viewer, limit: int = Query(100, le=1000)):  # type: ignore[no-untyped-def]
        return c.audit.recent(limit)

    @app.get("/api/resources")
    def res(_: Viewer) -> dict[str, Any]:
        return resources(c)

    # ------------------------------------------------------------- dashboard
    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC / "index.html")

    return app
