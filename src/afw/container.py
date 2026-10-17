"""Explicit dependency wiring (composition root)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog

from afw.config import LabConfig, Settings, get_settings, load_lab_config
from afw.enforcement.memory import MemoryBackend, MemoryProbe
from afw.enforcement.probe import LabProbe, ProbeAgent
from afw.ml.datasets import DatasetStore
from afw.ml.registry import ArtifactStore
from afw.persistence.db import make_engine, upgrade
from afw.persistence.repositories import (
    SqlAdaptationRepository,
    SqlAnalysisRepository,
    SqlAuditLog,
    SqlEventRepository,
    SqlExperimentRepository,
    SqlModelRepository,
    SqlPolicyRepository,
    SqlProfileRepository,
    SqlSettingsRepository,
)
from afw.policy.service import PolicyService
from afw.policy.validator import PolicyValidator
from afw.ports.enforcement import EnforcementBackend, TrafficProbe
from afw.services.learning import LearningService
from afw.services.runtime import Controller
from afw.telemetry.stats import TelemetryStats

log = structlog.get_logger(__name__)


@dataclass
class Container:
    settings: Settings
    cfg: LabConfig
    events: SqlEventRepository
    analysis: SqlAnalysisRepository
    profiles: SqlProfileRepository
    models: SqlModelRepository
    policies_repo: SqlPolicyRepository
    adaptation: SqlAdaptationRepository
    settings_repo: SqlSettingsRepository
    audit: SqlAuditLog
    experiments: SqlExperimentRepository
    stats: TelemetryStats
    datasets: DatasetStore
    artifacts: ArtifactStore
    policy_service: PolicyService
    learning: LearningService
    controller: Controller
    backends: list[EnforcementBackend]
    simulated: bool


def _backends(
    cfg: LabConfig, simulated: bool
) -> tuple[list[EnforcementBackend], TrafficProbe | None]:
    if simulated:
        mem = MemoryBackend()
        return [mem], MemoryProbe(mem)
    backends: list[EnforcementBackend] = []
    if cfg.opnsense and cfg.opnsense.key_file.exists():
        from afw.enforcement.opnsense import OpnsenseBackend

        svc = cfg.service(cfg.applications[0].service)
        backends.append(OpnsenseBackend(cfg.opnsense, svc))
    else:
        log.warning("opnsense_backend_disabled", reason="no config/secret")
    if cfg.waf_helper and cfg.waf_helper.token_file.exists():
        from afw.enforcement.waf import WafHelperBackend

        backends.append(WafHelperBackend(cfg.waf_helper))
    else:
        log.warning("waf_backend_disabled", reason="no config/secret")
    probe: TrafficProbe | None = None
    if cfg.probes and all(a.token_file.exists() for a in cfg.probes.agents):
        probe = LabProbe(
            [
                ProbeAgent(url=a.url, owns=a.owns, token=a.token_file.read_text().strip())
                for a in cfg.probes.agents
            ],
            legit_source=cfg.probes.legitimate_source,
            timeout_s=cfg.probes.timeout_s,
        )
    return backends, probe


def build_container(
    settings: Settings | None = None, *, simulated: bool = False, migrate: bool = True
) -> Container:
    settings = settings or get_settings()
    cfg = load_lab_config(settings.config)
    url = settings.db_url()
    if migrate:
        upgrade(url)
    engine = make_engine(url)
    events = SqlEventRepository(engine)
    analysis = SqlAnalysisRepository(engine)
    profiles = SqlProfileRepository(engine)
    models = SqlModelRepository(engine)
    policies_repo = SqlPolicyRepository(engine)
    adaptation = SqlAdaptationRepository(engine)
    settings_repo = SqlSettingsRepository(engine, cfg.initial_mode)
    audit = SqlAuditLog(engine)
    experiments = SqlExperimentRepository(engine)
    stats = TelemetryStats()
    datasets = DatasetStore(Path(settings.data_dir) / "datasets")
    artifacts = ArtifactStore(settings.model_dir())
    backends, probe = _backends(cfg, simulated)
    policy_service = PolicyService(
        repo=policies_repo,
        validator=PolicyValidator(cfg),
        backends=backends,
        settings=settings_repo,
        audit=audit,
        probe=probe,
    )
    learning = LearningService(
        cfg, profiles, models, adaptation, events, datasets, artifacts, audit
    )
    controller = Controller(cfg, stats, events, analysis, adaptation, learning, policy_service)
    return Container(
        settings=settings,
        cfg=cfg,
        events=events,
        analysis=analysis,
        profiles=profiles,
        models=models,
        policies_repo=policies_repo,
        adaptation=adaptation,
        settings_repo=settings_repo,
        audit=audit,
        experiments=experiments,
        stats=stats,
        datasets=datasets,
        artifacts=artifacts,
        policy_service=policy_service,
        learning=learning,
        controller=controller,
        backends=backends,
        simulated=simulated,
    )
