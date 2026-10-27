"""Attack-evaluation harness (M6): scenario registry, run journal, kill switch.

The harness never generates attack traffic. The team runs standard tools from
ATK01 against lab-owned targets; this module makes those runs safe and
measurable:

* a **registry** of scenarios whose attackers must sit in the ATTACK zone and whose
  targets must be on an explicit lab-owned allowlist (management, controller and
  database networks are refused outright);
* a **journal** recording ground truth (who ran what, when it began and ended, phase
  marks), with one active run at a time;
* a **kill switch** (``abort``) and a max-duration **watchdog** that stop ATK01 through
  the GNS3 API, so an attack can always be ended from the host;
* a **manifest** generated from the journal, labelling attacker sources with the exact
  run window, ready for ``afw dataset capture``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from afw.config import LabConfig
from afw.domain.common import new_id
from afw.ml.datasets import Purpose

LAB = IPv4Network("10.77.0.0/16")
# Never an attack target, whatever a registry says.
DENY = (
    IPv4Network("10.77.50.0/24"),  # management / controller / recovery path
    IPv4Network("10.77.60.0/24"),  # database tier
)
MAX_DURATION_S = 3600


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Target(_M):
    ip: IPv4Address
    port: int = Field(ge=1, le=65535)
    proto: str = "tcp"
    name: str = ""

    def key(self) -> tuple[IPv4Address, int, str]:
        return (self.ip, self.port, self.proto)


class ScenarioSpec(_M):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,40}$")
    family: str
    description: str
    attackers: tuple[IPv4Address, ...] = Field(min_length=1)
    targets: tuple[Target, ...] = Field(min_length=1)
    purpose: Purpose = Purpose.TEST
    max_duration_s: int = Field(default=900, ge=60, le=MAX_DURATION_S)
    expected_evidence: tuple[str, ...] = ()
    team_tooling: str = Field(default="", description="free text: chosen and run by the team")


class Registry(_M):
    allowed_targets: tuple[Target, ...] = Field(min_length=1)
    scenarios: tuple[ScenarioSpec, ...] = ()

    @model_validator(mode="after")
    def _safe(self) -> Registry:
        for t in self.allowed_targets:
            if t.ip not in LAB or any(t.ip in n for n in DENY):
                raise ValueError(f"target {t.ip} is outside the lab or in a denied network")
        allowed = {t.key() for t in self.allowed_targets}
        ids = [s.id for s in self.scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate scenario id")
        for s in self.scenarios:
            bad = [str(t.ip) for t in s.targets if t.key() not in allowed]
            if bad:
                raise ValueError(f"{s.id}: targets not on the allowlist: {bad}")
        return self

    def get(self, scenario_id: str) -> ScenarioSpec:
        for s in self.scenarios:
            if s.id == scenario_id:
                return s
        raise KeyError(f"unknown scenario {scenario_id}")


def load_registry(path: Path, cfg: LabConfig) -> Registry:
    reg = Registry.model_validate(yaml.safe_load(path.read_text()))
    attack = next((z for z in cfg.zones if z.name == "ATTACK"), None)
    if attack is None:
        raise ValueError("lab config has no ATTACK zone")
    reserved = {IPv4Address("10.77.10.1"), IPv4Address("10.77.10.250")}  # FW, probe
    for s in reg.scenarios:
        for ip in s.attackers:
            if ip not in attack.network or ip in reserved:
                raise ValueError(f"{s.id}: attacker {ip} is not an ATTACK-zone client address")
    return reg


class RunStatus(StrEnum):
    RUNNING = "running"
    ENDED = "ended"
    ABORTED = "aborted"


class RunRecord(BaseModel):
    run_id: str
    scenario_id: str
    operator: str
    status: RunStatus = RunStatus.RUNNING
    begun_at: datetime
    ended_at: datetime | None = None
    marks: list[tuple[datetime, str]] = Field(default_factory=list)
    abort_reason: str = ""
    kill_result: list[str] = Field(default_factory=list)
    notes: str = ""


def _atomic_json(path: Path, data: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    tmp.write_text(data)
    tmp.replace(path)


class RunJournal:
    """Ground-truth journal on the host (one JSON file per run)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, run_id: str) -> Path:
        return self.root / f"{run_id}.json"

    def _save(self, r: RunRecord) -> RunRecord:
        _atomic_json(self._path(r.run_id), r.model_dump_json(indent=2))
        return r

    def get(self, run_id: str) -> RunRecord:
        return RunRecord.model_validate_json(self._path(run_id).read_text())

    def runs(self) -> list[RunRecord]:
        out = [RunRecord.model_validate_json(p.read_text()) for p in self.root.glob("run-*.json")]
        return sorted(out, key=lambda r: r.begun_at)

    def active(self) -> RunRecord | None:
        return next((r for r in self.runs() if r.status is RunStatus.RUNNING), None)

    def begin(self, spec: ScenarioSpec, operator: str, now: datetime, notes: str = "") -> RunRecord:
        if not operator.strip():
            raise ValueError("an operator name is required (ground truth: who ran it)")
        act = self.active()
        if act is not None:
            raise ValueError(f"run {act.run_id} is still running; end or abort it first")
        return self._save(
            RunRecord(
                run_id=new_id("run"),
                scenario_id=spec.id,
                operator=operator,
                begun_at=now,
                notes=notes,
            )
        )

    def mark(self, run_id: str, label: str, now: datetime) -> RunRecord:
        r = self._running(run_id)
        r.marks.append((now, label))
        return self._save(r)

    def end(self, run_id: str, now: datetime) -> RunRecord:
        r = self._running(run_id)
        r.status, r.ended_at = RunStatus.ENDED, now
        return self._save(r)

    def abort(
        self, run_id: str, reason: str, now: datetime, kill: Callable[[], list[str]]
    ) -> RunRecord:
        """Kill switch: stop the attack host first, then record why."""
        r = self.get(run_id)
        result = kill()
        if r.status is RunStatus.RUNNING:
            r.status, r.ended_at = RunStatus.ABORTED, now
        r.abort_reason, r.kill_result = reason, result
        return self._save(r)

    def watchdog(
        self, registry: Registry, now: datetime, kill: Callable[[], list[str]]
    ) -> RunRecord | None:
        """Abort the active run once it exceeds its scenario's max duration."""
        r = self.active()
        if r is None:
            return None
        limit = registry.get(r.scenario_id).max_duration_s
        if (now - r.begun_at).total_seconds() > limit:
            return self.abort(r.run_id, f"watchdog: exceeded max_duration_s={limit}", now, kill)
        return None

    def _running(self, run_id: str) -> RunRecord:
        r = self.get(run_id)
        if r.status is not RunStatus.RUNNING:
            raise ValueError(f"run {run_id} is {r.status.value}")
        return r


def manifest_for(
    run: RunRecord,
    spec: ScenarioSpec,
    benign: Sequence[IPv4Address] = (),
    app_id: str = "rental",
) -> dict[str, Any]:
    """Capture manifest (``afw dataset capture``) built from the journal's ground truth."""
    if run.ended_at is None:
        raise ValueError("run has not ended")
    if set(benign) & set(spec.attackers):
        raise ValueError("a source cannot be both benign and attacker")
    start, end = run.begun_at.isoformat(), run.ended_at.isoformat()
    sources: list[dict[str, Any]] = [
        {"ip": str(ip), "role": "attack", "attack_type": spec.family, "start": start, "end": end}
        for ip in spec.attackers
    ] + [{"ip": str(ip), "role": "benign"} for ip in benign]
    return {
        "app_id": app_id,
        "start": start,
        "end": end,
        "scenario": f"{spec.id}: {spec.family}",
        "seed": 0,
        "generator": f"team-run by {run.operator}; tooling: {spec.team_tooling or 'unspecified'}",
        "notes": json.dumps(
            {
                "run_id": run.run_id,
                "status": run.status.value,
                "abort_reason": run.abort_reason,
                "marks": [(t.isoformat(), m) for t, m in run.marks],
                "targets": [f"{t.ip}:{t.port}/{t.proto}" for t in spec.targets],
            }
        ),
        "sources": sources,
    }
