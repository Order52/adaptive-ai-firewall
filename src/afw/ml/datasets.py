"""Reproducible, run-level datasets and the separate ground-truth store.

A dataset is one complete recorded traffic run. Splits are made by *run*, never
by randomly mixing overlapping windows, which prevents temporal leakage.
Ground-truth labels live only in the dataset manifest and are read exclusively
by evaluation code (``afw.ml.evaluation``) — never by live detection.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from afw.domain.events import HttpObservation, IdsAlert
from afw.domain.features import FeatureVector
from afw.domain.network import NetworkEvent


class Purpose(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    HOLDOUT = "holdout"  # attack families never used for any tuning (Scenario E)
    DRIFT = "drift"  # legitimate application change (Scenario C)


class Role(StrEnum):
    BENIGN = "benign"
    ATTACK = "attack"
    PROBE = "probe"  # verification probes: excluded from training and metrics


class SourceLabel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: IPv4Address
    role: Role
    attack_type: str | None = None
    start: datetime | None = None
    end: datetime | None = None


class DatasetManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str
    app_id: str
    purpose: Purpose
    scenario: str
    seed: int
    start: datetime
    end: datetime
    app_versions: tuple[str, ...]
    sources: tuple[SourceLabel, ...]
    n_observations: int = 0
    observations_sha256: str = ""
    # IDS alerts of the labelled sources during the run (empty for runs captured
    # before 2026-10-28, which therefore replay without IDS evidence)
    n_ids_alerts: int = 0
    ids_sha256: str = ""
    # Suricata network events (flow/dns/tls/ssh/anomaly) of the labelled sources (N1;
    # empty for runs captured before FW01 exported them)
    n_net_events: int = 0
    net_sha256: str = ""
    generator: str = ""
    notes: str = ""

    def has_attack(self) -> bool:
        """Whether any source is labelled as an attacker."""
        return any(s.role is Role.ATTACK for s in self.sources)


class LabelIndex:
    """Window-level ground truth derived from a manifest (evaluation only)."""

    def __init__(self, manifest: DatasetManifest) -> None:
        self._labels = manifest.sources

    def label(self, fv: FeatureVector) -> Role | None:
        for s in self._labels:
            if s.ip != fv.source_ip:
                continue
            if s.start and fv.window_end < s.start:
                continue
            if s.end and fv.window_start > s.end:
                continue
            return s.role
        return None

    def attack_type(self, fv: FeatureVector) -> str | None:
        for s in self._labels:
            if s.ip == fv.source_ip and s.role is Role.ATTACK:
                return s.attack_type
        return None

    def role_at(self, ip: IPv4Address, ts: datetime) -> Role | None:
        """Role of one observation from ``ip`` at time ``ts`` (respects windows)."""
        for s in self._labels:
            if s.ip != ip:
                continue
            if s.start and ts < s.start:
                continue
            if s.end and ts > s.end:
                continue
            return s.role
        return None

    def label_ip(self, ip: IPv4Address) -> Role | None:
        """Source-level role, independent of time windows.

        Used for per-source containment accounting (an IP is treated as an
        attacker if any of its manifest labels is ATTACK). Returns ``None`` for
        sources the manifest does not label.
        """
        roles = {s.role for s in self._labels if s.ip == ip}
        for role in (Role.ATTACK, Role.BENIGN, Role.PROBE):
            if role in roles:
                return role
        return None


class DatasetStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _dir(self, dataset_id: str) -> Path:
        if not dataset_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid dataset id")
        return self.root / dataset_id

    def write(
        self,
        manifest: DatasetManifest,
        observations: Sequence[HttpObservation],
        ids_alerts: Sequence[IdsAlert] = (),
        net_events: Sequence[NetworkEvent] = (),
    ) -> Path:
        d = self._dir(manifest.dataset_id)
        d.mkdir(parents=True, exist_ok=False)
        obs_path = d / "observations.jsonl.gz"
        with gzip.open(obs_path, "wt") as fh:
            for o in sorted(observations, key=lambda o: o.observed_at):
                fh.write(o.model_dump_json() + "\n")
        digest = hashlib.sha256(obs_path.read_bytes()).hexdigest()
        ids_digest = ""
        if ids_alerts:
            ids_path = d / "ids_alerts.jsonl.gz"
            with gzip.open(ids_path, "wt") as fh:
                for a in sorted(ids_alerts, key=lambda a: a.observed_at):
                    fh.write(a.model_dump_json() + "\n")
            ids_digest = hashlib.sha256(ids_path.read_bytes()).hexdigest()
        net_digest = ""
        if net_events:
            net_path = d / "net_events.jsonl.gz"
            with gzip.open(net_path, "wt") as fh:
                for e in sorted(net_events, key=lambda e: (e.observed_at, e.event_id)):
                    fh.write(e.model_dump_json() + "\n")
            net_digest = hashlib.sha256(net_path.read_bytes()).hexdigest()
        final = manifest.model_copy(
            update={
                "n_observations": len(observations),
                "observations_sha256": digest,
                "n_ids_alerts": len(ids_alerts),
                "ids_sha256": ids_digest,
                "n_net_events": len(net_events),
                "net_sha256": net_digest,
            }
        )
        (d / "manifest.json").write_text(final.model_dump_json(indent=2))
        return d

    def manifest(self, dataset_id: str) -> DatasetManifest:
        return DatasetManifest.model_validate_json(
            (self._dir(dataset_id) / "manifest.json").read_text()
        )

    def observations(self, dataset_id: str, verify: bool = True) -> list[HttpObservation]:
        path = self._dir(dataset_id) / "observations.jsonl.gz"
        if verify:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != self.manifest(dataset_id).observations_sha256:
                raise ValueError(f"dataset {dataset_id} failed integrity check")
        with gzip.open(path, "rt") as fh:
            return [HttpObservation.model_validate(json.loads(line)) for line in fh if line.strip()]

    def ids_alerts(self, dataset_id: str) -> list[IdsAlert]:
        m = self.manifest(dataset_id)
        if not m.ids_sha256:
            return []
        path = self._dir(dataset_id) / "ids_alerts.jsonl.gz"
        if hashlib.sha256(path.read_bytes()).hexdigest() != m.ids_sha256:
            raise ValueError(f"dataset {dataset_id} IDS alerts failed integrity check")
        with gzip.open(path, "rt") as fh:
            return [IdsAlert.model_validate(json.loads(line)) for line in fh if line.strip()]

    def net_events(self, dataset_id: str) -> list[NetworkEvent]:
        m = self.manifest(dataset_id)
        if not m.net_sha256:
            return []
        path = self._dir(dataset_id) / "net_events.jsonl.gz"
        if hashlib.sha256(path.read_bytes()).hexdigest() != m.net_sha256:
            raise ValueError(f"dataset {dataset_id} network events failed integrity check")
        with gzip.open(path, "rt") as fh:
            return [NetworkEvent.model_validate(json.loads(line)) for line in fh if line.strip()]

    def list(self) -> list[DatasetManifest]:
        if not self.root.exists():
            return []
        return sorted(
            (self.manifest(p.name) for p in self.root.iterdir() if (p / "manifest.json").exists()),
            key=lambda m: m.start,
        )


def assert_disjoint(*groups: Iterable[str]) -> None:
    seen: set[str] = set()
    for g in groups:
        ids = set(g)
        overlap = seen & ids
        if overlap:
            raise ValueError(f"dataset(s) used in more than one split: {sorted(overlap)}")
        seen |= ids
