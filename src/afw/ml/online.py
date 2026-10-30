"""Online (prequential) Half-Space-Trees challenger and its crash-safe checkpoints.

The challenger is a deep copy of the trusted profile's hash-verified HST
artifact, updated one admitted window at a time: every window is scored
*before* it is learned (prequential), and the pre-learning score is kept.
The champion artifact is never written. See ADR-028.

River HST facts this module depends on (River 0.26.1):
* ``score_one`` returns 0 until the first ``window_size`` samples were learned
  (``_first_window``): a cold model calls everything normal -> ``warm`` flag.
* scores use the reference mass, which pivots every ``window_size`` learns, so
  predictions change in steps while internal mass/counters change every learn.
"""

from __future__ import annotations

import copy
import hashlib
import io
import math
import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from afw.domain.common import new_id
from afw.domain.detection import ModelRecord
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.learning import ChallengerCheckpoint, CheckpointStatus, LearnedWindow
from afw.ml.detectors.hst import HalfSpaceTreesDetector

FORMAT_VERSION = 1

# Valid value ranges (inclusive) of every feature; anything else is malformed.
_UPPER = {
    "unknown_route_frac": 1.0,
    "novel_method_frac": 1.0,
    "write_frac": 1.0,
    "client_err_frac": 1.0,
    "server_err_frac": 1.0,
    "auth_fail_frac": 1.0,
    "interarrival_cv": 10.0,
}


def malformed(fv: FeatureVector) -> str | None:
    """Reason the feature vector cannot be learned from, or None if valid."""
    missing = [n for n in FEATURE_NAMES if n not in fv.values]
    if missing:
        return f"missing:{missing[0]}"
    for name in FEATURE_NAMES:
        v = fv.values[name]
        if not math.isfinite(v) or v < 0:
            return f"invalid:{name}"
        if v > _UPPER.get(name, math.inf):
            return f"range:{name}"
    return None


def fingerprint(fv: FeatureVector) -> str:
    raw = "|".join(
        (
            fv.app_id,
            str(fv.source_ip),
            fv.window_start.isoformat(),
            fv.window_end.isoformat(),
            ",".join(fv.request_ids),
        )
    )
    return hashlib.sha256(raw.encode()).hexdigest()


class OnlineChallenger:
    def __init__(self, detector: HalfSpaceTreesDetector, parent: ModelRecord, n_learned: int = 0):
        if detector.profile_version != parent.profile_version:
            raise ValueError("challenger and parent belong to different profiles")
        self.detector = detector
        self.parent = parent
        self.n_learned = n_learned

    @classmethod
    def from_champion(
        cls, champion: HalfSpaceTreesDetector, parent: ModelRecord
    ) -> OnlineChallenger:
        """Warm start: an independent deep copy; the champion is never mutated."""
        return cls(copy.deepcopy(champion), parent)

    @property
    def warm(self) -> bool:
        return not bool(self.detector.model._first_window)

    def score(self, fv: FeatureVector) -> float:
        row = np.array(fv.as_row(), dtype=float)
        return float(self.detector.score(row[None, :])[0])

    def score_then_learn(self, fv: FeatureVector) -> tuple[float, bool]:
        """Prequential step: (score before learning, warm before learning)."""
        warm = self.warm
        before = self.score(fv)
        self.detector.learn_one(np.array(fv.as_row(), dtype=float))
        self.n_learned += 1
        return before, warm

    def state(self) -> dict[str, float | int]:
        """Observable internal state, used to prove learning actually happened."""
        m = self.detector.model
        nodes = [n for tree in getattr(m, "_tree_nodes", []) for n in tree]
        return {
            "n_learned": self.n_learned,
            "counter": int(m.counter),
            "warm": int(self.warm),
            "window_size": int(m.window_size),
            "l_mass_total": float(sum(n.l_mass for n in nodes)),
            "r_mass_total": float(sum(n.r_mass for n in nodes)),
        }

    def blob(self) -> bytes:
        buf = io.BytesIO()
        joblib.dump(self.detector, buf, compress=3)
        return buf.getvalue()


def _atomic_write(path: Path, blob: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with tmp.open("wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)
    dir_fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class CheckpointStore:
    """Atomic checkpoint files + a DB row (with the ledger) committed in one transaction.

    A file without a DB row is an orphan and ignored; a DB row whose file is
    missing or fails its sha256 is marked corrupt and skipped. Files are
    hash-verified *before* unpickling.
    """

    def __init__(self, root: Path, repo: Any, keep: int = 3) -> None:
        self.root = root
        self.repo = repo
        self.keep = keep

    def save(
        self,
        ch: OnlineChallenger,
        *,
        app_id: str,
        watermarks: dict[str, datetime],
        learned: Sequence[LearnedWindow],
        now: datetime,
    ) -> ChallengerCheckpoint:
        existing = self.repo.checkpoints(app_id)
        seq = (existing[0].seq + 1) if existing else 1
        blob = ch.blob()
        ckpt_id = new_id("ckpt")
        path = self.root / app_id / f"{ckpt_id}.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, blob)
        ckpt = ChallengerCheckpoint(
            checkpoint_id=ckpt_id,
            app_id=app_id,
            seq=seq,
            created_at=now,
            format_version=FORMAT_VERSION,
            parent_model_id=ch.parent.model_id,
            parent_sha256=ch.parent.artifact_sha256,
            feature_names=FEATURE_NAMES,
            artifact_path=str(path),
            sha256=hashlib.sha256(blob).hexdigest(),
            size_bytes=len(blob),
            n_learned=ch.n_learned,
            watermarks=dict(watermarks),
            state=ch.state(),
        )
        self.repo.commit_checkpoint(ckpt, learned)
        self._prune(app_id)
        return ckpt

    def _prune(self, app_id: str) -> None:
        old = self.repo.checkpoints(app_id)[self.keep :]
        self.repo.drop_checkpoints([c.checkpoint_id for c in old])
        for c in old:
            Path(c.artifact_path).unlink(missing_ok=True)

    def restore(
        self, app_id: str, parent: ModelRecord
    ) -> tuple[OnlineChallenger, ChallengerCheckpoint] | None:
        """Newest valid, compatible checkpoint of this champion; None if there is none."""
        for ckpt in self.repo.checkpoints(app_id):
            if ckpt.status is CheckpointStatus.CORRUPT:
                continue
            if (
                ckpt.format_version != FORMAT_VERSION
                or ckpt.parent_model_id != parent.model_id
                or ckpt.parent_sha256 != parent.artifact_sha256
                or tuple(ckpt.feature_names) != FEATURE_NAMES
            ):
                continue  # descends from another champion / format: not ours
            loaded = self._load(ckpt, parent)
            if loaded is None:
                self.repo.mark_checkpoint(ckpt, CheckpointStatus.CORRUPT)
                continue
            return loaded, ckpt
        return None

    def _load(self, ckpt: ChallengerCheckpoint, parent: ModelRecord) -> OnlineChallenger | None:
        path = Path(ckpt.artifact_path)
        try:
            blob = path.read_bytes()
        except OSError:
            return None
        if hashlib.sha256(blob).hexdigest() != ckpt.sha256:
            return None
        try:
            det = joblib.load(io.BytesIO(blob))  # hash-verified local artifact
        except Exception:
            return None
        if not isinstance(det, HalfSpaceTreesDetector):
            return None
        try:
            ch = OnlineChallenger(det, parent, n_learned=ckpt.n_learned)
        except ValueError:
            return None
        return ch
