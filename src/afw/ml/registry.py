"""Versioned model artifacts with integrity verification."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import joblib

from afw.domain.detection import ModelRecord
from afw.ml.detectors.base import Detector


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def save(self, app_id: str, model_id: str, detector: Detector) -> tuple[str, str, int]:
        buf = io.BytesIO()
        joblib.dump(detector, buf, compress=3)
        blob = buf.getvalue()
        digest = hashlib.sha256(blob).hexdigest()
        path = self.root / app_id / f"{model_id}.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        return str(path), digest, len(blob)

    def load(self, record: ModelRecord) -> Detector:
        path = Path(record.artifact_path)
        blob = path.read_bytes()
        if hashlib.sha256(blob).hexdigest() != record.artifact_sha256:
            raise ValueError(f"model artifact {record.model_id} failed integrity check")
        # Artifacts are produced locally by our own training pipeline (hash-pinned).
        detector = joblib.load(io.BytesIO(blob))
        if not isinstance(detector, Detector):
            raise TypeError("artifact is not a Detector")
        return detector
