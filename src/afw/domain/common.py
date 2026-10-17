"""Shared domain primitives."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class DomainModel(BaseModel):
    """Immutable, strictly validated base for domain value objects."""

    model_config = ConfigDict(frozen=True, extra="forbid")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def stable_hash(payload: Any) -> str:
    """Deterministic SHA-256 of a JSON-serialisable payload (sorted keys)."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()
