"""Online (shadow) learning records: eligibility, ledger, checkpoints, shadow scores.

See docs/engineering/M2_ONLINE_LEARNING_DESIGN.md (ADR-028).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel


class Exclusion(StrEnum):
    """Why a window was not learned. Stage 1 = at window time, stage 2 = at release."""

    UNVERIFIED = "unverified"  # some observation lacks authenticated/curated provenance
    UNJOINED = "unjoined"  # some request not confirmed by the application
    MALFORMED = "malformed"  # missing / non-finite / out-of-range feature values
    PROTECTED = "protected"  # protected, sensor or probe address
    NEGATIVE_EVIDENCE = "negative_evidence"  # WAF / IDS / AUTH evidence in the window
    CHAMPION_ANOMALOUS = "champion_anomalous"  # a trusted detector flagged the window
    SENSITIVE_RANGE = "sensitive_range"  # security-sensitive feature above trusted q99
    OVERLAP = "overlap"  # overlaps a window already taken for this source
    DUPLICATE = "duplicate"  # at/behind the persisted watermark or already in the ledger
    TAINTED = "tainted"  # source carries a live taint
    LATE_TAINT = "late_taint"  # source tainted / policed / reported during quarantine
    TENURE = "tenure"  # source first seen too recently
    SOURCE_RATE = "source_rate"  # per-source hourly admission cap reached
    SOURCE_SHARE = "source_share"  # source would dominate recent learning
    POPULATION = "population"  # too few distinct sources released recently
    QUARANTINE_FULL = "quarantine_full"  # bounded quarantine overflowed
    NO_CHALLENGER = "no_challenger"  # no trusted HST champion to adapt from


class SourceRecord(DomainModel):
    """Persisted per-source reputation used only to gate learning (never enforcement)."""

    source_ip: IPv4Address
    first_seen: datetime
    last_seen: datetime
    taint_until: datetime | None = None
    taint_reason: str | None = None

    def tainted(self, now: datetime) -> bool:
        return self.taint_until is not None and now < self.taint_until


class LearnedWindow(DomainModel):
    """Prequential ledger entry: the challenger scored the window *before* learning it."""

    fingerprint: str = Field(description="sha256 of app, source, bounds and request ids")
    app_id: str
    source_ip: IPv4Address
    window_start: datetime
    window_end: datetime
    learned_at: datetime
    challenger_score_before: float
    champion_score: float
    challenger_warm_before: bool
    n_learned_after: int


class CheckpointStatus(StrEnum):
    VALID = "valid"
    CORRUPT = "corrupt"


class ChallengerCheckpoint(DomainModel):
    checkpoint_id: str
    app_id: str
    seq: int = Field(ge=1)
    created_at: datetime
    status: CheckpointStatus = CheckpointStatus.VALID
    format_version: int
    parent_model_id: str = Field(description="trusted HST champion the challenger descends from")
    parent_sha256: str
    feature_names: tuple[str, ...]
    artifact_path: str
    sha256: str
    size_bytes: int
    n_learned: int
    watermarks: dict[str, datetime] = Field(
        description="source ip -> window_end of its last learned window (replay guard)"
    )
    state: dict[str, float | int] = Field(default_factory=dict)


class ShadowScore(DomainModel):
    """Champion vs challenger on one live window. Never read by enforcement."""

    app_id: str
    source_ip: IPv4Address
    window_end: datetime
    champion_score: float
    champion_anomalous: bool
    challenger_score: float
    challenger_anomalous: bool
    challenger_warm: bool
    n_learned: int
    threshold: float
