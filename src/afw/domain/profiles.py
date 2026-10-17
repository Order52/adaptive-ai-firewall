"""Application behavioral profiles and their versioned lifecycle.

A profile is the learned description of *normal* behavior for one protected
application. Only a TRUSTED profile is used for live detection. New behavior is
learned into SHADOW/CANDIDATE versions and promoted only after review and the
evaluation gate, so attacker traffic cannot silently become "normal".
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from afw.domain.common import DomainModel
from afw.domain.features import WindowSpec


class ProfileStatus(StrEnum):
    CANDIDATE = "candidate"  # built from shadow data, awaiting review
    TRUSTED = "trusted"  # the single active profile for an application
    RETIRED = "retired"  # previously trusted, kept for rollback/audit
    REJECTED = "rejected"


class FeatureStats(DomainModel):
    """Robust distribution summary of one feature over benign windows."""

    median: float
    mad: float
    q01: float
    q05: float
    q95: float
    q99: float
    mean: float
    std: float


class EndpointStats(DomainModel):
    route: str
    method: str
    share: float = Field(ge=0, le=1)
    n_requests: int
    n_sources: int
    status_mix: dict[str, float]
    req_bytes_p95: float
    auth_fail_frac: float | None = None


class ProfileProvenance(DomainModel):
    dataset_ids: tuple[str, ...]
    n_windows: int
    n_sources: int
    app_versions: tuple[str, ...]
    max_source_share: float = Field(
        description="largest fraction of training windows contributed by one source"
    )
    excluded_windows: int = 0
    exclusion_reasons: dict[str, int] = Field(default_factory=dict)


class BehaviorProfile(DomainModel):
    profile_id: str
    app_id: str
    version: int = Field(ge=1)
    parent_version: int | None = None
    status: ProfileStatus
    created_at: datetime
    window: WindowSpec
    endpoints: tuple[EndpointStats, ...]
    features: dict[str, FeatureStats]
    provenance: ProfileProvenance
    content_hash: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None

    def known_routes(self) -> frozenset[str]:
        return frozenset(e.route for e in self.endpoints)

    def known_methods(self) -> frozenset[tuple[str, str]]:
        return frozenset((e.route, e.method) for e in self.endpoints)


class ProfileDiff(DomainModel):
    """Explainable difference between a trusted profile and a candidate."""

    app_id: str
    from_version: int
    to_version: int
    added_endpoints: tuple[str, ...]
    removed_endpoints: tuple[str, ...]
    shifted_features: dict[str, dict[str, float]]
    new_app_versions: tuple[str, ...]
