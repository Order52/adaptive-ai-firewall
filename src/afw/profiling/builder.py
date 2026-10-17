"""Build versioned behavioral profiles from benign, provenance-tracked data.

Anti-poisoning measures applied to *every* profile build (trusted or shadow):
* windows with WAF hits, IDS alerts or any policy/feedback against the source
  are excluded (the exclusion predicate is supplied by the caller);
* no single source may contribute more than ``max_source_share`` of the
  windows — dominant sources are deterministically down-sampled;
* a minimum number of distinct sources is required.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime
from ipaddress import IPv4Address

import numpy as np

from afw.domain.common import new_id, stable_hash
from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.features import FEATURE_NAMES, FeatureVector, WindowSpec
from afw.domain.profiles import (
    BehaviorProfile,
    EndpointStats,
    FeatureStats,
    ProfileDiff,
    ProfileProvenance,
    ProfileStatus,
)
from afw.telemetry.routes import is_unknown


class InsufficientData(ValueError):
    pass


ExclusionRule = Callable[[FeatureVector], str | None]


def default_exclusion(fv: FeatureVector) -> str | None:
    if fv.evidence.get("waf_hit_requests", 0) > 0:
        return "waf_evidence"
    if fv.evidence.get("ids_alerts", 0) > 0:
        return "ids_evidence"
    return None


def cap_source_share(
    vectors: Sequence[FeatureVector], max_share: float, seed: int = 7
) -> tuple[list[FeatureVector], int]:
    by_src: dict[IPv4Address, list[FeatureVector]] = defaultdict(list)
    for v in vectors:
        by_src[v.source_ip].append(v)
    if len(by_src) <= 1:
        return list(vectors), 0
    # Iteratively cap: a source's windows <= max_share * total (after capping).
    rng = random.Random(seed)
    counts = {s: len(v) for s, v in by_src.items()}
    for _ in range(10):
        total = sum(counts.values())
        cap = max(1, int(max_share * total))
        over = {s for s, c in counts.items() if c > cap}
        if not over:
            break
        for s in over:
            counts[s] = cap
    kept: list[FeatureVector] = []
    dropped = 0
    for s, items in sorted(by_src.items(), key=lambda kv: str(kv[0])):
        if counts[s] < len(items):
            chosen = sorted(rng.sample(range(len(items)), counts[s]))
            kept.extend(items[i] for i in chosen)
            dropped += len(items) - counts[s]
        else:
            kept.extend(items)
    kept.sort(key=lambda v: v.window_end)
    return kept, dropped


def _feature_stats(values: np.ndarray) -> FeatureStats:
    med = float(np.median(values))
    q = np.percentile(values, [1, 5, 95, 99])
    return FeatureStats(
        median=med,
        mad=float(np.median(np.abs(values - med))),
        q01=float(q[0]),
        q05=float(q[1]),
        q95=float(q[2]),
        q99=float(q[3]),
        mean=float(values.mean()),
        std=float(values.std()),
    )


def _endpoint_stats(observations: Sequence[HttpObservation]) -> tuple[EndpointStats, ...]:
    groups: dict[tuple[str, str], list[HttpObservation]] = defaultdict(list)
    for o in observations:
        if not is_unknown(o.route):
            groups[(o.route, o.method)].append(o)
    total = sum(len(g) for g in groups.values()) or 1
    out: list[EndpointStats] = []
    for (route, method), items in sorted(groups.items()):
        statuses = Counter(f"{o.status // 100}xx" for o in items)
        auths = [o.auth_outcome for o in items if o.auth_outcome is not None]
        out.append(
            EndpointStats(
                route=route,
                method=method,
                share=len(items) / total,
                n_requests=len(items),
                n_sources=len({o.client_ip for o in items}),
                status_mix={k: v / len(items) for k, v in sorted(statuses.items())},
                req_bytes_p95=float(np.percentile([o.bytes_in for o in items], 95)),
                auth_fail_frac=(
                    sum(1 for a in auths if a is AuthOutcome.FAILURE) / len(auths)
                    if auths
                    else None
                ),
            )
        )
    return tuple(out)


def build_profile(
    *,
    app_id: str,
    version: int,
    parent_version: int | None,
    window: WindowSpec,
    vectors: Sequence[FeatureVector],
    observations: Sequence[HttpObservation],
    dataset_ids: Sequence[str],
    created_at: datetime,
    exclusion: ExclusionRule = default_exclusion,
    max_source_share: float = 0.35,
    min_sources: int = 3,
    min_windows: int = 200,
    min_endpoint_sources: int = 2,
) -> BehaviorProfile:
    reasons: Counter[str] = Counter()
    clean: list[FeatureVector] = []
    for v in vectors:
        why = exclusion(v)
        if why:
            reasons[why] += 1
        else:
            clean.append(v)
    kept, dropped = cap_source_share(clean, max_share=max_source_share)
    if dropped:
        reasons["source_share_cap"] += dropped
    sources = {v.source_ip for v in kept}
    if len(sources) < min_sources:
        raise InsufficientData(f"{len(sources)} sources < required {min_sources}")
    if len(kept) < min_windows:
        raise InsufficientData(f"{len(kept)} windows < required {min_windows}")

    matrix = np.array([v.as_row() for v in kept], dtype=float)
    features = {name: _feature_stats(matrix[:, i]) for i, name in enumerate(FEATURE_NAMES)}
    # Endpoints only from clean sources, and only those used by several sources
    clean_sources = sources
    eps = tuple(
        e
        for e in _endpoint_stats([o for o in observations if o.client_ip in clean_sources])
        if e.n_sources >= min_endpoint_sources
    )
    share = Counter(v.source_ip for v in kept)
    provenance = ProfileProvenance(
        dataset_ids=tuple(dataset_ids),
        n_windows=len(kept),
        n_sources=len(sources),
        app_versions=tuple(sorted({ver for v in kept for ver in v.app_versions})),
        max_source_share=max(share.values()) / len(kept),
        excluded_windows=sum(reasons.values()),
        exclusion_reasons=dict(reasons),
    )
    body = {
        "app_id": app_id,
        "window": window.model_dump(),
        "endpoints": [e.model_dump() for e in eps],
        "features": {k: v.model_dump() for k, v in features.items()},
        "provenance": provenance.model_dump(),
    }
    return BehaviorProfile(
        profile_id=new_id("prof"),
        app_id=app_id,
        version=version,
        parent_version=parent_version,
        status=ProfileStatus.CANDIDATE,
        created_at=created_at,
        window=window,
        endpoints=eps,
        features=features,
        provenance=provenance,
        content_hash=stable_hash(body),
    )


def diff_profiles(old: BehaviorProfile, new: BehaviorProfile) -> ProfileDiff:
    old_eps = {f"{e.method} {e.route}" for e in old.endpoints}
    new_eps = {f"{e.method} {e.route}" for e in new.endpoints}
    shifted: dict[str, dict[str, float]] = {}
    for name in FEATURE_NAMES:
        a, b = old.features[name], new.features[name]
        scale = max(a.mad * 1.4826, abs(a.median) * 0.05, 1e-6)
        z = (b.median - a.median) / scale
        if abs(z) >= 1.0 or abs(b.q95 - a.q95) > max(abs(a.q95) * 0.25, 1e-6):
            shifted[name] = {
                "old_median": a.median,
                "new_median": b.median,
                "old_q95": a.q95,
                "new_q95": b.q95,
                "median_shift_mad": round(z, 3),
            }
    return ProfileDiff(
        app_id=new.app_id,
        from_version=old.version,
        to_version=new.version,
        added_endpoints=tuple(sorted(new_eps - old_eps)),
        removed_endpoints=tuple(sorted(old_eps - new_eps)),
        shifted_features=shifted,
        new_app_versions=tuple(
            sorted(set(new.provenance.app_versions) - set(old.provenance.app_versions))
        ),
    )
