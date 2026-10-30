"""Pure feature computation shared by live scoring and offline dataset building."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from itertools import combinations

import numpy as np

from afw.domain.events import AuthOutcome, HttpObservation, Provenance
from afw.domain.features import FeatureVector, WindowSpec
from afw.telemetry.routes import is_unknown

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# CRS rule-id families -> evidence keys (context for correlation, never ML input)
CRS_FAMILIES: dict[str, range] = {
    "crs_scanner": range(913000, 914000),
    "crs_protocol": range(920000, 922000),
    "crs_lfi": range(930000, 931000),
    "crs_rfi": range(931000, 932000),
    "crs_rce": range(932000, 933000),
    "crs_php": range(933000, 934000),
    "crs_xss": range(941000, 942000),
    "crs_sqli": range(942000, 943000),
    "crs_session": range(943000, 944000),
}
_CRS_ANOMALY_RULES = range(949000, 960000)  # blocking-evaluation rules, not attack families


class EndpointCatalog:
    """Known routes/methods of the trusted profile plus owner-declared login routes."""

    def __init__(
        self,
        routes: frozenset[str],
        methods: frozenset[tuple[str, str]],
        login_routes: frozenset[str],
    ) -> None:
        self.routes = routes
        self.methods = methods
        self.login_routes = login_routes


# A request is WAF *evidence* only if CRS blocked it or its inbound anomaly score
# reaches the PL1 blocking threshold (5). Lone warnings (e.g. 920350, numeric Host
# header, 3 points) stay recorded on the observation but add no risk.
WAF_SIGNAL_MIN_SCORE = 5


def _entropy(counts: Counter[str]) -> float:
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) if total else 0.0


def _values(
    obs: Sequence[HttpObservation], window: WindowSpec, catalog: EndpointCatalog
) -> dict[str, float]:
    n = len(obs)
    length = float(window.length_s)
    routes = Counter(o.route for o in obs)
    logins = [o for o in obs if o.route in catalog.login_routes and o.method == "POST"]
    login_outcomes = [o.auth_outcome for o in logins if o.auth_outcome is not None]
    failures = sum(1 for a in login_outcomes if a is AuthOutcome.FAILURE)
    users = {o.username_hash for o in logins if o.username_hash}

    times = sorted(o.observed_at.timestamp() for o in obs)
    gaps = np.diff(np.array(times)) if n >= 3 else np.array([])
    cv = float(gaps.std() / gaps.mean()) if gaps.size and gaps.mean() > 0 else 0.0

    return {
        "req_rate": n / length,
        "route_count": float(len(routes)),
        "route_entropy": _entropy(routes),
        "unknown_route_frac": sum(
            c for r, c in routes.items() if is_unknown(r) or r not in catalog.routes
        )
        / n,
        "novel_method_frac": sum(
            1
            for o in obs
            if not is_unknown(o.route)
            and (o.route, o.method) not in catalog.methods
            and o.route in catalog.routes
        )
        / n,
        "write_frac": sum(1 for o in obs if o.method in WRITE_METHODS) / n,
        "client_err_frac": sum(1 for o in obs if 400 <= o.status < 500) / n,
        "server_err_frac": sum(1 for o in obs if o.status >= 500) / n,
        "login_rate": len(logins) * 60.0 / length,
        "auth_fail_frac": failures / len(login_outcomes) if login_outcomes else 0.0,
        "distinct_usernames": float(len(users)),
        "req_bytes_p95": float(np.percentile([o.bytes_in for o in obs], 95)),
        "interarrival_cv": min(cv, 10.0),
    }


def _auth_evidence_request(o: HttpObservation, catalog: EndpointCatalog) -> bool:
    """A request that the AUTH evidence rule counts as a failure."""
    return (
        o.route in catalog.login_routes
        and o.method == "POST"
        and o.auth_outcome is AuthOutcome.FAILURE
    )


def _waf_evidence_request(o: HttpObservation) -> bool:
    return o.waf_blocked or o.waf_anomaly_score >= WAF_SIGNAL_MIN_SCORE


def residuals(
    obs: Sequence[HttpObservation], window: WindowSpec, catalog: EndpointCatalog
) -> dict[str, dict[str, float] | None]:
    """Feature values without the requests behind AUTH and/or WAF evidence (SV-1)."""
    drop = {
        "auth": [_auth_evidence_request(o, catalog) for o in obs],
        "waf": [_waf_evidence_request(o) for o in obs],
    }
    present = [k for k, flags in drop.items() if any(flags)]
    out: dict[str, dict[str, float] | None] = {}
    for r in range(1, len(present) + 1):
        for keys in combinations(present, r):
            rest = [o for i, o in enumerate(obs) if not any(drop[k][i] for k in keys)]
            out["+".join(sorted(keys))] = _values(rest, window, catalog) if rest else None
    return out


def compute_features(
    obs: Sequence[HttpObservation],
    window: WindowSpec,
    catalog: EndpointCatalog,
    window_start: datetime,
    window_end: datetime,
) -> FeatureVector:
    if not obs:
        raise ValueError("cannot compute features for an empty window")
    n = len(obs)
    logins = [o for o in obs if o.route in catalog.login_routes and o.method == "POST"]
    login_outcomes = [o.auth_outcome for o in logins if o.auth_outcome is not None]
    failures = sum(1 for a in login_outcomes if a is AuthOutcome.FAILURE)
    values = _values(obs, window, catalog)
    evidence: dict[str, float] = {
        "waf_hit_requests": float(sum(1 for o in obs if o.waf_rule_ids)),
        "waf_signal_requests": float(
            sum(1 for o in obs if o.waf_blocked or o.waf_anomaly_score >= WAF_SIGNAL_MIN_SCORE)
        ),
        "waf_blocked": float(sum(1 for o in obs if o.waf_blocked)),
        "waf_max_anomaly": float(max(o.waf_anomaly_score for o in obs)),
        "auth_failures": float(failures),
        "login_attempts": float(len(logins)),
        "app_unjoined": float(sum(1 for o in obs if not o.app_joined and o.reached_backend)),
        "backend_requests": float(sum(1 for o in obs if o.reached_backend)),
        # Provenance (ADR-029): online learning needs every observation trusted
        # and confirmed by the application.
        "untrusted_obs": float(sum(1 for o in obs if o.provenance is Provenance.UNVERIFIED)),
        "unjoined_obs": float(sum(1 for o in obs if not o.app_joined)),
    }
    families: Counter[str] = Counter()
    for o in obs:
        for rid in o.waf_rule_ids:
            if rid in _CRS_ANOMALY_RULES:
                continue
            for fam, rng in CRS_FAMILIES.items():
                if rid in rng:
                    families[fam] += 1
    evidence.update({k: float(v) for k, v in families.items()})

    return FeatureVector(
        app_id=obs[0].app_id,
        source_ip=obs[0].client_ip,
        window_start=window_start,
        window_end=window_end,
        n_requests=n,
        values=values,
        app_versions=tuple(sorted({o.app_version for o in obs if o.app_version})),
        evidence=evidence,
        request_ids=tuple(o.request_id for o in obs[-50:]),
        residuals=residuals(obs, window, catalog),
    )
