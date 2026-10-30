"""Synthetic malicious-behaviour regression cases (P6, labelled SYNTHETIC).

A fixed suite that asks "does this model still notice X?" for attack-shaped behaviour
of known size. No traffic is sent: synthetic observations are added to the
observations of a real benign base window and the window's features are recomputed
with the evaluated model's own catalog, so every model is asked about the same change.

These cases measure sensitivity regression only. They are not attack-detection
results: recall on real attacks needs the team's labelled runs (Gate B).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import numpy as np

from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.features import FeatureVector, WindowSpec
from afw.features.extract import EndpointCatalog, compute_features
from afw.telemetry.routes import UNKNOWN_ROUTE_PREFIX, coarsen

# family -> intensities (synthetic requests added to one 30 s window)
FAMILIES: dict[str, tuple[int, ...]] = {
    "brute_force": (3, 5, 10, 20),
    "stuffing": (3, 5, 10, 20),
    "enumeration": (5, 10, 20, 40),
    "idor": (5, 10, 20, 40),
    "scraping": (20, 40, 80, 160),
}
# predeclared must-detect level per family (P6 §5); scraping is reported only
MUST_DETECT: dict[str, int] = {"brute_force": 10, "stuffing": 10, "enumeration": 20, "idor": 20}
_ENUM_PATHS = ("/admin", "/.env", "/backup", "/config", "/api/v1/users", "/debug", "/old", "/test")


@dataclass(frozen=True)
class Base:
    """A real benign window and its observations."""

    source: IPv4Address
    start: datetime
    end: datetime
    observations: tuple[HttpObservation, ...]


def bases(
    windows: Sequence[FeatureVector],
    observations: Sequence[HttpObservation],
    spacing_s: float = 300.0,
) -> list[Base]:
    """At most one base window per source every ``spacing_s`` seconds, in time order."""
    by_src: dict[IPv4Address, list[HttpObservation]] = {}
    for o in sorted(observations, key=lambda o: o.observed_at):
        by_src.setdefault(o.client_ip, []).append(o)
    last: dict[IPv4Address, datetime] = {}
    out: list[Base] = []
    for w in sorted(windows, key=lambda w: (w.window_end, int(w.source_ip))):
        prev = last.get(w.source_ip)
        if prev is not None and (w.window_start - prev).total_seconds() < spacing_s:
            continue
        obs = tuple(
            o
            for o in by_src.get(w.source_ip, ())
            if w.window_start <= o.observed_at <= w.window_end
        )
        if obs:
            out.append(Base(w.source_ip, w.window_start, w.window_end, obs))
            last[w.source_ip] = w.window_start
    return out


def synthetic(family: str, k: int, base: Base) -> list[HttpObservation]:
    """``k`` synthetic requests of ``family`` spread evenly over the base window."""
    if family not in FAMILIES:
        raise ValueError(f"unknown family {family}")
    tmpl = base.observations[-1]
    span = (base.end - base.start).total_seconds()
    size = int(np.median([o.bytes_in for o in base.observations]))
    out = []
    for i in range(k):
        at = base.start + timedelta(seconds=(i + 0.5) * span / k)
        fields: dict[str, object] = {
            "event_id": f"syn-{family}-{k}-{i}",
            "request_id": f"syn{family[:4]}{k:03d}{i:04d}x",
            "observed_at": at,
            "bytes_in": size,
            "waf_rule_ids": (),
            "waf_anomaly_score": 0,
            "waf_blocked": False,
            "app_joined": True,
            "reached_backend": True,
            "auth_outcome": None,
            "username_hash": None,
        }
        match family:
            case "brute_force" | "stuffing":
                user = "syn-u0" if family == "brute_force" else f"syn-u{i}"
                fields |= {
                    "method": "POST",
                    "path": "/login",
                    "route": "/login",
                    "status": 401,
                    "auth_outcome": AuthOutcome.FAILURE,
                    "username_hash": user,
                }
            case "enumeration":
                path = f"{_ENUM_PATHS[i % len(_ENUM_PATHS)]}/x{i}"
                fields |= {
                    "method": "GET",
                    "path": path,
                    "route": UNKNOWN_ROUTE_PREFIX + coarsen(path),
                    "status": 404,
                }
            case "idor":
                fields |= {
                    "method": "GET",
                    "path": f"/booking/{1000 + i}",
                    "route": "/booking/{booking_id}",
                    "status": 404,
                }
            case "scraping":
                fields |= {
                    "method": "GET",
                    "path": f"/cars/{1 + i % 40}",
                    "route": "/cars/{car_id}",
                    "status": 200,
                }
        out.append(tmpl.model_copy(update=fields))
    return out


def case_window(
    family: str, k: int, base: Base, window: WindowSpec, catalog: EndpointCatalog
) -> FeatureVector:
    obs = sorted([*base.observations, *synthetic(family, k, base)], key=lambda o: o.observed_at)
    return compute_features(obs, window, catalog, base.start, base.end)


def suite(
    base_windows: Sequence[Base], window: WindowSpec, catalog: EndpointCatalog
) -> dict[tuple[str, int], list[FeatureVector]]:
    """Every family and intensity applied to every base window."""
    return {
        (fam, k): [case_window(fam, k, b, window, catalog) for b in base_windows]
        for fam, ks in FAMILIES.items()
        for k in ks
    }
