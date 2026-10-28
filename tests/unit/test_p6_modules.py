"""P6: synthetic regression suite, evidence-weighted fractions, security path."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import numpy as np
import pytest

from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.features import WindowSpec
from afw.features.extract import EndpointCatalog, compute_features
from afw.ml import regression_suite as rs
from afw.ml.security_path import (
    CEILINGS,
    QUANTITIES,
    SecurityPath,
    evidence_weighted,
    quantities,
    wilson_lower,
)

T0 = dt.datetime(2026, 10, 28, 12, 0, 0, tzinfo=dt.UTC)
SRC = IPv4Address("10.77.20.140")
WIN = WindowSpec(length_s=30, hop_s=5, min_requests=3)
CAT = EndpointCatalog(
    frozenset({"/", "/cars", "/cars/{car_id}", "/login", "/booking/{booking_id}"}),
    frozenset(
        {
            ("/", "GET"),
            ("/cars", "GET"),
            ("/cars/{car_id}", "GET"),
            ("/login", "POST"),
            ("/booking/{booking_id}", "GET"),
        }
    ),
    frozenset({"/login"}),
)


def obs(i: int, route: str = "/cars", method: str = "GET", status: int = 200, **kw):
    return HttpObservation(
        event_id=f"e{i}",
        request_id=f"req{i:08d}",
        app_id="rental",
        observed_at=T0 + dt.timedelta(seconds=2 * i),
        client_ip=SRC,
        method=method,
        path=route,
        route=route,
        status=status,
        bytes_in=300,
        app_joined=True,
        reached_backend=True,
        **kw,
    )


def benign_base() -> rs.Base:
    o = (obs(0, "/"), obs(1), obs(2, "/cars/{car_id}"), obs(3, "/cars/{car_id}"))
    return rs.Base(SRC, T0, T0 + dt.timedelta(seconds=30), o)


def fv(observations):
    return compute_features(observations, WIN, CAT, T0, T0 + dt.timedelta(seconds=30))


# ------------------------------------------------------------ regression suite
@pytest.mark.parametrize(
    ("family", "check"),
    [
        (
            "brute_force",
            lambda v: v.evidence["auth_failures"] == 10 and v.values["distinct_usernames"] == 1,
        ),
        ("stuffing", lambda v: v.values["distinct_usernames"] == 10),
        ("enumeration", lambda v: v.values["unknown_route_frac"] == pytest.approx(10 / 14)),
        ("idor", lambda v: v.values["client_err_frac"] == pytest.approx(10 / 14)),
        ("scraping", lambda v: v.n_requests == 14 and v.values["client_err_frac"] == 0),
    ],
)
def test_each_family_changes_the_window_as_described(family, check):
    v = rs.case_window(family, 10, benign_base(), WIN, CAT)
    assert v.n_requests == 14 and check(v)
    assert v.window_start == T0 and v.source_ip == SRC


def test_synthetic_requests_stay_inside_the_window_and_are_labelled():
    syn = rs.synthetic("enumeration", 7, benign_base())
    assert all(T0 <= o.observed_at <= T0 + dt.timedelta(seconds=30) for o in syn)
    assert all(o.event_id.startswith("syn-") for o in syn)
    assert all(o.route.startswith("?") for o in syn)


def test_bases_are_spaced_per_source():
    o = [obs(i) for i in range(0, 600, 3)]
    windows = [
        fv([x for x in o if x.observed_at < T0 + dt.timedelta(seconds=30)]).model_copy(
            update={
                "window_start": T0 + dt.timedelta(seconds=s),
                "window_end": T0 + dt.timedelta(seconds=s + 30),
            }
        )
        for s in range(0, 1200, 30)
    ]
    b = rs.bases(windows, o, spacing_s=300)
    starts = [(x.start - T0).total_seconds() for x in b]
    assert starts == [0, 300, 600, 900]


def test_must_detect_levels_are_among_the_intensities():
    for fam, k in rs.MUST_DETECT.items():
        assert k in rs.FAMILIES[fam]


# ------------------------------------------------------ evidence-weighted fractions
def test_wilson_lower_bound_grows_with_evidence():
    assert wilson_lower(0, 0) == 0.0
    assert wilson_lower(1, 1) < 0.35  # one typo is weak evidence
    assert wilson_lower(10, 10) > 0.75
    assert wilson_lower(1, 1) < wilson_lower(3, 3) < wilson_lower(10, 10)
    assert wilson_lower(5, 10) < 0.5


def test_evidence_weighted_replaces_fractions_only():
    o = [obs(0, "/"), obs(1, "/login", "POST", 401, auth_outcome=AuthOutcome.FAILURE)]
    o += [obs(2, "/cars/{car_id}", status=404)]
    v = fv(o)
    w = evidence_weighted(v)
    assert v.values["auth_fail_frac"] == 1.0 and w.values["auth_fail_frac"] < 0.35
    assert w.values["client_err_frac"] < v.values["client_err_frac"]
    assert w.values["req_rate"] == v.values["req_rate"]


# ------------------------------------------------------------- security path
def test_calibrated_threshold_bounds_benign_flags():
    base = fv(list(benign_base().observations))
    benign = [base] * 990 + [rs.case_window("idor", 5, benign_base(), WIN, CAT)] * 10
    sp = SecurityPath(alpha=0.01)
    sp.calibrate(benign)
    assert sp.flags(benign).mean() <= 0.01


def test_ceiling_holds_however_broad_the_benign_data():
    """Even if 'benign' calibration data contained attack-sized windows, the ceiling
    still flags them: adaptation cannot loosen past it."""
    poisoned = [rs.case_window("brute_force", 20, benign_base(), WIN, CAT)] * 500
    sp = SecurityPath(alpha=0.01)
    sp.calibrate(poisoned)
    assert sp.flags(poisoned).all()
    i = QUANTITIES.index("auth_failures")
    assert sp.effective()["auth_failures"] == CEILINGS["auth_failures"]
    assert quantities(poisoned[0])[i] == 20


def test_one_typo_is_not_flagged_but_brute_force_is():
    """Calibrated on benign data where some users mistype once, a single typo is
    normal; ten failures in a window reach the ceiling."""
    clean = fv(list(benign_base().observations))
    typo_obs = obs(9, "/login", "POST", 401, auth_outcome=AuthOutcome.FAILURE)
    typo = fv([*benign_base().observations, typo_obs])
    sp = SecurityPath(alpha=0.01)
    sp.calibrate([clean] * 180 + [typo] * 20)
    brute = rs.case_window("brute_force", 10, benign_base(), WIN, CAT)
    assert sp.flags([typo, brute]).tolist() == [False, True]
    assert "auth_failures_ceiling" in sp.reasons(brute)


def test_effective_limits_never_exceed_ceilings():
    sp = SecurityPath()
    sp.thresholds = np.array([1e9] * len(QUANTITIES))
    assert all(sp.effective()[q] == CEILINGS[q] for q in QUANTITIES)
