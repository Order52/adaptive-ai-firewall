"""Final-year scorecard: the predeclared detection thresholds as a checkable verdict.

Input is the JSON written by ``afw experiment evaluate --out`` (aggregate plus ``per_run``).
Thresholds are fixed here and in ``docs/FINAL_YEAR_PLAN.md`` (predeclared 2026-11-21, before
any team attack run exists); they are never read from the report. Every gate is PASS, FAIL or
NOT_RUN (too few runs). A report built from synthetic data is refused: nothing it contains is a
result. The scorecard judges numbers; it generates no traffic and never creates evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

ARM = "M2"  # the ML strategy (what the controller runs when strategy: ml)
BASELINES = ("M0", "M1")  # static rules, statistical profile

# scenario -> role. "known": gated. "withheld": new-family test (own experiment). "holdout": INFO.
SCENARIOS = {
    "web-bruteforce-login": "known",
    "web-sqli-probe": "known",
    "net-portscan": "known",
    "net-ssh-guessing": "known",
    "web-content-discovery": "withheld",
    "low-and-slow-bruteforce": "holdout",
    "net-slow-scan": "holdout",
}

MIN_TEST_RUNS = 3
MIN_RUNS_PASSING = 2  # of the test runs, for D1 and D2
CONTAINED_MIN = 0.8  # D1: share of attack sources contained in a run
LATENCY_MAX_S = 180.0  # D2: median first-action latency (6 windows of 30 s)
SITE_RESTRICTED_MAX = 0  # D3: legitimate sources blocked or rate limited
LEGIT_SUCCESS_MIN = 0.98  # D3: share of legitimate requests not impacted
VALUE_OVER_STATIC_MIN = 0.2  # D4: pooled containment, M2 minus M0
VALUE_VS_STATISTICAL_TOL = 0.05  # D4: M2 may trail M1 by at most this


def _arm(run: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    for a in run.get("arms", []):
        if a.get("arm") == name:
            return a  # type: ignore[no-any-return]
    return None


def _contained(a: Mapping[str, Any]) -> float | None:
    n = a.get("attack_sources") or 0
    return a["attack_sources_contained"] / n if n else None


def _gate(gid: str, status: str, detail: str) -> dict[str, str]:
    return {"gate": gid, "status": status, "detail": detail}


_NAMES = ("D1 containment", "D2 speed", "D3 harm")


def _family(scenario: str, runs: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    if len(runs) < MIN_TEST_RUNS:
        why = f"{len(runs)} test run(s), need {MIN_TEST_RUNS}"
        return [_gate(f"{scenario}:{g}", "NOT_RUN", why) for g in _NAMES]
    arms = [a for r in runs if (a := _arm(r, ARM)) is not None]
    if len(arms) < len(runs):
        return [
            _gate(f"{scenario}:{g}", "NOT_RUN", f"arm {ARM} missing") for g in ("D1", "D2", "D3")
        ]
    cont = [_contained(a) for a in arms]
    ok1 = sum(1 for c in cont if c is not None and c >= CONTAINED_MIN)
    lat = [a.get("median_detection_latency_s") for a in arms]
    ok2 = sum(1 for v in lat if v is not None and v <= LATENCY_MAX_S)
    restricted = [a.get("benign_sources_site_restricted", 0) for a in arms]
    success = [
        a["legit_request_success"] for a in arms if a.get("legit_request_success") is not None
    ]
    mean_success = sum(success) / len(success) if success else None
    ok3 = max(restricted) <= SITE_RESTRICTED_MAX and (
        mean_success is not None and mean_success >= LEGIT_SUCCESS_MIN
    )
    per_run = [None if c is None else round(c, 2) for c in cont]
    shown_success = None if mean_success is None else round(mean_success, 3)
    return [
        _gate(
            f"{scenario}:D1 containment",
            "PASS" if ok1 >= MIN_RUNS_PASSING else "FAIL",
            f"{ok1}/{len(arms)} runs contain >= {CONTAINED_MIN:.0%} of attack sources "
            f"(need {MIN_RUNS_PASSING}); per run {per_run}",
        ),
        _gate(
            f"{scenario}:D2 speed",
            "PASS" if ok2 >= MIN_RUNS_PASSING else "FAIL",
            f"{ok2}/{len(arms)} runs act within {LATENCY_MAX_S:.0f} s (median); per run {lat}",
        ),
        _gate(
            f"{scenario}:D3 harm",
            "PASS" if ok3 else "FAIL",
            f"legitimate sources restricted per run {restricted} (max {SITE_RESTRICTED_MAX}); "
            f"legitimate request success {shown_success} "
            f"(min {LEGIT_SUCCESS_MIN})",
        ),
    ]


def _pooled(runs: Sequence[Mapping[str, Any]], name: str) -> float | None:
    got = tot = 0
    for r in runs:
        a = _arm(r, name)
        if a is not None:
            got += a.get("attack_sources_contained", 0)
            tot += a.get("attack_sources", 0)
    return got / tot if tot else None


def _value(known_runs: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    if not known_runs:
        return _gate("D4 value over baselines", "NOT_RUN", "no known-family test runs")
    m2, m0, m1 = (_pooled(known_runs, n) for n in (ARM, "M0", "M1"))
    if m2 is None or m0 is None or m1 is None:
        return _gate("D4 value over baselines", "NOT_RUN", "an arm is missing from the runs")
    ok = m2 - m0 >= VALUE_OVER_STATIC_MIN and m2 >= m1 - VALUE_VS_STATISTICAL_TOL
    return _gate(
        "D4 value over baselines",
        "PASS" if ok else "FAIL",
        f"pooled containment M2 {m2:.2f}, M1 {m1:.2f}, M0 {m0:.2f} "
        f"(need M2-M0 >= {VALUE_OVER_STATIC_MIN}, M2 >= M1-{VALUE_VS_STATISTICAL_TOL})",
    )


def scorecard(report: Mapping[str, Any]) -> dict[str, Any]:
    """Judge an ``experiment evaluate`` report against the predeclared thresholds."""
    label = str(report.get("label", ""))
    if "SYNTHETIC" in label.upper() or report.get("synthetic_datasets"):
        raise ValueError("synthetic report refused: it contains no result to judge")
    runs = list(report.get("per_run", []))
    by_scn: dict[str, list[Mapping[str, Any]]] = {}
    for r in runs:
        if r.get("purpose") == "test":
            by_scn.setdefault(str(r.get("scenario")), []).append(r)
    gates: list[dict[str, str]] = []
    known_runs: list[Mapping[str, Any]] = []
    for scn, role in SCENARIOS.items():
        if role != "known":
            continue
        gates += _family(scn, by_scn.get(scn, []))
        known_runs += by_scn.get(scn, [])
    gates.append(_value(known_runs))
    info = []
    for scn, role in SCENARIOS.items():
        if role == "known":
            continue
        rs = by_scn.get(scn, [])
        pooled = _pooled(rs, ARM)
        info.append(
            {
                "scenario": scn,
                "role": role,
                "test_runs": len(rs),
                "m2_pooled_containment": None if pooled is None else round(pooled, 3),
                "note": "withheld family: judged by the new-threat experiment "
                "(NEW_THREAT_EXPERIMENT.md), not here"
                if role == "withheld"
                else "holdout: evaluated once, reported, never gated",
            }
        )
    statuses = {g["status"] for g in gates}
    overall = "FAIL" if "FAIL" in statuses else ("NOT_RUN" if "NOT_RUN" in statuses else "PASS")
    return {"overall": overall, "gates": gates, "info": info, "arm": ARM}
