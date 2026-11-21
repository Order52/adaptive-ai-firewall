"""Scorecard logic on hand-made report structures. These are fixtures for the judging code,
not results: nothing here is, or is presented as, attack evidence."""

from __future__ import annotations

from typing import Any

import pytest

from afw.ml.scorecard import SCENARIOS, scorecard


def _arm(name: str, contained: int, total: int = 1, lat: float | None = 60.0, restricted: int = 0):
    return {
        "arm": name,
        "attack_sources": total,
        "attack_sources_contained": contained,
        "median_detection_latency_s": lat,
        "benign_sources_site_restricted": restricted,
        "legit_request_success": 1.0,
    }


def _run(scenario: str, m2: dict[str, Any], m0_contained: int = 0, m1_contained: int = 1):
    return {
        "scenario": scenario,
        "purpose": "test",
        "arms": [_arm("M0", m0_contained), _arm("M1", m1_contained), m2],
    }


KNOWN = [s for s, r in SCENARIOS.items() if r == "known"]


def _full(m2_factory) -> dict[str, Any]:
    return {
        "label": "lab runs",
        "per_run": [_run(s, m2_factory()) for s in KNOWN for _ in range(3)],
    }


def _status(card: dict[str, Any], gate: str) -> str:
    return next(g["status"] for g in card["gates"] if g["gate"] == gate)


def test_synthetic_report_is_refused() -> None:
    with pytest.raises(ValueError, match="synthetic"):
        scorecard({"label": "SYNTHETIC - NOT A RESULT", "per_run": []})
    with pytest.raises(ValueError, match="synthetic"):
        scorecard({"label": "lab runs", "synthetic_datasets": ["x"], "per_run": []})


def test_no_runs_is_not_run_never_pass() -> None:
    card = scorecard({"label": "lab runs", "per_run": []})
    assert card["overall"] == "NOT_RUN"
    assert {g["status"] for g in card["gates"]} == {"NOT_RUN"}


def test_two_runs_per_family_is_not_enough() -> None:
    rep = {
        "label": "lab runs",
        "per_run": [_run("web-sqli-probe", _arm("M2", 1)) for _ in range(2)],
    }
    card = scorecard(rep)
    assert _status(card, "web-sqli-probe:D1 containment") == "NOT_RUN"


def test_all_thresholds_met_passes() -> None:
    card = scorecard(_full(lambda: _arm("M2", 1)))
    assert card["overall"] == "PASS"


def test_slow_detection_fails_speed_only() -> None:
    card = scorecard(_full(lambda: _arm("M2", 1, lat=400.0)))
    assert card["overall"] == "FAIL"
    assert _status(card, "web-sqli-probe:D2 speed") == "FAIL"
    assert _status(card, "web-sqli-probe:D1 containment") == "PASS"


def test_one_restricted_legitimate_source_fails_harm() -> None:
    rep = _full(lambda: _arm("M2", 1))
    first = next(r for r in rep["per_run"] if r["scenario"] == "net-portscan")
    first["arms"][2] = _arm("M2", 1, restricted=1)
    card = scorecard(rep)
    assert _status(card, "net-portscan:D3 harm") == "FAIL"
    assert card["overall"] == "FAIL"


def test_no_value_over_static_fails() -> None:
    rep = _full(lambda: _arm("M2", 1))
    for r in rep["per_run"]:
        r["arms"][0] = _arm("M0", 1)  # static contains everything too
    card = scorecard(rep)
    assert _status(card, "D4 value over baselines") == "FAIL"


def test_holdout_and_withheld_are_reported_not_gated() -> None:
    rep = _full(lambda: _arm("M2", 1))
    rep["per_run"] += [_run("web-content-discovery", _arm("M2", 0)) for _ in range(3)]
    rep["per_run"] += [_run("net-slow-scan", _arm("M2", 0)) for _ in range(2)]
    card = scorecard(rep)
    assert card["overall"] == "PASS"  # a miss on withheld or holdout does not fail the known gates
    assert {i["scenario"] for i in card["info"]} >= {"web-content-discovery", "net-slow-scan"}


def test_validation_runs_are_not_scored() -> None:
    rep = _full(lambda: _arm("M2", 1))
    for r in rep["per_run"]:
        r["purpose"] = "validation"
    assert scorecard(rep)["overall"] == "NOT_RUN"
