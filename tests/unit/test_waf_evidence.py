"""WAF evidence calibration (regressions found on the GNS3 lab, 2026-10-17)."""

from __future__ import annotations

import random
from datetime import timedelta
from ipaddress import IPv4Address

from conftest import T0
from fixtures.synthetic import _obs

from afw.container import build_container
from afw.correlation.engine import CorrelationEngine
from afw.domain.features import WindowSpec
from afw.features.extract import EndpointCatalog, compute_features
from afw.telemetry.parsers.lines import parse_waf_audit

RID = "a" * 32


def _audit(messages, http_code=200):
    return {
        "transaction": {
            "client_ip": "10.77.20.10",
            "time_stamp": "Sat Oct 17 13:48:48 2026",
            "unique_id": RID,
            "response": {"http_code": http_code},
            "messages": messages,
        }
    }


# Shape copied from a real WAF01 audit record (numeric Host header, CRS 4.25.2).
HOST_IS_IP = {
    "message": "Host header is a numeric IP address",
    "details": {"ruleId": "920350", "severity": "4", "data": "10.77.30.10"},
}


def test_sub_threshold_warning_scores_from_severity():
    a = parse_waf_audit(_audit([HOST_IS_IP]))
    assert a.rule_ids == (920350,)
    assert a.anomaly_score == 3
    assert not a.blocked


def test_reported_total_and_severity_sum_take_the_max():
    sqli = {"message": "SQLi", "details": {"ruleId": "942100", "severity": "2"}}
    total = {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 8)",
        "details": {"ruleId": "949110", "severity": "0"},
    }
    a = parse_waf_audit(_audit([HOST_IS_IP, sqli, total], http_code=403))
    assert a.anomaly_score == 8  # 3 + 5 summed, reporting rule 949110 adds nothing
    assert a.blocked


def _window(waf_scores):
    rng = random.Random(3)
    obs = []
    for i, score in enumerate(waf_scores):
        o = _obs(rng, T0 + timedelta(seconds=i), "10.77.20.10", "GET", "/cars", 200)
        obs.append(o.model_copy(update={"waf_rule_ids": (920350,), "waf_anomaly_score": score}))
    cat = EndpointCatalog(frozenset({"/cars"}), frozenset({("GET", "/cars")}), frozenset())
    return compute_features(obs, WindowSpec(), cat, T0, T0 + timedelta(seconds=30))


def test_lone_warnings_are_not_risk_evidence(lab_cfg):
    fv = _window([3, 3, 3, 3])
    assert fv.evidence["waf_hit_requests"] == 4
    assert fv.evidence["waf_signal_requests"] == 0
    assert CorrelationEngine(lab_cfg.risk)._waf(fv) == []


def test_threshold_matches_are_evidence(lab_cfg):
    fv = _window([3, 5, 7])
    assert fv.evidence["waf_signal_requests"] == 2
    (item,) = CorrelationEngine(lab_cfg.risk)._waf(fv)
    assert item.points >= 10


def test_waf_sensor_self_traffic_is_dropped(settings):
    c = build_container(settings, simulated=True)
    rng = random.Random(5)
    sensor = _obs(rng, T0, "10.77.30.10", "GET", "/health", 200)
    client = _obs(rng, T0, "10.77.20.10", "GET", "/cars", 200)
    c.controller.correlator.flush = lambda: [sensor, client]  # type: ignore[method-assign]
    c.controller.tick(T0 + timedelta(seconds=1))
    seen = {str(o.client_ip) for o in c.events.recent_observations(10)}
    assert seen == {"10.77.20.10"}
    assert c.stats.snapshot()["counts"]["sensor_self"] == 1
    assert IPv4Address("10.77.30.10") in c.cfg.telemetry.waf_sensor_ips
