from __future__ import annotations

import json
from ipaddress import IPv4Address

import pytest

from afw.domain.events import AuthOutcome
from afw.telemetry.correlator import RequestCorrelator
from afw.telemetry.parsers.lines import (
    ParseError,
    classify,
    parse_app,
    parse_suricata,
    parse_waf_access,
    parse_waf_audit,
)
from afw.telemetry.routes import RouteMatcher, is_unknown
from afw.telemetry.stats import TelemetryStats

RID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def access_line(rid: str = RID, src: str = "10.77.10.10", uri: str = "/login", status: int = 401):
    payload = {
        "ts": "1790000000.123",
        "rid": rid,
        "src": src,
        "method": "POST",
        "uri": uri,
        "status": status,
        "req_len": 420,
        "bytes": 310,
        "rt": "0.012",
        "upstream_status": str(status),
        "ua": "k6/1.0",
        "app": "rental",
        "xff_received": "1.2.3.4",
    }
    return "<134>Oct 17 12:00:00 waf01 afw-waf-access: " + json.dumps(payload)


def app_line(rid: str = RID, auth: str | None = "failure"):
    payload = {
        "rid": rid,
        "app": "rental",
        "ver": "1.0.0",
        "route": "/login",
        "method": "POST",
        "status": 401,
        "auth": auth,
        "user_h": "abcd",
        "ts": 1790000000.130,
    }
    return "<134>Oct 17 12:00:00 app01 afw-app: " + json.dumps(payload)


def audit_line(rid: str = RID):
    payload = {
        "transaction": {
            "client_ip": "10.77.10.10",
            "time_stamp": "Fri Oct 17 12:00:00 2026",
            "unique_id": rid,
            "response": {"http_code": 403},
            "messages": [
                {
                    "message": "SQL Injection Attack Detected via libinjection",
                    "details": {"ruleId": "942100", "severity": "2", "data": ""},
                },
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Score: 10)",
                    "details": {"ruleId": "949110", "data": ""},
                },
            ],
        }
    }
    return "<134>Oct 17 12:00:00 waf01 afw-waf-audit: " + json.dumps(payload)


def test_access_uses_transport_peer_not_forwarded_header():
    kind, p = classify(access_line())
    assert kind == "afw-waf-access"
    rec = parse_waf_access(p)
    assert rec.client_ip == IPv4Address("10.77.10.10")
    assert rec.app_id == "rental"


def test_audit_extracts_rules_score_and_block():
    _, p = classify(audit_line())
    rec = parse_waf_audit(p)
    assert rec.rule_ids == (942100, 949110)
    assert rec.anomaly_score == 10
    assert rec.blocked


def test_suricata_alert():
    line = json.dumps(
        {
            "timestamp": "2026-10-17T12:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.77.10.10",
            "dest_ip": "10.77.30.10",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 123,
            "alert": {"signature_id": 9000001, "signature": "AFW lab test", "severity": 2},
        }
    )
    kind, p = classify("<38>1 2026-10-17T12:00:00Z fw01 suricata 123 - - " + line)
    assert kind == "suricata"
    assert parse_suricata(p, "fw01").signature_id == 9000001


@pytest.mark.parametrize(
    "line,reason",
    [
        ("no json here", "no_json"),
        ("afw-app: {bad", "bad_json"),
        (
            "afw-waf-access: "
            + json.dumps({"rid": "x", "src": "1.2.3.4", "uri": "/", "status": 200, "ts": 1}),
            "bad_request_id",
        ),
    ],
)
def test_parse_errors_are_classified(line, reason):
    with pytest.raises(ParseError) as exc:
        kind, p = classify(line)
        parse_waf_access(p) if kind == "afw-waf-access" else parse_app(p)
    assert exc.value.reason == reason


def test_ipv6_rejected():
    _, p = classify(access_line(src="2001:db8::1"))
    with pytest.raises(ParseError, match="ipv6"):
        parse_waf_access(p)


def make_correlator():
    return RequestCorrelator(
        default_app="rental",
        matchers={"rental": RouteMatcher(["/login", "/cars/{car_id}"])},
        stats=TelemetryStats(),
        join_wait_s=1.0,
    )


def test_join_access_app_audit_and_dedupe():
    c = make_correlator()
    c.add_app(parse_app(classify(app_line())[1]), now=0.0)
    c.add_access(parse_waf_access(classify(access_line())[1]), now=0.1)
    c.add_audit(parse_waf_audit(classify(audit_line())[1]), now=0.2)
    obs = c.flush(now=0.3)
    assert len(obs) == 1
    o = obs[0]
    assert o.auth_outcome is AuthOutcome.FAILURE and o.app_joined
    assert o.waf_rule_ids == (942100, 949110)
    # replay of the same request id is ignored
    c.add_access(parse_waf_access(classify(access_line())[1]), now=1.0)
    assert c.flush(now=5.0) == []
    assert c.stats.snapshot()["counts"]["duplicate"] == 1


def test_orphan_app_record_is_not_trusted():
    c = make_correlator()
    c.add_app(parse_app(classify(app_line(rid="f" * 32))[1]), now=0.0)
    assert c.flush(now=2.0) == []
    assert c.stats.snapshot()["counts"]["orphan_app"] == 1


def test_waf_only_request_waits_then_emits_unjoined():
    c = make_correlator()
    c.add_access(parse_waf_access(classify(access_line(uri="/cars/12", status=200))[1]), now=0.0)
    assert c.flush(now=0.5) == []
    (o,) = c.flush(now=1.1)
    assert o.route == "/cars/{car_id}" and not o.app_joined and o.auth_outcome is None


def test_route_matcher_coarsens_unknown_paths():
    m = RouteMatcher(["/cars", "/cars/{car_id}"])
    assert m.match("/cars/") == "/cars"
    assert m.match("/cars/7?x=1") == "/cars/{car_id}"
    unknown = m.match("/admin/12345/secret/x")
    assert is_unknown(unknown) and unknown == "?/admin/{id}/secret"
