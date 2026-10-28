"""M5 telemetry v2: envelope (schema version, receipt time), IDS dedup, IDS-only view."""

from __future__ import annotations

import datetime as dt
import json
from ipaddress import IPv4Address

import pytest
from test_provenance import APP, WAF, _flush
from test_telemetry import access_line, app_line

from afw.container import build_container
from afw.domain.events import HttpObservation, IdsAlert
from afw.domain.policy import PolicyKind
from afw.ml.inference import Strategy
from afw.telemetry.correlator import SCHEMA_VERSION, to_ids_alert
from afw.telemetry.parsers.lines import classify, parse_suricata

FW = IPv4Address("10.77.50.1")
T = dt.datetime(2026, 10, 27, 12, 0, 30, tzinfo=dt.UTC)
SCANNER = "10.77.10.77"


def ids_line(
    flow_id: int = 123, severity: int = 1, src: str = SCANNER, ts: str = "12:00:00"
) -> str:
    body = json.dumps(
        {
            "timestamp": f"2026-10-27T{ts}.000000+0000",
            "event_type": "alert",
            "src_ip": src,
            "dest_ip": "10.77.30.10",
            "dest_port": 22,
            "proto": "TCP",
            "flow_id": flow_id,
            "alert": {"signature_id": 2001219, "signature": "ET SCAN ssh", "severity": severity},
        }
    )
    return "<38>1 2026-10-27T12:00:00Z fw01 suricata 123 - - " + body


@pytest.fixture
def ctl(settings):
    c = build_container(settings, simulated=True).controller
    c.clock = lambda: T
    c.inference.strategy = Strategy.ML
    return c


def test_ids_ids_are_content_derived():
    _, p = classify(ids_line())
    a, b = to_ids_alert(parse_suricata(p, "fw01")), to_ids_alert(parse_suricata(p, "fw01"))
    assert a.event_id == b.event_id and len(a.event_id) <= 40
    _, q = classify(ids_line(flow_id=124))
    assert to_ids_alert(parse_suricata(q, "fw01")).event_id != a.event_id
    assert a.schema_version == SCHEMA_VERSION == 2


def test_replayed_ids_line_is_stored_and_counted_once(ctl):
    for _ in range(3):
        ctl.ingest_line(FW, ids_line())
    assert ctl.stats.snapshot()["counts"]["duplicate_ids_event"] == 2
    assert len(ctl.correlation._ids[IPv4Address(SCANNER)]) == 1
    ra = ctl.correlation.assess_ids_only("rental", IPv4Address(SCANNER), T)
    assert ra is not None and ra.evidence[0].observed["alerts"] == 1


def test_http_observation_carries_envelope_v2(ctl):
    ctl.ingest_line(WAF, access_line(), "waf")
    ctl.ingest_line(APP, app_line(), "app")
    (obs,) = _flush(ctl)
    assert obs.schema_version == 2 and obs.received_at == T


def test_v1_records_still_load():
    legacy = {
        "event_id": "obs-1",
        "request_id": "r1",
        "app_id": "rental",
        "observed_at": "2026-10-01T00:00:00Z",
        "client_ip": "10.77.20.10",
        "method": "GET",
        "path": "/",
        "route": "/",
        "status": 200,
    }
    assert HttpObservation.model_validate(legacy).schema_version == 1
    alert = IdsAlert.model_validate(
        {
            "event_id": "ids-random",
            "observed_at": "2026-10-01T00:00:00Z",
            "sensor_id": "fw01",
            "src_ip": "10.77.10.1",
            "dst_ip": "10.77.30.10",
            "proto": "TCP",
            "signature_id": 1,
            "signature": "x",
            "severity": 2,
        }
    )
    assert alert.schema_version == 1 and alert.received_at is None


def test_ids_only_source_is_assessed_but_never_more_than_watched(ctl):
    submitted = []
    ctl.policies.submit = lambda intent, degraded=False: submitted.append(intent)
    # thresholds low enough that, without the IDS-only rule, this would be rate limited
    risk = ctl.cfg.risk.model_copy(update={"watch": 5, "rate_limit": 10, "block": 15})
    ctl.decisions.cfg = ctl.cfg.model_copy(update={"risk": risk})
    for i in range(12):  # many severity-1 alerts: maximal IDS evidence
        ctl.ingest_line(FW, ids_line(flow_id=1000 + i, ts=f"12:00:{i:02d}"))
    out = ctl.tick(T)
    (ra,) = [r for r in out if r.view == "ids_only"]
    assert ra.source_ip == IPv4Address(SCANNER) and ra.score >= 25
    assert ra.corroborating_categories == ("ids",)
    assert [p.kind for p in submitted] == [PolicyKind.WATCH]
    assert "ids_only_observe" in submitted[0].reason_codes
    # re-assessed at most once per minute
    assert not [r for r in ctl.tick(T + dt.timedelta(seconds=10)) if r.view == "ids_only"]


def test_ids_only_view_skips_protected_sources(ctl):
    for i in range(3):
        ctl.ingest_line(FW, ids_line(flow_id=i, src="10.77.50.10"))  # CTRL01 is protected
    assert not [r for r in ctl.tick(T) if r.view == "ids_only"]


def hb_line() -> str:
    return '<14>1 2026-10-27T12:00:00Z waf01 afw-heartbeat: {"hb":"2026-10-27T12:00:00Z"}'


def test_heartbeat_counts_only_on_an_authenticated_channel(ctl):
    ctl.ingest_line(WAF, hb_line())
    assert ctl.stats.snapshot()["counts"]["heartbeat_unauthenticated"] == 1
    assert ctl.stats.age("heartbeat:waf") is None
    ctl.ingest_line(WAF, hb_line(), "waf")
    assert ctl.stats.age("heartbeat:waf") is not None
    assert "role_mismatch" not in ctl.stats.snapshot()["counts"]


def test_silent_sensor_after_restart_marks_evidence_degraded(ctl, monkeypatch):
    import afw.services.runtime as rt

    assert ctl.sensor_health() == {}  # no live receiver: nothing expected
    ctl._started_at = rt.time.monotonic() - rt.HEARTBEAT_STALE_S - 1
    health = ctl.sensor_health()
    assert health["waf"]["stale"] and health["app"]["stale"]  # never (re)connected
    assert ctl.degraded()
    ctl.ingest_line(WAF, hb_line(), "waf")
    ctl.ingest_line(APP, hb_line(), "app")
    assert not any(h["stale"] for h in ctl.sensor_health().values())
    assert not ctl.degraded()


def test_ids_alerts_on_the_authenticated_channel_need_the_ids_identity(ctl):
    """P5: FW01's IDS feed over mTLS. Only the ids identity may send Suricata lines;
    a WAF or APP sensor forging IDS alerts on its own channel is dropped."""
    ctl.ingest_line(FW, ids_line(flow_id=1), "ids")
    ctl.ingest_line(WAF, ids_line(flow_id=2), "waf")
    ctl.ingest_line(FW, ids_line(flow_id=3))  # plaintext, still accepted while enabled
    counts = ctl.stats.snapshot()["counts"]
    assert counts["role_mismatch"] == 1
    assert counts["ids_authenticated"] == 1 and counts["ids_unauthenticated"] == 1
    assert len(ctl.correlation._ids[IPv4Address(SCANNER)]) == 2


def test_ids_identity_cannot_send_http_telemetry(ctl):
    ctl.ingest_line(FW, access_line(), "ids")
    assert ctl.correlator.pending == 0
    assert ctl.stats.snapshot()["counts"]["role_mismatch"] == 1
