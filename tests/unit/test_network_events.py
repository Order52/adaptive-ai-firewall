"""N1: Suricata EVE network events (flow/dns/tls/ssh/anomaly) as NetworkEvent."""

from __future__ import annotations

import datetime as dt
import json
from ipaddress import IPv4Address

import pytest
from test_telemetry_v2 import FW, SCANNER, T, ctl, ids_line  # noqa: F401 (fixture)

from afw.domain.network import FlowState, NetKind
from afw.telemetry.parsers.lines import ParseError, classify, parse_suricata_net

WAF = "10.77.30.10"


def eve(event_type: str, src: str = SCANNER, ts: str = "12:00:10", **extra) -> dict:
    return {
        "timestamp": f"2026-10-27T{ts}.000000+0000",
        "flow_id": 1001,
        "in_iface": "vtnet2",
        "event_type": event_type,
        "src_ip": src,
        "src_port": 40000,
        "dest_ip": WAF,
        "dest_port": 443,
        "proto": "TCP",
        **extra,
    }


def flow(pkts_tc: int = 5, rst: bool = False, port: int = 443, **kw) -> dict:
    return eve(
        "flow",
        dest_port=port,
        app_proto="tls" if pkts_tc else "failed",
        flow={
            "pkts_toserver": 6,
            "pkts_toclient": pkts_tc,
            "bytes_toserver": 900,
            "bytes_toclient": 4000 if pkts_tc else 0,
            "start": "2026-10-27T12:00:00.000000+0000",
            "end": "2026-10-27T12:00:02.500000+0000",
            "age": 2,
            "state": "closed" if pkts_tc else "new",
            "reason": "timeout",
            "alerted": False,
        },
        tcp={"tcp_flags": "1b", "syn": True, "fin": bool(pkts_tc), "rst": rst},
        **kw,
    )


def line(payload: dict) -> str:
    return "<38>1 2026-10-27T12:00:00Z fw01 suricata 123 - - " + json.dumps(payload)


def test_flow_event_fields():
    ev = parse_suricata_net(flow(), "fw01")
    assert ev.kind is NetKind.FLOW and ev.state is FlowState.CLOSED
    assert ev.observed_at == dt.datetime(2026, 10, 27, 12, 0, 2, 500000, tzinfo=dt.UTC)
    assert ev.duration_s == pytest.approx(2.5)
    assert (ev.pkts_to_server, ev.pkts_to_client, ev.bytes_to_client) == (6, 5, 4000)
    assert ev.syn and ev.fin and not ev.rst and ev.answered and not ev.failed
    assert ev.in_iface == "vtnet2" and ev.app_proto == "tls" and ev.dst_port == 443


def test_unanswered_and_reset_flows_are_failed():
    assert parse_suricata_net(flow(pkts_tc=0, port=22), "fw01").failed
    rst = flow(pkts_tc=1, rst=True)
    rst["flow"]["bytes_toclient"] = 0
    assert parse_suricata_net(rst, "fw01").failed


def test_dns_v3_and_v2_layouts():
    v3 = eve(
        "dns",
        proto="UDP",
        dns={
            "version": 3,
            "type": "response",
            "rcode": "NXDOMAIN",
            "queries": [{"rrname": "Evil.Example", "rrtype": "A"}],
        },
    )
    ev = parse_suricata_net(v3, "fw01")
    assert (ev.dns_rrname, ev.dns_rrtype, ev.dns_rcode) == ("evil.example", "A", "NXDOMAIN")
    v2 = eve("dns", proto="UDP", dns={"type": "query", "rrname": "a.lab", "rrtype": "AAAA"})
    assert parse_suricata_net(v2, "fw01").dns_rrtype == "AAAA"


def test_tls_ssh_anomaly_keep_metadata_only():
    tls = parse_suricata_net(
        eve("tls", tls={"sni": "Rental.Lab.Afw", "version": "TLS 1.3", "subject": "CN=x"}), "fw01"
    )
    assert (tls.tls_sni, tls.tls_version) == ("rental.lab.afw", "TLS 1.3")
    ssh = parse_suricata_net(eve("ssh", ssh={"client": {"software_version": "libssh_0.9"}}), "fw01")
    assert ssh.ssh_client == "libssh_0.9"
    an = parse_suricata_net(eve("anomaly", anomaly={"type": "stream", "event": "x"}), "fw01")
    assert an.anomaly == "stream:x"


@pytest.mark.parametrize(
    "payload",
    [eve("alert"), eve("flow"), {**flow(), "src_ip": "not-an-ip"}, {**flow(), "src_ip": "::1"}],
)
def test_bad_or_foreign_events_raise(payload):
    with pytest.raises(ParseError):
        parse_suricata_net(payload, "fw01")


def test_event_ids_are_content_derived():
    a, b = parse_suricata_net(flow(), "fw01"), parse_suricata_net(flow(), "fw01")
    assert a.event_id == b.event_id and len(a.event_id) <= 40
    assert parse_suricata_net(flow(port=8443), "fw01").event_id != a.event_id


def test_runtime_stores_network_events_once_and_keeps_alerts_separate(ctl):  # noqa: F811
    for _ in range(3):
        ctl.ingest_line(FW, line(flow()), "ids")
    ctl.ingest_line(FW, line(flow(pkts_tc=0, port=22)), "ids")
    ctl.ingest_line(FW, ids_line(), "ids")
    ctl.tick(T)
    counts = ctl.stats.snapshot()["counts"]
    assert counts["net_flow"] == 4 and counts["duplicate_net_event"] == 2
    stored = ctl.events.net_events_between(T - dt.timedelta(hours=1), T + dt.timedelta(hours=1))
    assert len(stored) == 2 and {e.dst_port for e in stored} == {22, 443}
    # the alert went down the IDS-alert path only
    assert len(ctl.correlation._ids[IPv4Address(SCANNER)]) == 1


def test_network_events_need_the_ids_identity(ctl):  # noqa: F811
    ctl.ingest_line(IPv4Address(WAF), line(flow()), "waf")
    ctl.tick(T)
    assert ctl.stats.snapshot()["counts"]["role_mismatch"] == 1
    assert ctl.events.net_events_between(T - dt.timedelta(hours=1), T) == []


def test_classify_routes_flows_to_the_suricata_kind():
    assert classify(line(flow()))[0] == "suricata"
