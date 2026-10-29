"""N2: multi-horizon residual network features."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import pytest

from afw.domain.network import FlowState, NetKind, NetworkEvent
from afw.features.network import FEATURE_NAMES, NetworkWindows, residual, vector

T0 = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
WAF = IPv4Address("10.77.30.10")
SERVICES = frozenset({(WAF, 443)})
ATK = IPv4Address("10.77.10.10")
USER = IPv4Address("10.77.20.150")
_n = 0


def fl(src=ATK, dst=WAF, port=443, at=0.0, answered=True, rst=False, proto="TCP", dur=1.0):
    global _n
    _n += 1
    start = T0 + dt.timedelta(seconds=at)
    return NetworkEvent(
        event_id=f"net-{_n}",
        kind=NetKind.FLOW,
        observed_at=start + dt.timedelta(seconds=dur),
        sensor_id="fw01",
        src_ip=src,
        src_port=40000 + _n,
        dst_ip=dst,
        dst_port=port,
        proto=proto,
        started_at=start,
        duration_s=dur,
        pkts_to_server=3,
        pkts_to_client=4 if answered else 0,
        bytes_to_server=500,
        bytes_to_client=3000 if answered else 0,
        state=FlowState.CLOSED if answered else FlowState.NEW,
        syn=True,
        rst=rst,
    )


RESOLVER = IPv4Address("1.1.1.1")


def dns(src=USER, name="x.lab", rcode="", at=0.0, answer=False, legacy=False):
    """A query from ``src``; ``answer`` its response as the parser stores it (oriented
    to the client); ``legacy`` a response stored before schema 2 (src = resolver)."""
    global _n
    _n += 1
    client, server, cport = (src, RESOLVER, 40000 + _n)
    if legacy:
        return NetworkEvent(
            event_id=f"net-{_n}",
            kind=NetKind.DNS,
            observed_at=T0 + dt.timedelta(seconds=at),
            sensor_id="fw01",
            src_ip=server,
            src_port=53,
            dst_ip=client,
            dst_port=cport,
            proto="UDP",
            dns_rrname=name,
            dns_rcode=rcode,
        )
    return NetworkEvent(
        event_id=f"net-{_n}",
        kind=NetKind.DNS,
        observed_at=T0 + dt.timedelta(seconds=at),
        sensor_id="fw01",
        src_ip=client,
        src_port=cport,
        dst_ip=server,
        dst_port=53,
        proto="UDP",
        dns_rrname=name,
        dns_rcode=rcode,
        dns_answer=answer,
    )


def test_answered_service_connections_are_not_residual():
    assert not residual(fl(), SERVICES)  # already analysed request by request
    assert residual(fl(answered=False), SERVICES)  # failed handshake: no HTTP request
    assert residual(fl(port=22), SERVICES)
    assert residual(dns(), SERVICES)


def test_legitimate_web_user_produces_no_vector():
    w = NetworkWindows(SERVICES)
    for i in range(50):
        w.add(fl(src=USER, at=i))
    assert w.emit(T0 + dt.timedelta(seconds=200)) == []


def test_horizontal_and_vertical_scan_shapes():
    ev = [fl(port=p, at=i * 0.2, answered=p == 443) for i, p in enumerate(range(1, 101))]
    ev += [
        fl(dst=IPv4Address(f"10.77.30.{h}"), port=22, at=30 + h, answered=False)
        for h in range(20, 26)
    ]
    v = vector(ATK, [e for e in ev if residual(e, SERVICES)], T0 + dt.timedelta(seconds=60))
    # port 1 starts exactly at the open lower bound of the 60 s horizon: 2..100 remain
    assert v.values["dst_ports_60"] == 99
    assert v.values["max_ports_per_host_60"] == 99
    assert v.values["failed_60"] == 99 + 6 and v.values["dst_hosts_60"] == 7
    assert v.values["ssh_flows_60"] == 7  # port 22 on WAF01 + 6 hosts
    assert set(v.values) == set(FEATURE_NAMES)


def test_two_horizons_see_different_spans():
    ev = [fl(port=22, at=t, answered=False) for t in (-200, -100, 10, 20)]
    v = vector(ATK, ev, T0 + dt.timedelta(seconds=30))
    assert v.values["ssh_flows_60"] == 2 and v.values["ssh_flows_300"] == 4


def test_dns_quantities():
    ev = [dns(name=f"h{i}.evil", at=i) for i in range(12)] + [dns(name="a.lab")]
    ev += [dns(name=f"h{i}.evil", rcode="NXDOMAIN", at=i + 0.1, answer=True) for i in range(12)]
    ev += [dns(name="a.lab", rcode="NOERROR", at=0.1, answer=True)]
    v = vector(USER, ev, T0 + dt.timedelta(seconds=40))
    # queries and names come from the requests, NXDOMAIN from the answers
    assert (v.values["dns_queries_60"], v.values["dns_nxdomain_60"], v.values["dns_names_60"]) == (
        13,
        12,
        13,
    )


def test_dns_answers_belong_to_the_client_never_the_resolver():
    w = NetworkWindows(SERVICES)
    w.add(dns(at=1))
    w.add(dns(name="printer.home", rcode="NXDOMAIN", at=1.1, answer=True))
    w.add(dns(name="nas.lan", rcode="NXDOMAIN", at=2.1, legacy=True))  # stored before schema 2
    vs = w.emit(T0 + dt.timedelta(seconds=120))
    assert [v.source_ip for v in vs] == [USER]
    assert vs[0].values["dns_nxdomain_60"] == 2 and vs[0].values["dns_queries_60"] == 1


def test_emission_waits_for_lateness_and_respects_period():
    w = NetworkWindows(SERVICES, every_s=30, lateness_s=75)
    w.add(fl(port=22, at=0, answered=False))
    assert w.emit(T0 + dt.timedelta(seconds=60)) == []  # still inside the lateness
    w2 = NetworkWindows(SERVICES, every_s=30, lateness_s=75)
    w2.add(fl(port=22, at=0, answered=False))
    out = w2.emit(T0 + dt.timedelta(seconds=80))
    assert len(out) == 1 and out[0].window_end == T0 + dt.timedelta(seconds=5)
    assert w2.emit(T0 + dt.timedelta(seconds=90)) == []  # period not elapsed


def test_events_older_than_every_emitted_horizon_are_counted_too_late():
    w = NetworkWindows(SERVICES, every_s=30, lateness_s=75)
    w.emit(T0 + dt.timedelta(seconds=1000))
    assert not w.add(fl(port=22, at=0, answered=False)) and w.too_late == 1


def test_buffers_are_bounded_and_expire():
    w = NetworkWindows(SERVICES, max_events_per_source=10)
    for i in range(15):
        w.add(fl(port=1000 + i, at=i, answered=False))
    assert w.dropped == 5
    w.emit(T0 + dt.timedelta(seconds=100))
    w.emit(T0 + dt.timedelta(seconds=1000))
    assert w.tracked_sources == 0


@pytest.mark.parametrize("n", [1000])
def test_vector_cost_is_small(n, benchmark=None):
    import time

    ev = [fl(port=1000 + i % 500, at=i * 0.05, answered=False) for i in range(n)]
    t = time.perf_counter()
    vector(ATK, ev, T0 + dt.timedelta(seconds=60))
    assert time.perf_counter() - t < 0.05  # 1000 events in well under 50 ms
