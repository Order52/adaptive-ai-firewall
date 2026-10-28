"""RELP over mutual TLS: frames, acknowledgement only after queueing, backpressure."""

from __future__ import annotations

import asyncio
import ssl
from ipaddress import IPv4Address

import pytest
from test_provenance import pki  # noqa: F401 - fixture

import afw.telemetry.receiver as rcv
from afw.config import TelemetryConfig
from afw.telemetry.receiver import RelpError, SyslogReceiver, read_relp_frame, relp_rsp
from afw.telemetry.stats import TelemetryStats

WAF = IPv4Address("10.77.30.10")
OPEN = b"1 open 46 relp_version=0\nrelp_software=t\ncommands=syslog\n"


def frame(txnr: int, cmd: str, data: bytes = b"") -> bytes:
    return (
        b"%d %s %d %s\n" % (txnr, cmd.encode(), len(data), data)
        if data
        else (b"%d %s 0\n" % (txnr, cmd.encode()))
    )


def reader_of(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


def session(r: SyslogReceiver, data: bytes, w: Writer) -> None:
    async def main() -> None:
        await r.relp_session(reader_of(data), w, WAF, "waf")

    asyncio.run(main())


class Writer:
    def __init__(self) -> None:
        self.out = bytearray()
        self.closed = False

    def write(self, b: bytes) -> None:
        self.out += b

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def rx(queue_size: int = 10, max_line: int = 1000) -> SyslogReceiver:
    return SyslogReceiver(
        TelemetryConfig(queue_size=queue_size, max_line_bytes=max_line), TelemetryStats()
    )


async def _frames(data: bytes, max_data: int = 1000):
    r = reader_of(data)
    out = []
    while not r.at_eof():
        out.append(await read_relp_frame(r, max_data))
    return out


def test_frame_parsing_exact():
    got = asyncio.run(_frames(frame(1, "syslog", b"<14>hi") + frame(2, "close")))
    assert got == [(1, "syslog", b"<14>hi"), (2, "close", b"")]
    (big,) = asyncio.run(_frames(frame(3, "syslog", b"x" * 50), max_data=10))
    assert big == (3, "syslog", None)  # read off, not kept


@pytest.mark.parametrize(
    "bad",
    [b"x syslog 1 a\n", b"1 sys-log 1 a\n", b"1 syslog 2 abc\n", b"1 syslog 3\n", b"1" * 20],
)
def test_malformed_frames_are_errors(bad):
    with pytest.raises((RelpError, asyncio.IncompleteReadError)):
        asyncio.run(_frames(bad))


def test_rsp_format():
    assert relp_rsp(7) == b"7 rsp 6 200 OK\n"
    assert relp_rsp(8, b"") == b"8 rsp 0\n"


def test_session_open_syslog_close():
    r, w = rx(), Writer()
    data = OPEN + frame(2, "syslog", b"<14>1 t waf01 afw-heartbeat: {}") + frame(3, "close")
    session(r, data, w)
    assert w.out == relp_rsp(1, rcv.RELP_OPEN_OK) + relp_rsp(2) + relp_rsp(3, b"")
    assert r.lines.get_nowait() == (WAF, "<14>1 t waf01 afw-heartbeat: {}", "waf")
    assert w.closed


def test_syslog_before_open_is_refused_and_not_queued():
    r, w = rx(), Writer()
    session(r, frame(1, "syslog", b"x"), w)
    assert w.out == relp_rsp(1, b"500 unexpected command")
    assert r.lines.empty()


def test_oversize_line_is_acknowledged_but_not_queued():
    r, w = rx(max_line=10), Writer()
    session(r, OPEN + frame(2, "syslog", b"y" * 50), w)
    assert w.out.endswith(relp_rsp(2))  # a resend could never fit
    assert r.lines.empty() and r.stats.snapshot()["counts"]["oversize"] == 1


def test_acknowledgement_waits_for_queue_space():
    """The ack for a line is sent only after the line is queued: while the queue is
    full nothing is acknowledged, so the sender keeps (and on reconnect resends) it."""
    r, w = rx(queue_size=1), Writer()
    r.lines.put_nowait((WAF, "older", "waf"))  # queue full

    async def main():
        reader = asyncio.StreamReader()
        reader.feed_data(OPEN + frame(2, "syslog", b"newer"))
        task = asyncio.create_task(r.relp_session(reader, w, WAF, "waf"))
        await asyncio.sleep(0.3)
        assert relp_rsp(2) not in w.out  # held back: not queued yet
        assert r.lines.get_nowait()[1] == "older"  # consumer frees space
        await asyncio.sleep(0.2)
        assert w.out.endswith(relp_rsp(2))
        reader.feed_eof()
        await task

    asyncio.run(main())
    assert r.lines.get_nowait()[1] == "newer"
    assert "queue_drop" not in r.stats.snapshot()["counts"]


def test_line_is_dropped_and_counted_after_the_backpressure_limit(monkeypatch):
    monkeypatch.setattr(rcv, "RELP_BACKPRESSURE_S", 0.2)
    r, w = rx(queue_size=1), Writer()
    r.lines.put_nowait((WAF, "older", "waf"))
    session(r, OPEN + frame(2, "syslog", b"newer"), w)
    assert w.out.endswith(relp_rsp(2))
    assert r.stats.snapshot()["counts"]["queue_drop"] == 1  # marks telemetry degraded


def test_protocol_error_closes_the_session():
    r, w = rx(), Writer()
    session(r, OPEN + b"2 syslog 1x a\n", w)
    assert w.closed and r.stats.snapshot()["counts"]["relp_protocol_error"] == 1


# ------------------------------------------------------------ over mutual TLS
def _relp_over_tls(pki, client: str | None) -> tuple[list, dict, bytes]:  # noqa: F811
    cfg = TelemetryConfig(
        listen_host="127.0.0.1",
        tls_cert=pki / "srv.pem",
        tls_key=pki / "srv.key",
        tls_ca=pki / "ca.pem",
        tls_identities={"waf01.lab.afw": "waf"},
    )
    r = SyslogReceiver(cfg, TelemetryStats())
    got = b""

    async def main():
        nonlocal got
        srv = await asyncio.start_server(r._handle_relp, "127.0.0.1", 0, ssl=rcv.tls_context(cfg))
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            ctx = ssl.create_default_context(cafile=str(pki / "ca.pem"))
            ctx.check_hostname = False
            if client:
                ctx.load_cert_chain(pki / f"{client}.pem", pki / f"{client}.key")
            try:
                rd, wr = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
                wr.write(OPEN + frame(2, "syslog", b"<14>line") + frame(3, "close"))
                await wr.drain()
                got = await asyncio.wait_for(rd.read(), 5)
                wr.close()
            except (ssl.SSLError, ConnectionError):
                pass

    asyncio.run(main())
    lines = []
    while not r.lines.empty():
        lines.append(r.lines.get_nowait())
    return lines, r.stats.snapshot()["counts"], got


def test_relp_over_mtls_attaches_the_identity(pki):  # noqa: F811
    lines, counts, got = _relp_over_tls(pki, "waf01.lab.afw")
    assert [(s, line, role) for s, line, role in lines] == [
        (IPv4Address("127.0.0.1"), "<14>line", "waf")
    ]
    assert got == relp_rsp(1, rcv.RELP_OPEN_OK) + relp_rsp(2) + relp_rsp(3, b"")
    assert counts["relp_session:waf"] == 1


def test_relp_rejects_unknown_identity_and_missing_certificate(pki):  # noqa: F811
    for client in ("intruder.lab.afw", None):
        lines, _, got = _relp_over_tls(pki, client)
        assert lines == [] and b"rsp" not in got


def test_resent_lines_are_acknowledged_but_queued_once():
    """rsyslog resends its unacknowledged batch after a reconnect (at-least-once);
    exact repeats are suppressed per role, distinct lines never are."""
    r = rx()
    first = OPEN + frame(2, "syslog", b"<14>a 1") + frame(3, "syslog", b"<14>a 2")
    session(r, first, Writer())
    w = Writer()
    session(r, OPEN + frame(2, "syslog", b"<14>a 2") + frame(3, "syslog", b"<14>a 3"), w)
    assert w.out.endswith(relp_rsp(2) + relp_rsp(3))  # both acknowledged
    got = []
    while not r.lines.empty():
        got.append(r.lines.get_nowait()[1])
    assert got == ["<14>a 1", "<14>a 2", "<14>a 3"]
    assert r.stats.snapshot()["counts"]["relp_duplicate"] == 1


def test_duplicate_window_is_bounded_and_per_role(monkeypatch):
    monkeypatch.setattr(rcv, "RELP_DEDUP_LINES", 2)
    r = rx()
    session(r, OPEN + b"".join(frame(i + 2, "syslog", b"l%d" % i) for i in range(3)), Writer())

    async def other_role():
        await r.relp_session(reader_of(OPEN + frame(2, "syslog", b"l2")), Writer(), WAF, "app")

    asyncio.run(other_role())  # same bytes from another sensor: not a resend
    session(r, OPEN + frame(2, "syslog", b"l0"), Writer())  # evicted: accepted again
    assert r.lines.qsize() == 5
    assert "relp_duplicate" not in r.stats.snapshot()["counts"]


def test_dropped_line_is_not_remembered(monkeypatch):
    monkeypatch.setattr(rcv, "RELP_BACKPRESSURE_S", 0.1)
    r = rx(queue_size=1)
    r.lines.put_nowait((WAF, "older", "waf"))
    session(r, OPEN + frame(2, "syslog", b"x"), Writer())  # dropped: queue full
    r.lines.get_nowait()
    session(r, OPEN + frame(2, "syslog", b"x"), Writer())  # the resend is taken
    assert r.lines.get_nowait()[1] == "x"
