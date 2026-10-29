"""Multi-horizon network behaviour per source (N2).

Windows are keyed by when connections *started*, and a window is emitted only after
``lateness`` has passed, because Suricata reports a flow when it ends (up to its flow
timeout later; 60 s for TCP on FW01). Each source gets one vector per emission with
the same quantities over a short and a long horizon.

**Residual network activity only.** The quantities are computed over the connections
the HTTP pipeline cannot see: flows to anything other than a protected service, plus
*failed* connections to a protected service (no answer or reset before any data,
which never produce an HTTP request). Answered service connections are already
analysed request by request, so counting them here would double-count the same
behaviour (ADR-039). A legitimate web user therefore has a zero vector.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from statistics import median

from pydantic import Field

from afw.domain.common import DomainModel
from afw.domain.network import NetKind, NetworkEvent

HORIZONS_S = (60, 300)
LATENESS_S = 75  # FW01 TCP flow timeout (60 s) + delivery margin
QUANTITIES = (
    "flows",  # residual connections started
    "failed",  # of which unanswered or reset before data
    "dst_hosts",  # distinct destination addresses
    "dst_ports",  # distinct destination ports
    "max_ports_per_host",  # widest port fan-out to one host (vertical scan)
    "udp_flows",
    "icmp_flows",
    "ssh_flows",  # TCP/22 connection attempts
    "dns_queries",
    "dns_nxdomain",
    "dns_names",  # distinct names asked
    "bytes_out_log",  # log1p(bytes client -> server)
    "median_duration_s",
)
FEATURE_NAMES = tuple(f"{q}_{h}" for h in HORIZONS_S for q in QUANTITIES)


class NetworkVector(DomainModel):
    source_ip: IPv4Address
    window_end: datetime  # end of the long horizon (= emission time - lateness)
    values: dict[str, float]
    n_events: int = Field(ge=0)
    event_ids: tuple[str, ...] = ()  # newest events, for explanations
    schema_version: int = 1

    def as_row(self) -> list[float]:
        return [self.values[n] for n in FEATURE_NAMES]


def _start(e: NetworkEvent) -> datetime:
    return e.started_at or e.observed_at


def residual(e: NetworkEvent, services: frozenset[tuple[IPv4Address, int]]) -> bool:
    """Part of the network behaviour the HTTP pipeline does not already see."""
    if e.kind is NetKind.FLOW:
        to_service = (e.dst_ip, e.dst_port or 0) in services
        return not to_service or e.failed
    # tls/ssh/anomaly records describe flows that are counted as flows
    return e.kind is NetKind.DNS


def quantities(events: Sequence[NetworkEvent]) -> dict[str, float]:
    flows = [e for e in events if e.kind is NetKind.FLOW]
    dns = [e for e in events if e.kind is NetKind.DNS and not e.is_dns_answer]
    answers = [e for e in events if e.kind is NetKind.DNS and e.is_dns_answer]
    ports_per_host: dict[IPv4Address, set[int]] = defaultdict(set)
    for f in flows:
        ports_per_host[f.dst_ip].add(f.dst_port or 0)
    durations = [f.duration_s for f in flows if f.duration_s is not None]
    return {
        "flows": float(len(flows)),
        "failed": float(sum(f.failed for f in flows)),
        "dst_hosts": float(len({f.dst_ip for f in flows})),
        "dst_ports": float(len({(f.dst_port or 0) for f in flows})),
        "max_ports_per_host": float(max((len(p) for p in ports_per_host.values()), default=0)),
        "udp_flows": float(sum(f.proto == "UDP" for f in flows)),
        "icmp_flows": float(sum(f.proto.startswith("ICMP") for f in flows)),
        "ssh_flows": float(sum(f.proto == "TCP" and f.dst_port == 22 for f in flows)),
        "dns_queries": float(len(dns)),
        "dns_nxdomain": float(sum(a.dns_rcode.upper() == "NXDOMAIN" for a in answers)),
        "dns_names": float(len({d.dns_rrname for d in dns if d.dns_rrname})),
        "bytes_out_log": math.log1p(sum(f.bytes_to_server for f in flows)),
        "median_duration_s": float(median(durations)) if durations else 0.0,
    }


def vector(
    source: IPv4Address, events: Sequence[NetworkEvent], window_end: datetime
) -> NetworkVector:
    """``events``: this source's residual events with start in the long horizon."""
    values: dict[str, float] = {}
    for h in HORIZONS_S:
        lo = window_end - timedelta(seconds=h)
        q = quantities([e for e in events if lo < _start(e) <= window_end])
        values.update({f"{k}_{h}": v for k, v in q.items()})
    newest = sorted(events, key=_start)[-10:]
    return NetworkVector(
        source_ip=source,
        window_end=window_end,
        values=values,
        n_events=len(events),
        event_ids=tuple(e.event_id for e in newest),
    )


class NetworkWindows:
    """Bounded per-source buffers of residual events; emits one vector per source with
    residual activity in the long horizon, every ``every_s``, ``lateness_s`` behind."""

    def __init__(
        self,
        services: Iterable[tuple[IPv4Address, int]],
        every_s: int = 30,
        lateness_s: int = LATENESS_S,
        max_events_per_source: int = 5000,
    ) -> None:
        self.services = frozenset(services)
        self.every = timedelta(seconds=every_s)
        self.lateness = timedelta(seconds=lateness_s)
        self.long = timedelta(seconds=max(HORIZONS_S))
        self.cap = max_events_per_source
        self._buf: dict[IPv4Address, list[NetworkEvent]] = defaultdict(list)
        self._last_emit: datetime | None = None
        self.dropped = 0  # events beyond the per-source cap (counted, not silent)
        self.too_late = 0  # events whose start is before an already-emitted horizon

    def add(self, e: NetworkEvent) -> bool:
        if not residual(e, self.services):
            return False
        if self._last_emit is not None and _start(e) <= self._last_emit - self.lateness - self.long:
            self.too_late += 1
            return False
        buf = self._buf[e.client_ip]
        if len(buf) >= self.cap:
            self.dropped += 1
            return False
        buf.append(e)
        return True

    @property
    def tracked_sources(self) -> int:
        return len(self._buf)

    def emit(self, now: datetime) -> list[NetworkVector]:
        if self._last_emit is not None and now - self._last_emit < self.every:
            return []
        self._last_emit = now
        end = now - self.lateness
        out: list[NetworkVector] = []
        for src in list(self._buf):
            keep = [e for e in self._buf[src] if _start(e) > end - self.long]
            if not keep:
                del self._buf[src]
                continue
            self._buf[src] = keep
            inside = [e for e in keep if _start(e) <= end]
            if inside:
                out.append(vector(src, inside, end))
        return out
