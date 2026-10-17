"""Sliding per-(application, source) windows for live and offline use."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector, WindowSpec
from afw.features.extract import EndpointCatalog, compute_features

Key = tuple[str, IPv4Address]


class SlidingWindows:
    """Bounded live window state.

    Every ``hop`` the caller invokes :meth:`emit`; sources with at least
    ``min_requests`` in the window *and* new activity since their last emission
    yield one feature vector. Idle sources are evicted; the number of tracked
    sources is capped (LRU) so memory stays bounded under address-spraying.
    """

    def __init__(self, window: WindowSpec, catalog: EndpointCatalog, max_sources: int = 1000):
        self.window = window
        self.catalog = catalog
        self.max_sources = max_sources
        self._buf: OrderedDict[Key, deque[HttpObservation]] = OrderedDict()
        self._dirty: set[Key] = set()
        self.evicted = 0

    def add(self, obs: HttpObservation) -> None:
        key = (obs.app_id, obs.client_ip)
        dq = self._buf.get(key)
        if dq is None:
            if len(self._buf) >= self.max_sources:
                old, _ = self._buf.popitem(last=False)
                self._dirty.discard(old)
                self.evicted += 1
            dq = deque(maxlen=5000)
            self._buf[key] = dq
        else:
            self._buf.move_to_end(key)
        dq.append(obs)
        self._dirty.add(key)

    def emit(self, now: datetime) -> list[FeatureVector]:
        start = now - timedelta(seconds=self.window.length_s)
        out: list[FeatureVector] = []
        for key in list(self._buf):
            dq = self._buf[key]
            while dq and dq[0].observed_at < start:
                dq.popleft()
            if not dq:
                del self._buf[key]
                self._dirty.discard(key)
                continue
            if key in self._dirty and len(dq) >= self.window.min_requests:
                out.append(compute_features(list(dq), self.window, self.catalog, start, now))
            self._dirty.discard(key)
        return out

    def set_catalog(self, catalog: EndpointCatalog) -> None:
        self.catalog = catalog

    @property
    def tracked_sources(self) -> int:
        return len(self._buf)


def replay_windows(
    observations: Iterable[HttpObservation],
    window: WindowSpec,
    catalog: EndpointCatalog,
) -> Iterator[FeatureVector]:
    """Deterministically replay recorded observations through the live windowing."""
    ordered: Sequence[HttpObservation] = sorted(observations, key=lambda o: o.observed_at)
    if not ordered:
        return
    sw = SlidingWindows(window, catalog, max_sources=100_000)
    hop = timedelta(seconds=window.hop_s)
    tick = ordered[0].observed_at + hop
    for obs in ordered:
        while obs.observed_at >= tick:
            yield from sw.emit(tick)
            tick += hop
        sw.add(obs)
    end = ordered[-1].observed_at + timedelta(seconds=window.length_s)
    while tick <= end:
        yield from sw.emit(tick)
        tick += hop
