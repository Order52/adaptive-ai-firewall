"""Thread-safe telemetry counters and freshness tracking."""

from __future__ import annotations

import threading
import time
from collections import Counter


class TelemetryStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()
        self._last_seen: dict[str, float] = {}

    def inc(self, key: str, n: int = 1) -> None:
        if n:
            with self._lock:
                self._counts[key] += n

    def seen(self, sensor: str) -> None:
        with self._lock:
            self._last_seen[sensor] = time.time()

    def snapshot(self) -> dict[str, object]:
        now = time.time()
        with self._lock:
            return {
                "counts": dict(self._counts),
                "age_s": {k: round(now - v, 1) for k, v in self._last_seen.items()},
            }

    def age(self, sensor: str) -> float | None:
        with self._lock:
            ts = self._last_seen.get(sensor)
        return None if ts is None else time.time() - ts
