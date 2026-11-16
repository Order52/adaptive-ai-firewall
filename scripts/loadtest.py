#!/usr/bin/env python3
"""Light load tests for the controller (docs/SLO.md section "Capacity").

  uv run python scripts/loadtest.py ingest [--sources 200] [--rates 100,500,1000,2000,3000]
        [--seconds 10]
      In-process pipeline capacity at paced request rates: synthetic WAF-access + app lines
      for many sources go through the real classify -> correlate -> window -> features ->
      detection -> risk path of a simulated controller. Reports drops, tick latency and
      memory per rate. SYNTHETIC traffic: this measures software capacity, never detection
      quality.

  uv run python scripts/loadtest.py api --url https://10.77.50.10:8080 --token-file T \
        [--ca lab-ca.pem] [--clients 20] [--seconds 30]
      Concurrent read traffic against a running API (the dashboard's request mix).
      Rate limits apply: raise AFW_API_RATE_PER_MIN on a test instance, or expect 429s.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import threading
import time
from collections import Counter
from ipaddress import IPv4Address
from pathlib import Path

import psutil


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else float("nan")


def ingest(sources: int, rates: list[int], seconds: int) -> None:
    """Feed paced synthetic traffic (request = one WAF-access line + one app line) and report
    whether the pipeline keeps up: drops, correlation, tick latency, memory."""
    from afw.config import Settings
    from afw.container import build_container

    root = Path(__file__).resolve().parent.parent
    uris = ["/", "/properties", "/properties/1", "/login", "/search?q=x", "/bookings"]
    sender = IPv4Address("10.77.30.10")
    print(f"{'req/s':>6} {'offered':>8} {'joined':>8} {'dropped':>8} {'assessed':>9} "
          f"{'tick p50':>9} {'tick p95':>9} {'tick max':>9} {'rss MB':>7} {'degraded':>9}")  # fmt: skip
    for rate in rates:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(config=root / "config" / "lab.yaml", data_dir=Path(tmp))
            c = build_container(settings, simulated=True)
            ctl = c.controller
            ips = [f"10.77.{10 + i // 250 % 2 * 10}.{i % 250 + 1}" for i in range(sources)]
            slice_s, n_slices = 0.1, int(seconds / 0.1)
            per_slice = max(1, round(rate * slice_s))
            tick_ms: list[float] = []
            offered = 0
            start = time.perf_counter()
            for k in range(n_slices):
                due = start + k * slice_s
                while time.perf_counter() < due:
                    time.sleep(0.001)
                now_ts = time.time()
                for j in range(per_slice):
                    i = offered
                    offered += 1
                    rid = f"{i:032x}"
                    ip, uri = ips[i % sources], uris[i % len(uris)]
                    status = 401 if uri == "/login" and i % 7 == 0 else 200
                    acc = {"ts": f"{now_ts:.3f}", "rid": rid, "src": ip, "method": "GET",
                           "uri": uri, "status": status, "req_len": 400, "bytes": 1200,
                           "rt": "0.010", "upstream_status": str(status), "ua": "loadtest/1.0",
                           "app": "rental", "xff_received": "-"}  # fmt: skip
                    app = {"rid": rid, "app": "rental", "ver": "1.0.0", "route": uri.split("?")[0],
                           "method": "GET", "status": status, "auth": None, "user_h": "u",
                           "ts": now_ts}  # fmt: skip
                    ctl.ingest_line(sender, "<134>Nov 16 08:00:00 waf01 afw-waf-access: " + json.dumps(acc))
                    ctl.ingest_line(sender, "<134>Nov 16 08:00:00 app01 afw-app: " + json.dumps(app))
                t1 = time.perf_counter()
                ctl.tick()
                tick_ms.append((time.perf_counter() - t1) * 1000)
            time.sleep(2.5)  # let the last join window close
            ctl.tick()
            counts = c.stats.snapshot()["counts"]
            assert isinstance(counts, dict)
            dropped = int(counts.get("join_overflow", 0)) + int(counts.get("queue_drop", 0))
            n_assess = len(c.analysis.recent_assessments(limit=1_000_000))
            joined = offered - dropped
            rss = psutil.Process(os.getpid()).memory_info().rss / 2**20
            print(f"{rate:>6} {offered:>8} {joined:>8} {dropped:>8} {n_assess:>9} "
                  f"{pct(tick_ms, .5):>8.0f}ms {pct(tick_ms, .95):>8.0f}ms {max(tick_ms):>8.0f}ms "
                  f"{rss:>7.0f} {str(ctl.degraded()):>9}")  # fmt: skip


def api(url: str, token: str, ca: str | None, clients: int, seconds: int) -> None:
    import httpx

    paths = ["/api/overview", "/api/health", "/api/policies", "/api/detections", "/api/events",
             "/api/network", "/api/learning/shadow", "/api/audit", "/api/resources", "/api/metrics"]  # fmt: skip
    lat: dict[str, list[float]] = {p: [] for p in paths}
    codes: Counter[int] = Counter()
    lock = threading.Lock()
    stop = time.time() + seconds

    def worker(k: int) -> None:
        with httpx.Client(base_url=url, verify=ca or True, timeout=20,
                          headers={"Authorization": f"Bearer {token}"}) as cl:  # fmt: skip
            i = k
            while time.time() < stop:
                p = paths[i % len(paths)]
                i += 1
                t = time.perf_counter()
                try:
                    r = cl.get(p)
                    code = r.status_code
                except httpx.HTTPError:
                    code = 0
                ms = (time.perf_counter() - t) * 1000
                with lock:
                    codes[code] += 1
                    if code == 200:
                        lat[p].append(ms)

    th = [threading.Thread(target=worker, args=(k,)) for k in range(clients)]
    t0 = time.time()
    [x.start() for x in th]
    [x.join() for x in th]
    wall = time.time() - t0
    total = sum(codes.values())
    allms = [x for v in lat.values() for x in v]
    print(f"clients={clients} duration={wall:.0f}s requests={total} ({total / wall:.0f}/s) status={dict(codes)}")
    print(f"all 200s: p50 {pct(allms, .5):.0f} ms  p95 {pct(allms, .95):.0f} ms  p99 {pct(allms, .99):.0f} ms  max {max(allms, default=0):.0f} ms")
    for p, v in lat.items():
        if v:
            print(f"  {p:<22} n={len(v):<5} p50 {statistics.median(v):6.0f}  p95 {pct(v, .95):6.0f}  max {max(v):6.0f} ms")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("ingest")
    a.add_argument("--sources", type=int, default=200)
    a.add_argument("--rates", default="100,500,1000,2000,3000")
    a.add_argument("--seconds", type=int, default=10)
    b = sub.add_parser("api")
    b.add_argument("--url", required=True)
    b.add_argument("--token-file", required=True)
    b.add_argument("--ca")
    b.add_argument("--clients", type=int, default=20)
    b.add_argument("--seconds", type=int, default=30)
    n = ap.parse_args()
    if n.mode == "ingest":
        ingest(n.sources, [int(x) for x in n.rates.split(",")], n.seconds)
    else:
        api(n.url, Path(n.token_file).read_text().strip(), n.ca, n.clients, n.seconds)
